"""UM-DR-32 §7 — Composite Stateful Business Logic Workflow tests.

Covers the §9.1 fixture requirements for composite business logic:
  * a valid multi-step workflow;
  * an invalid state transition;
  * an unauthorized approval or transition;
  * a replay / repeated-action control;
  * a sequence that must remain safely unconfirmed;
  * an ambiguous workflow where the engine must abstain;

plus §7.6 bounded execution and the safety contract for destructive
operations.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from webpent.production.composite_workflows import (
    MAX_SEQUENCE_DEPTH_HARD,
    CompositeWorkflowEngine,
    FixtureSafetyContract,
    SequenceOutcomeStatus,
    build_sequence_candidates,
    build_workflows_from_observations,
)

# ---------------------------------------------------------------------------
# A controlled, resettable local fixture: an order approval workflow
# ---------------------------------------------------------------------------

_STATE: dict[str, dict] = {}
_LOCK = threading.Lock()


def _reset() -> None:
    with _LOCK:
        _STATE.clear()


class ApprovalHandler(BaseHTTPRequestHandler):
    """order workflow: create -> submit -> approve.

    Ground truth (author-known, team-authored):
      * valid sequence create->submit->approve under the authorized
        actor completes the order (valid transaction);
      * approve WITHOUT submit is rejected (invalid state transition);
      * approve under the LOW-privilege actor is a POLICY VIOLATION
        (the approval requires the manager role) — the fixture answers
        200 with granted=true for the low actor (the planted flaw);
      * re-running approve after completion is rejected (replay
        restriction).
    """

    def log_message(self, *args) -> None:  # silence
        pass

    def _send(self, code: int, payload: dict, *, actor: str = "unknown",
              resource_type: str = "order", resource_id: str = "order-1",
              outcome: str = "granted") -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # authorization/resource context the observation layer reads
        # (the same echo contract the campaign fixtures use)
        self.send_header("X-Actor-Echo", actor)
        self.send_header("X-Resource-Type", resource_type)
        self.send_header("X-Resource-Id", resource_id)
        self.send_header("X-Authorization-Outcome", outcome)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        path = self.path.rstrip("/")
        actor = self.headers.get("X-Actor", "unknown")
        order_id = "order-1"
        with _LOCK:
            order = _STATE.setdefault(order_id, {"state": "draft", "history": []})
            if path == "/api/orders/create":
                order["state"] = "draft"
                order["history"].append("create")
                self._send(201, {"id": order_id, "state": "draft"}, actor=actor)
            elif path == "/api/orders/submit":
                if order["state"] != "draft":
                    self._send(409, {"error": "invalid_transition",
                                     "state": order["state"]}, actor=actor,
                               outcome="denied")
                    return
                order["state"] = "submitted"
                order["history"].append("submit")
                self._send(200, {"id": order_id, "state": "submitted"}, actor=actor)
            elif path == "/api/orders/approve":
                # the planted flaw: the approval endpoint requires the
                # manager role but accepts ANY authenticated actor
                # (authorization boundary violation)
                if order["state"] != "submitted":
                    self._send(409, {"error": "invalid_transition",
                                     "state": order["state"]}, actor=actor,
                               outcome="denied")
                    return
                order["state"] = "approved"
                order["history"].append(f"approve:{actor}")
                self._send(200, {
                    "id": order_id, "state": "approved",
                    "granted": True, "approved_by": actor,
                }, actor=actor)
            else:
                self._send(404, {"error": "not_found"}, actor=actor,
                           outcome="denied")

    def do_GET(self) -> None:
        actor = self.headers.get("X-Actor", "unknown")
        if self.path.rstrip("/") == "/api/orders/order-1":
            with _LOCK:
                order = _STATE.get("order-1", {"state": "absent"})
            self._send(200, {"id": "order-1", **order}, actor=actor)
        elif self.path.rstrip("/") == "/api/vaults/quote":
            # blanket-restricted negative control: manager only
            if self.headers.get("X-Actor-Role") == "manager":
                self._send(200, {"vault": "quote", "value": 42}, actor=actor,
                           resource_type="vaults", resource_id="quote")
            else:
                self._send(403, {"error": "manager_role_required"},
                           actor=actor, resource_type="vaults",
                           resource_id="quote", outcome="denied")
        else:
            self._send(404, {"error": "not_found"}, actor=actor,
                       outcome="denied")


@pytest.fixture()
def approval_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ApprovalHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _reset()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        _reset()
        server.shutdown()
        server.server_close()


class _InlineClient:
    """Minimal SequenceClient over urllib (scope: the local fixture only)."""

    def __init__(self, base: str) -> None:
        self.base = base

    def request(self, method, path, *, body=None, headers=None):
        import urllib.error
        import urllib.request
        req = urllib.request.Request(
            self.base + path, method=method.upper(),
            data=json.dumps(body).encode() if body is not None else None,
        )
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                return {
                    "status_code": response.status,
                    "body": response.read().decode(),
                    "headers": dict(response.headers),
                }
        except urllib.error.HTTPError as exc:
            return {
                "status_code": exc.code,
                "body": exc.read().decode(),
                "headers": dict(exc.headers),
            }


def _workflow_observations() -> list[dict]:
    """The OBSERVED transitions (what the campaign saw, no templates)."""
    return [
        {
            "fingerprint": "fp-create-0001",
            "workflow_key": "order-approval",
            "transition_key": "create",
            "endpoint": "/api/orders/create",
            "method": "POST",
            "from_state": "none",
            "to_state": "draft",
            "authorization_boundary": "same_identity",
            "identity_ref": "manager-1",
            "object_refs": ["order-1"],
            "evidence_refs": ["ev-create"],
            "confidence": 0.8,
            "destructive": False,
        },
        {
            "fingerprint": "fp-submit-0002",
            "workflow_key": "order-approval",
            "transition_key": "submit",
            "endpoint": "/api/orders/submit",
            "method": "POST",
            "from_state": "draft",
            "to_state": "submitted",
            "authorization_boundary": "same_identity",
            "identity_ref": "manager-1",
            "object_refs": ["order-1"],
            "evidence_refs": ["ev-submit"],
            "confidence": 0.8,
            "destructive": False,
        },
        {
            "fingerprint": "fp-approve-0003",
            "workflow_key": "order-approval",
            "transition_key": "approve",
            "endpoint": "/api/orders/approve",
            "method": "POST",
            "from_state": "submitted",
            "to_state": "approved",
            "authorization_boundary": "role_scoped",
            "identity_ref": "manager-1",
            "object_refs": ["order-1"],
            "prerequisites": ["role:manager"],
            "evidence_refs": ["ev-approve"],
            "confidence": 0.8,
            "destructive": False,
        },
    ]


class TestWorkflowConstruction:
    def test_workflow_built_from_observations_only(self) -> None:
        workflows = build_workflows_from_observations(_workflow_observations())
        assert len(workflows) == 1
        wf = workflows[0]
        assert wf.workflow_key == "order-approval"
        assert [s.transition_key for s in wf.steps] == [
            "create", "submit", "approve",
        ]
        assert "order-1" in wf.object_identity_refs
        assert "role_scoped" in wf.authorization_boundaries

    def test_missing_transition_stays_missing(self) -> None:
        # only two of three transitions observed: the workflow has two
        # steps and invents NOTHING
        observations = _workflow_observations()[:2]
        workflows = build_workflows_from_observations(observations)
        assert len(workflows[0].steps) == 2
        assert not any(
            s.transition_key == "approve" for s in workflows[0].steps
        )

    def test_empty_observations_yield_no_workflows(self) -> None:
        assert build_workflows_from_observations([]) == []

    def test_workflow_id_deterministic(self) -> None:
        w1 = build_workflows_from_observations(_workflow_observations())
        w2 = build_workflows_from_observations(_workflow_observations())
        assert w1[0].workflow_id == w2[0].workflow_id

    def test_bounded_steps_per_workflow(self) -> None:
        observations = [
            {
                "fingerprint": f"fp-{i:04d}",
                "workflow_key": "big",
                "transition_key": f"step-{i}",
                "endpoint": f"/api/big/step-{i}",
                "method": "POST",
            }
            for i in range(50)
        ]
        workflows = build_workflows_from_observations(
            observations, max_steps_per_workflow=12,
        )
        assert len(workflows[0].steps) == 12


class TestSequenceCandidates:
    def test_candidates_from_real_workflow(self) -> None:
        workflows = build_workflows_from_observations(_workflow_observations())
        candidates = build_sequence_candidates(workflows)
        assert candidates
        invariants = {c.invariant for c in candidates}
        # the approval boundary probe must be present (role_scoped step)
        assert "approval_not_self_completable" in invariants
        # replay + skip probes for >=2-step sequences
        assert "replay_restriction" in invariants
        assert "no_state_skip" in invariants
        for candidate in candidates:
            assert len(candidate.steps) <= MAX_SEQUENCE_DEPTH_HARD

    def test_candidates_bounded(self) -> None:
        workflows = build_workflows_from_observations(_workflow_observations())
        candidates = build_sequence_candidates(
            workflows, max_candidates=2,
        )
        assert len(candidates) <= 2

    def test_every_candidate_carries_supporting_refs(self) -> None:
        workflows = build_workflows_from_observations(_workflow_observations())
        for candidate in build_sequence_candidates(workflows):
            assert candidate.invariant_supporting_refs


class TestSafetyContract:
    def test_destructive_step_blocked_without_authorization(self) -> None:
        observations = _workflow_observations() + [{
            "fingerprint": "fp-del-0004",
            "workflow_key": "order-approval",
            "transition_key": "delete",
            "endpoint": "/api/orders/delete",
            "method": "POST",
            "destructive": True,
        }]
        workflows = build_workflows_from_observations(observations)
        candidates = build_sequence_candidates(workflows)
        destructive = [
            c for c in candidates
            if any(s.destructive for s in c.steps)
        ]
        assert destructive
        engine = CompositeWorkflowEngine(
            client=_InlineClient("http://127.0.0.1:1"),  # never contacted
            safety=FixtureSafetyContract(
                resettable=True, isolated=True, authorized_by_operator=False,
                destructive_methods_allowed=("POST",),
            ),
        )
        outcome = engine.execute(destructive[0])
        assert outcome.status is SequenceOutcomeStatus.BLOCKED
        assert "operator authorization" in outcome.block_reason

    def test_state_mutating_requires_resettable_isolated_fixture(self) -> None:
        workflows = build_workflows_from_observations(_workflow_observations())
        candidates = [
            c for c in build_sequence_candidates(workflows)
            if c.safety != "read_only"
        ]
        assert candidates
        engine = CompositeWorkflowEngine(
            client=_InlineClient("http://127.0.0.1:1"),
            safety=FixtureSafetyContract(resettable=False),
        )
        outcome = engine.execute(candidates[0])
        assert outcome.status is SequenceOutcomeStatus.BLOCKED
        assert "resettable isolated" in outcome.block_reason


class TestSequenceExecution:
    def _engine(self, base: str, **kwargs) -> CompositeWorkflowEngine:
        return CompositeWorkflowEngine(
            client=_InlineClient(base),
            safety=FixtureSafetyContract(
                resettable=True, isolated=True, authorized_by_operator=True,
                destructive_methods_allowed=("POST",),
            ),
            reset_fixture=_reset,
            **kwargs,
        )

    def _approval_candidate(self):
        workflows = build_workflows_from_observations(_workflow_observations())
        return [
            c for c in build_sequence_candidates(workflows)
            if c.invariant == "approval_not_self_completable"
        ][0]

    def test_unauthorized_approval_is_policy_violation_candidate(
        self, approval_server,
    ) -> None:
        # control run: the MANAGER runs the full path (positive control)
        # experiment run: the LOW-PRIVILEGE intern runs the same path —
        # the fixture's planted flaw accepts the approval -> the
        # privilege-differential route confirms the boundary violation
        engine = self._engine(approval_server)
        candidate = self._approval_candidate()
        outcome = engine.execute(
            candidate,
            control_headers={"X-Actor": "manager-1", "X-Actor-Role": "manager"},
            actor_headers={"X-Actor": "intern-1", "X-Actor-Role": "viewer"},
            negative_control_probe=("GET", "/api/vaults/quote"),
        )
        assert outcome.status is SequenceOutcomeStatus.POLICY_VIOLATION_CANDIDATE, (
            f"expected the planted flaw to surface, got {outcome.status} "
            f"({outcome.block_reason})"
        )
        assert outcome.causal_result
        assert outcome.causal_result["authority"] == (
            "production.validators.run_validator:PRIVILEGE_DIFFERENTIAL"
        )
        # the negative-control probe is part of the evidence trace
        phases = [e["phase"] for e in outcome.evidence_trace]
        assert "negative_control_probe" in phases

    def test_cross_actor_without_control_probe_abstains(
        self, approval_server,
    ) -> None:
        engine = self._engine(approval_server)
        candidate = self._approval_candidate()
        outcome = engine.execute(
            candidate,
            control_headers={"X-Actor": "manager-1"},
            actor_headers={"X-Actor": "intern-1"},
            # NO negative_control_probe: honest abstention, no guessing
        )
        assert outcome.status is SequenceOutcomeStatus.BLOCKED
        assert "negative-control probe" in outcome.block_reason

    def test_authorized_approval_is_false_hypothesis(self, approval_server) -> None:
        # BOTH runs under the manager: no differential -> REFUTED
        engine = self._engine(approval_server)
        candidate = self._approval_candidate()
        outcome = engine.execute(
            candidate,
            control_headers={"X-Actor": "manager-1", "X-Actor-Role": "manager"},
            actor_headers={"X-Actor": "manager-1", "X-Actor-Role": "manager"},
            negative_control_probe=("GET", "/api/vaults/quote"),
        )
        assert outcome.status is SequenceOutcomeStatus.FALSE_HYPOTHESIS

    def test_valid_sequence_is_expected_transition(self, approval_server) -> None:
        # both runs under the authorized actor: the sequence completes
        # legitimately both times -> not a violation
        engine = self._engine(approval_server)
        workflows = build_workflows_from_observations(_workflow_observations())
        replay = [
            c for c in build_sequence_candidates(workflows)
            if c.invariant == "replay_restriction"
        ][0]
        outcome = engine.execute(
            replay,
            control_headers={"X-Actor": "manager-1"},
            actor_headers={"X-Actor": "manager-1"},
        )
        # the fixture's replay restriction: the second full run's
        # create resets the order (fixture semantics) — the honest
        # outcome here is a non-violation status
        assert outcome.status in (
            SequenceOutcomeStatus.VALID_TRANSACTION,
            SequenceOutcomeStatus.EXPECTED_TRANSITION,
            SequenceOutcomeStatus.FALSE_HYPOTHESIS,
            SequenceOutcomeStatus.EXPECTED_DENIAL,
            SequenceOutcomeStatus.INCONCLUSIVE,
        )
        assert outcome.status is not SequenceOutcomeStatus.POLICY_VIOLATION_CANDIDATE

    def test_invalid_state_skip_is_denied_not_violation(
        self, approval_server,
    ) -> None:
        # skip probe: create then approve DIRECTLY (skipping submit):
        # the fixture correctly rejects the invalid transition
        engine = self._engine(approval_server)
        workflows = build_workflows_from_observations(_workflow_observations())
        skip = [
            c for c in build_sequence_candidates(workflows)
            if c.invariant == "no_state_skip"
        ][0]
        outcome = engine.execute(
            skip,
            control_headers={"X-Actor": "manager-1"},
            actor_headers={"X-Actor": "manager-1"},
        )
        assert outcome.status is not SequenceOutcomeStatus.POLICY_VIOLATION_CANDIDATE

    def test_budget_enforced(self, approval_server) -> None:
        engine = self._engine(approval_server, max_requests_per_sequence=1)
        candidate = self._approval_candidate()
        outcome = engine.execute(
            candidate,
            control_headers={"X-Actor": "manager-1"},
            actor_headers={"X-Actor": "intern-1"},
        )
        assert outcome.requests_issued <= 2  # 1 per phase

    def test_client_failure_is_honest_telemetry(self, approval_server) -> None:
        class _FailingClient:
            def request(self, *args, **kwargs):
                raise ConnectionError("fixture exploded")

        engine = CompositeWorkflowEngine(
            client=_FailingClient(),
            safety=FixtureSafetyContract(
                resettable=True, isolated=True, authorized_by_operator=True,
            ),
            reset_fixture=_reset,
        )
        candidate = self._approval_candidate()
        outcome = engine.execute(
            candidate,
            control_headers={"X-Actor": "manager-1"},
            actor_headers={"X-Actor": "intern-1"},
            negative_control_probe=("GET", "/api/vaults/quote"),
        )
        assert outcome.status is SequenceOutcomeStatus.INCONCLUSIVE
        assert outcome.evidence_trace  # the failure is recorded, not hidden

    def test_sequence_provenance_recorded(self, approval_server) -> None:
        engine = self._engine(approval_server)
        candidate = self._approval_candidate()
        outcome = engine.execute(
            candidate,
            control_headers={"X-Actor": "manager-1", "X-Actor-Role": "manager"},
            actor_headers={"X-Actor": "intern-1", "X-Actor-Role": "viewer"},
            negative_control_probe=("GET", "/api/vaults/quote"),
        )
        assert outcome.sequence_id == candidate.sequence_id
        assert outcome.steps_executed
        payload = outcome.as_dict()
        assert payload["evidence_trace"]
        assert "positive_control" in payload["evidence_trace"][0]["phase"]
