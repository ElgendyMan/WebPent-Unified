# tests/test_integration_wiring.py
"""Wiring tests: integration layer ↔ GOED research engine / attack graph.

These tests prove the additive wiring (docs/integration/
SHANNON_GOED_INTEGRATION_FINAL.md, wiring section):

* AgendaBridge composes reconciliation + agenda + queue with GOED's
  budget-aware ``ResearchState`` (scope, dedup, and budget gates are
  GOED's own — the bridge never bypasses them).
* Auth-validation verdicts feed the agenda through the deterministic
  ``to_signal_strength`` weight (advisory signal, never a verdict).
* ``attach_source_lane`` annotates ENDPOINT attack-graph nodes
  additively (pure function, idempotent, no node/edge semantic change).
* The additive settings flag defaults to False (compatibility path
  unchanged) and the merged ``auth_validation`` state key is compatible
  with the open ``PentestState`` TypedDict contract.

Security invariants asserted here (protocol §8, §12, §22):

* Bridge output is planning-only (``operation="plan"``) — no task is
  ever auto-executed or auto-validated.
* No verdict authority: no planned task or lane annotation carries a
  verdict/confirmation field.
* Determinism: identical inputs → identical plans and lanes.
"""

from __future__ import annotations

import json

import pytest

from webpent.attack_graph import attach_source_lane, source_lane_summary
from webpent.config.settings import Settings
from webpent.integration.auth_session_contract import (
    AuthFailurePoint,
    AuthValidationVerdict,
    merge_into_state_dict,
)
from webpent.integration.exploitation_queue import ExploitAttemptRecord
from webpent.integration.priority_policy import PriorityProposal
from webpent.integration.reconciliation import reconcile
from webpent.integration.research_agenda import AgendaLimits
from webpent.integration.source_mapping import (
    CodeLocation,
    SourceMappingRecord,
    SourceRole,
    join_source_locations,
)
from webpent.models.attack_graph import (
    AttackGraph,
    AttackGraphEdge,
    AttackGraphNode,
    AttackGraphNodeKind,
)
from webpent.research_engine import AgendaBridge
from webpent.research_engine.agenda_bridge import (
    BRIDGE_VERSION,
    signal_from_auth_verdict,
    signal_from_reconciliation_task,
)
from webpent.research_engine.research_budget import ResearchBudget
from webpent.research_engine.research_state import ResearchState


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _recon_rows() -> list[dict]:
    return [
        {
            "producer_id": "recon-a",
            "kind": "sqli_candidate",
            "endpoint_path": "/api/login",
            "parameter": "user",
            "role": "query",
            "payload": {"param_type": "string", "reflected": True},
            "source_refs": ["obs:1001", "obs:1002"],
        },
        {
            "producer_id": "recon-b",
            "kind": "sqli_candidate",
            "endpoint_path": "/api/login",
            "parameter": "user",
            "role": "query",
            "payload": {"param_type": "string", "reflected": True},
            "source_refs": ["obs:2001"],
        },
    ]


def _bridge(**kwargs) -> AgendaBridge:
    defaults: dict = {"engagement_id": "eng-1", "target_id": "tgt-1"}
    defaults.update(kwargs)
    return AgendaBridge(**defaults)


# ---------------------------------------------------------------------------
# bridge: reconciliation → agenda → GOED research state
# ---------------------------------------------------------------------------
def test_reconciliation_task_feeds_agenda_signal() -> None:
    result = reconcile(_recon_rows())
    assert result.tasks, "reconciliation must materialize a task"
    task = result.tasks[0]
    signal = signal_from_reconciliation_task(
        task,
        severity_potential=8,
        evidence_strength=0.6,
        exploitability=0.5,
        novelty=0.7,
    )
    assert signal.hypothesis_id == task.suggested_hypothesis_id()
    assert set(task.evidence_candidate_refs) <= set(signal.source_refs)
    assert signal.severity_potential == 8


def test_bridge_plans_and_admits_into_research_state() -> None:
    bridge = _bridge()
    result = reconcile(_recon_rows())
    signal = signal_from_reconciliation_task(
        result.tasks[0], severity_potential=9, evidence_strength=0.9
    )
    bridge.ingest(signal)

    planned = bridge.plan_research_tasks()
    assert len(planned) == 1
    item = planned[0]
    assert item.task.task_id == f"agenda::{item.branch_id}"
    assert item.task.engagement_id == "eng-1"
    assert item.task.target_id == "tgt-1"
    assert item.task.operation == "plan"
    assert 0.0 <= item.task.priority <= 1.0
    assert item.task.priority == round(item.agenda_priority / 100.0, 4)

    state = ResearchState(engagement_id="eng-1", target_id="tgt-1")
    outcome = bridge.admit_into_state(state)
    assert outcome.admitted == 1
    assert outcome.stop_reason == ""
    assert outcome.updated_state is not None
    # GOED's immutable-state discipline: input state intact, new state carries the task
    assert len(state.tasks) == 0
    assert len(outcome.updated_state.tasks) == 1
    assert outcome.updated_state.tasks[0].task_id == item.task.task_id


def test_bridge_respects_goed_budget_gate() -> None:
    bridge = _bridge()
    for i, sev in enumerate((9, 3)):
        rows = _recon_rows()
        rows[0]["kind"] = f"kind_{i}"
        result = reconcile(rows)
        sig = signal_from_reconciliation_task(
            result.tasks[0], severity_potential=sev, evidence_strength=0.8
        )
        bridge.ingest(sig)
    state = ResearchState(
        engagement_id="eng-1",
        target_id="tgt-1",
        budget=ResearchBudget(max_requests=1),
    )
    outcome = bridge.admit_into_state(state)
    assert outcome.admitted == 1
    assert outcome.stop_reason == "task_budget_exhausted"


def test_bridge_scope_mismatch_is_rejected_by_goed_gate() -> None:
    bridge = _bridge()
    result = reconcile(_recon_rows())
    sig = signal_from_reconciliation_task(
        result.tasks[0], severity_potential=9, evidence_strength=0.9
    )
    bridge.ingest(sig)
    wrong_scope = ResearchState(engagement_id="eng-OTHER", target_id="tgt-1")
    with pytest.raises(ValueError):
        bridge.admit_into_state(wrong_scope)


def test_bridge_plan_is_deterministic() -> None:
    def build() -> tuple:
        bridge = _bridge()
        result = reconcile(_recon_rows())
        bridge.ingest(
            signal_from_reconciliation_task(
                result.tasks[0], severity_potential=8, evidence_strength=0.9
            ),
            proposal=PriorityProposal(suggested_delta=3, reason="llm hint", proposer="llm"),
        )
        return bridge.plan_research_tasks(), bridge.to_audit_dict()

    a_tasks, a_audit = build()
    b_tasks, b_audit = build()
    assert a_tasks == b_tasks
    assert json.loads(json.dumps(a_audit)) == json.loads(json.dumps(b_audit))
    # proposer recorded (auditability: LLM influence is clamped + recorded)
    events = [e for e in a_audit["agenda"]["branches"].values() if e["decision_log"]]
    assert any(
        entry.get("proposal_proposer") == "llm"
        for e in events
        for entry in e["decision_log"]
    )
    # signal provenance recorded verbatim (both producers' refs survive dedup)
    assert any(
        entry.get("source_refs") == ["obs:1001", "obs:1002", "obs:2001"]
        for e in events
        for entry in e["decision_log"]
    )  # noqa: E501


# ---------------------------------------------------------------------------
# bridge: auth verdict → agenda
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("verdict", "expected_strength"),
    [
        (AuthValidationVerdict(login_success=True, session_verified=True), 1.0),
        (
            AuthValidationVerdict(
                login_success=False,
                failure_point=AuthFailurePoint.USERNAME_OR_PASSWORD,
            ),
            0.2,
        ),
    ],
)
def test_auth_verdict_feeds_agenda(
    verdict: AuthValidationVerdict, expected_strength: float
) -> None:
    signal = signal_from_auth_verdict(verdict, hypothesis_id="hyp-auth-1")
    assert signal.evidence_strength == expected_strength
    bridge = _bridge()
    bridge.ingest(signal)
    branches = bridge.agenda.ordered_active()
    assert len(branches) == 1
    assert branches[0].hypothesis_id == "hyp-auth-1"


# ---------------------------------------------------------------------------
# bridge: exploitation planning (evidence-gated, non-authoritative)
# ---------------------------------------------------------------------------
def test_exploitation_planning_full_cycle() -> None:
    bridge = _bridge()
    entry = bridge.queue.add_entry(
        hypothesis_id="hyp-xss-1",
        vuln_class="reflected_xss",
        endpoint_path="/search",
        rationale="reflected parameter",
        evidence_refs=("obs:77",),
    )
    gates = bridge.plan_exploitation()
    assert len(gates) == 1
    assert gates[0].decision.value == "run"

    record = ExploitAttemptRecord(
        entry_id=entry.entry_id,
        outcome="attempted",
        observation_refs=("obs:resp-1",),
        evidence_refs=("obs:77",),
    )
    bridge.record_exploit_outcome(record)
    assert len(bridge.exploit_attempts()) == 1

    # consumed entry: re-gate must SKIP (fail-closed, no re-exploitation)
    second = bridge.plan_exploitation()
    assert second == []
    assert bridge.queue.to_audit_dict()["by_status"]["consumed"] == 1


def test_bridge_audit_dict_is_json_safe() -> None:
    bridge = _bridge()
    result = reconcile(_recon_rows())
    sig = signal_from_reconciliation_task(
        result.tasks[0], severity_potential=7, evidence_strength=0.5
    )
    bridge.ingest(sig)
    payload = json.loads(json.dumps(bridge.to_audit_dict()))
    assert payload["bridge_version"] == BRIDGE_VERSION
    assert payload["engagement_id"] == "eng-1"
    assert "agenda" in payload and "queue" in payload


def test_agenda_limits_propagate_through_bridge() -> None:
    bridge = _bridge(limits=AgendaLimits(max_active_branches=1))
    first = reconcile(_recon_rows())
    sig = signal_from_reconciliation_task(
        first.tasks[0], severity_potential=8, evidence_strength=0.8
    )
    bridge.ingest(sig)
    rows = _recon_rows()
    rows[0]["kind"] = "other_kind"
    second = reconcile(rows)
    # weaker newcomer at the active cap → fails closed
    with pytest.raises(ValueError):
        bridge.ingest(
            signal_from_reconciliation_task(
                second.tasks[0], severity_potential=1, evidence_strength=0.1
            )
        )


# ---------------------------------------------------------------------------
# attack-graph source lane
# ---------------------------------------------------------------------------
def _graph_with_endpoint() -> AttackGraph:
    endpoint = AttackGraphNode(
        id="ep-1",
        kind=AttackGraphNodeKind.ENDPOINT,
        label="/api/login",
        metadata={"path": "/api/login"},
    )
    asset = AttackGraphNode(id="app-1", kind=AttackGraphNodeKind.ASSET, label="webapp")
    edge = AttackGraphEdge(
        id="edge-1", kind="targets", source_id="app-1", target_id="ep-1"
    )
    return AttackGraph(nodes={"ep-1": endpoint, "app-1": asset}, edges=[edge])


def _login_mapping() -> SourceMappingRecord:
    return SourceMappingRecord(
        code_location=CodeLocation(
            file="app/routes/login.py",
            start_line=10,
            end_line=20,
            role=SourceRole.SINK,
            symbol="db.execute",
        ),
        endpoint_path="/api/login",
        http_method="POST",
        hypothesis_id="hyp-sqli-1",
        evidence_refs=("obs:9",),
    )


def test_source_lane_annotates_endpoint_nodes_additively() -> None:
    graph = _graph_with_endpoint()
    joined = join_source_locations([_login_mapping()])
    annotated = attach_source_lane(graph, joined)

    lane = annotated.nodes["ep-1"].metadata["source_lane"]
    assert lane["schema_version"]
    assert lane["endpoint_path"] == "/api/login"
    assert lane["http_method"] == "POST"
    assert lane["locations"][0]["file"] == "app/routes/login.py"
    assert lane["hypothesis_ids"] == ["hyp-sqli-1"]
    # additive only: kinds, labels, edges untouched
    assert annotated.nodes["ep-1"].kind == graph.nodes["ep-1"].kind
    assert annotated.edges == graph.edges
    # input graph never mutated
    assert "source_lane" not in graph.nodes["ep-1"].metadata
    # non-endpoint node untouched
    assert "source_lane" not in annotated.nodes["app-1"].metadata


def test_source_lane_is_idempotent_and_deterministic() -> None:
    graph = _graph_with_endpoint()
    joined = join_source_locations([_login_mapping()])
    once = attach_source_lane(graph, joined)
    twice = attach_source_lane(once, joined)
    assert twice.nodes["ep-1"].metadata["source_lane"] == (
        once.nodes["ep-1"].metadata["source_lane"]
    )
    summary = source_lane_summary(twice)
    assert summary["annotated_nodes"] == 1
    assert summary["lanes"][0]["location_count"] == 1


def test_source_lane_leaves_unmatched_graph_unchanged() -> None:
    graph = _graph_with_endpoint()
    unmapped = SourceMappingRecord(
        code_location=CodeLocation(
            file="app/other.py",
            start_line=1,
            end_line=2,
            role=SourceRole.SOURCE,
            symbol="request.args",
        ),
        endpoint_path="/completely/different",
        http_method="GET",
    )
    annotated = attach_source_lane(graph, join_source_locations([unmapped]))
    assert "source_lane" not in annotated.nodes["ep-1"].metadata
    assert source_lane_summary(annotated)["annotated_nodes"] == 0


# ---------------------------------------------------------------------------
# settings flag + state contract compatibility
# ---------------------------------------------------------------------------
def test_integration_flag_defaults_to_false() -> None:
    field = Settings.model_fields["enable_integration_agenda"]
    assert field.default is False
    instance = Settings(enable_integration_agenda=True)
    assert instance.enable_integration_agenda is True


def test_auth_validation_state_key_is_pentest_state_compatible() -> None:
    verdict = AuthValidationVerdict(
        login_success=False,
        failure_point=AuthFailurePoint.TOTP_SECRET,
    )
    state = {
        "findings": [],
        "session_cookies": {"sid": "value"},
        "credentials": {"password": "s3cret", "token": "t0ken", "user": "alice"},
    }
    merged = merge_into_state_dict(state, verdict)
    assert "auth_validation" in merged
    assert merged["session_cookies"] == state["session_cookies"]
    record = merged["auth_validation"]
    assert record["redacted_value_keys_dropped"] == 2  # password + token dropped
    assert record["failure_point"] == "totp_secret"
    # no secret material may leak into the record
    flat = json.dumps(record)
    assert "s3cret" not in flat and "t0ken" not in flat
    # the open TypedDict (total=False) accepts the additive key
    from webpent.state.state import PentestState

    typed: PentestState = merged  # structural compatibility check
    assert typed["auth_validation"]["login_success"] is False


def test_integration_package_surface_matches_exports() -> None:
    """Every module exports exactly its declared __all__ surface."""
    import webpent.integration as pkg

    expected = {
        "AgendaLimits", "AgendaSignal", "AuthFailurePoint", "AuthSessionRecord",
        "AuthValidationVerdict", "BranchStatus", "CodeLocation",
        "ExploitAttemptRecord", "ExploitationQueue", "GateDecision", "GateResult",
        "Observation", "PriorityDecision", "PriorityFactor", "PriorityInput",
        "PriorityProposal", "QueueEntry", "ReconciliationResult", "ResearchAgenda",
        "ResearchTask", "SourceMappingRecord", "SourceRole", "SurfaceDossier",
        "branch_id_for", "build_surface_dossier", "compute_priority",
        "join_source_locations", "merge_into_state_dict", "reconcile",
        "record_from_verdict",
    }
    assert set(pkg.__all__) == expected
    for name in expected:
        assert getattr(pkg, name) is not None
