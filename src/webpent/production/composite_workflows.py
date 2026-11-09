"""UM-DR-32 §7 — Composite Stateful Business Logic Workflows.

Serious vulnerabilities often exist only in a SEQUENCE of otherwise
legitimate operations, not in any single request. This module builds an
evidence-driven workflow model that reasons about multi-step business
operations, preconditions, state transitions, principal changes,
ownership changes, authorization boundaries, replay restrictions,
approval requirements, ordering invariants and composite sequences.

Contract:

  * workflows DERIVE from observed application behavior (§7.1-7.2):
    workflow observations, transition sources, state-machine inference
    and object-identity relationships. A missing transition stays
    missing; an unobserved precondition is never invented;
  * typed workflow representation (§7.3) with explicit relationships
    between DIFFERENT object identities (an order, an invoice and an
    approval are related, never the same object);
  * bounded sequence reasoning (§7.4/7.6): configurable maximum depth,
    maximum candidates, request budgets, branch budgets, execution time
    limits, per-sequence evidence limits, safe state initialization,
    explicit state reset for repeated experiments, negative controls
    and sequence-level result provenance. Conservative defaults follow
    the existing campaign budgets; no overall budget increase;
  * composite sequence validation (§7.7): a finding requires CAUSAL
    evidence — the tested sequence, the security invariant violated,
    the relevant initial state, actor identities, operations, resulting
    state and negative controls. Response text alone is never
    sufficient. All confirmation flows through CausalGuard
    (cqa_v2.guarded_causal_evaluate) and the ProofBundle contract.

Destructive operations are blocked outside authorized isolated
fixtures (the safety classification refuses to execute them unless the
caller provides an explicit resettable-fixture contract).
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Protocol

__all__ = [
    "WORKFLOW_NAMESPACE",
    "CompositeWorkflow",
    "CompositeWorkflowEngine",
    "FixtureSafetyContract",
    "SequenceCandidate",
    "SequenceClient",
    "SequenceOutcome",
    "SequenceOutcomeStatus",
    "WorkflowStepSpec",
    "build_sequence_candidates",
    "build_workflows_from_observations",
]

WORKFLOW_NAMESPACE = uuid.UUID("d4e5f6a7-b8c9-4d0e-9f1a-2b3c4d5e6f70")

# §7.6 conservative bounds (aligned with BusinessLogicHypothesisSpec
# maximum_attempts<=5, request_budget<=10 and stateful probe budgets).
MAX_SEQUENCE_DEPTH_DEFAULT = 4
MAX_SEQUENCE_DEPTH_HARD = 6
MAX_CANDIDATE_SEQUENCES_DEFAULT = 8
MAX_CANDIDATE_SEQUENCES_HARD = 32
MAX_REQUESTS_PER_SEQUENCE_DEFAULT = 10
MAX_REQUESTS_PER_SEQUENCE_HARD = 24
SEQUENCE_TIME_LIMIT_SECONDS_DEFAULT = 60.0


class SequenceOutcomeStatus(str, Enum):
    """§7.7 — the honest outcome vocabulary for composite sequences."""

    VALID_TRANSACTION = "valid_transaction"          # the app behaved as designed
    EXPECTED_DENIAL = "expected_denial"              # authorization correctly denied
    EXPECTED_TRANSITION = "expected_transition"      # state moved as observed
    INCONCLUSIVE = "inconclusive"                    # evidence insufficient
    FALSE_HYPOTHESIS = "false_hypothesis"            # the hypothesized violation did not occur
    # causal evidence present -> CausalGuard
    POLICY_VIOLATION_CANDIDATE = "policy_violation_candidate"
    DECOY = "decoy"                                  # benign behavior that mimics a violation
    BLOCKED = "blocked"                              # safety/budget/scope refused execution


class SequenceClient(Protocol):
    """The authorized execution adapter (the StatefulCaseProber client
    contract — CampaignProberClient satisfies it)."""

    def request(
        self, method: str, path: str, *,
        body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Returns at least {status_code, body, headers}. Scope checks
        happen INSIDE the adapter before any request leaves."""
        ...


@dataclass(frozen=True)
class FixtureSafetyContract:
    """§7.6 — the explicit safety contract for state-mutating sequences."""

    resettable: bool                      # fixture can be reset between sequences
    reset_callback_ref: str = ""          # how the engine resets (opaque ref)
    isolated: bool = False                # fixture is isolated from production
    authorized_by_operator: bool = False  # explicit operator authorization
    # e.g. ("POST",) — DELETE never auto-allowed
    destructive_methods_allowed: tuple[str, ...] = ()

    def permits(self, method: str, destructive: bool) -> tuple[bool, str]:
        if not destructive:
            return True, ""
        if not (self.resettable and self.isolated and self.authorized_by_operator):
            return False, (
                "destructive step requires resettable+isolated fixture with "
                "explicit operator authorization (§7.6)"
            )
        if method.upper() not in {
            m.upper() for m in self.destructive_methods_allowed
        }:
            return False, f"method {method} not in allowed destructive methods"
        return True, ""


@dataclass
class WorkflowStepSpec:
    """One observed operation in a workflow (§7.3)."""

    transition_key: str
    endpoint: str
    method: str
    from_state: str = "unknown"
    to_state: str = "unknown"
    preconditions: list[str] = field(default_factory=list)
    authorization_boundary: str = "unknown"
    identity_ref: str = ""
    object_refs: list[str] = field(default_factory=list)
    destructive: bool = False
    evidence_refs: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "transition_key": self.transition_key,
            "endpoint": self.endpoint,
            "method": self.method,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "preconditions": list(self.preconditions),
            "authorization_boundary": self.authorization_boundary,
            "identity_ref": self.identity_ref,
            "object_refs": list(self.object_refs),
            "destructive": self.destructive,
            "evidence_refs": list(self.evidence_refs)[:20],
        }


@dataclass
class CompositeWorkflow:
    """A typed multi-step business workflow (§7.3)."""

    workflow_key: str
    steps: list[WorkflowStepSpec] = field(default_factory=list)
    object_identity_refs: list[str] = field(default_factory=list)
    authorization_boundaries: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    confidence: float = 0.0

    @property
    def workflow_id(self) -> str:
        return str(uuid.uuid5(WORKFLOW_NAMESPACE, self.workflow_key))

    def states(self) -> list[str]:
        seen: list[str] = []
        for step in self.steps:
            for state in (step.from_state, step.to_state):
                if state != "unknown" and state not in seen:
                    seen.append(state)
        return seen

    def as_dict(self) -> dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "workflow_key": self.workflow_key,
            "steps": [s.as_dict() for s in self.steps],
            "object_identity_refs": list(self.object_identity_refs),
            "authorization_boundaries": list(self.authorization_boundaries),
            "evidence_refs": list(self.evidence_refs)[:30],
            "states": self.states(),
            "confidence": round(self.confidence, 3),
        }


@dataclass
class SequenceCandidate:
    """A bounded candidate sequence built from REAL transitions (§7.4)."""

    sequence_id: str
    workflow_id: str
    steps: list[WorkflowStepSpec]
    invariant: str                 # the business invariant under test (§7.5)
    invariant_supporting_refs: list[str]  # observations backing the invariant
    hypothesis: str                # what violation we test for
    expected_negative_control: str  # how the control run differs
    safety: str = "read_only"      # read_only | state_mutating | destructive

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence_id": self.sequence_id,
            "workflow_id": self.workflow_id,
            "steps": [s.as_dict() for s in self.steps],
            "invariant": self.invariant,
            "invariant_supporting_refs": list(self.invariant_supporting_refs),
            "hypothesis": self.hypothesis,
            "expected_negative_control": self.expected_negative_control,
            "safety": self.safety,
        }


@dataclass
class SequenceOutcome:
    """§7.7 — the result of one bounded sequence execution."""

    sequence_id: str
    status: SequenceOutcomeStatus
    requests_issued: int = 0
    steps_executed: list[str] = field(default_factory=list)
    final_state: str = "unknown"
    evidence_trace: list[dict[str, Any]] = field(default_factory=list)
    causal_result: dict[str, Any] | None = None   # CausalGuard verdict when evaluated
    block_reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence_id": self.sequence_id,
            "status": self.status.value,
            "requests_issued": self.requests_issued,
            "steps_executed": list(self.steps_executed),
            "final_state": self.final_state,
            "evidence_trace": list(self.evidence_trace)[:60],
            "causal_result": self.causal_result,
            "block_reason": self.block_reason,
        }


# ---------------------------------------------------------------------------
# Workflow construction from OBSERVED data (§7.2)
# ---------------------------------------------------------------------------

def build_workflows_from_observations(
    observations: Iterable[Mapping[str, Any]],
    *,
    max_workflows: int = 64,
    max_steps_per_workflow: int = 12,
) -> list[CompositeWorkflow]:
    """Group observed transitions into workflows BY workflow_key.

    Every step comes from an actual WorkflowObservation — nothing is
    templated or invented. Missing transitions simply do not appear.
    """
    by_key: dict[str, list[WorkflowStepSpec]] = {}
    evidence: dict[str, set[str]] = {}
    objects: dict[str, set[str]] = {}
    boundaries: dict[str, set[str]] = {}
    confidences: dict[str, list[float]] = {}
    for obs in observations:
        if not isinstance(obs, Mapping):
            continue
        key = str(obs.get("workflow_key") or "")
        endpoint = str(obs.get("endpoint") or "")
        if not key or not endpoint:
            continue
        step = WorkflowStepSpec(
            transition_key=str(obs.get("transition_key") or endpoint),
            endpoint=endpoint,
            method=str(obs.get("method") or "GET"),
            from_state=str(obs.get("from_state") or "unknown"),
            to_state=str(obs.get("to_state") or "unknown"),
            preconditions=[str(p) for p in (obs.get("prerequisites") or [])][:12],
            authorization_boundary=str(obs.get("authorization_boundary") or "unknown"),
            identity_ref=str(obs.get("identity_ref") or ""),
            object_refs=[str(r) for r in (obs.get("object_refs") or [])][:20],
            destructive=bool(obs.get("destructive")),
            evidence_refs=[str(e) for e in (obs.get("evidence_refs") or [])][:20],
        )
        steps = by_key.setdefault(key, [])
        if len(steps) < max_steps_per_workflow and not any(
            s.transition_key == step.transition_key for s in steps
        ):
            steps.append(step)
        evidence.setdefault(key, set()).add(
            str(obs.get("fingerprint") or ""))
        if step.object_refs:
            objects.setdefault(key, set()).update(step.object_refs)
        boundaries.setdefault(key, set()).add(step.authorization_boundary)
        confidences.setdefault(key, []).append(
            float(obs.get("confidence") or 0.5))
    workflows: list[CompositeWorkflow] = []
    for key in sorted(by_key):
        if len(workflows) >= max_workflows:
            break
        conf = confidences.get(key) or [0.5]
        workflows.append(CompositeWorkflow(
            workflow_key=key,
            steps=by_key[key],
            object_identity_refs=sorted(objects.get(key, set())),
            authorization_boundaries=sorted(
                b for b in boundaries.get(key, set()) if b != "unknown"),
            evidence_refs=sorted(
                e for e in evidence.get(key, set()) if e)[:30],
            confidence=round(sum(conf) / len(conf), 3),
        ))
    return workflows


# ---------------------------------------------------------------------------
# Sequence candidates + invariants (§7.4/§7.5)
# ---------------------------------------------------------------------------

# Evidence-backed invariant templates (§7.5). An invariant used in a
# candidate MUST carry its supporting observation references.
INVARIANT_TEMPLATES: dict[str, str] = {
    "rejected_transition_no_state_change":
        "A rejected transition must not change the object state.",
    "approval_not_self_completable":
        "An operation requiring approval must not be completed by an "
        "unauthorized principal.",
    "replay_restriction":
        "A completed transaction must not be replayable in a way that "
        "violates the observed state rules.",
    "tenant_boundary_enforced":
        "A user must not be able to act on an unrelated tenant's object.",
    "ownership_boundary_enforced":
        "Ownership-dependent operations must enforce the observed "
        "ownership boundary.",
    "no_state_skip":
        "A workflow must not skip a required state.",
    "alternate_representation_same_authorization":
        "An alternate object representation must preserve the same "
        "authorization semantics.",
    "failed_operation_no_partial_state":
        "A failed operation must not leave an invalid partial state.",
}


def build_sequence_candidates(
    workflows: Iterable[CompositeWorkflow],
    *,
    max_depth: int = MAX_SEQUENCE_DEPTH_DEFAULT,
    max_candidates: int = MAX_CANDIDATE_SEQUENCES_DEFAULT,
) -> list[SequenceCandidate]:
    """Build a SMALL number of high-information bounded sequences.

    Prefer information-dense candidates over combinatorial volume
    (§7.4): (1) the full observed happy path with a replay/invariant
    probe; (2) direct final-step replay (state-skip test); (3) re-order
    probes only when ≥3 steps exist; (4) approval-boundary probes when
    a step declares a role_scoped boundary.
    """
    max_depth = max(1, min(max_depth, MAX_SEQUENCE_DEPTH_HARD))
    candidates: list[SequenceCandidate] = []

    def _add(candidate: SequenceCandidate) -> None:
        if len(candidates) < min(max_candidates, MAX_CANDIDATE_SEQUENCES_HARD):
            candidates.append(candidate)

    for wf in workflows:
        if not wf.steps:
            continue
        steps = wf.steps[:max_depth]
        supporting = [e for e in wf.evidence_refs][:8]
        objects = ",".join(wf.object_identity_refs[:3])

        # (1) happy path replay — replay restriction + rejected-transition invariants
        if len(steps) >= 2:
            _add(SequenceCandidate(
                sequence_id=str(uuid.uuid5(
                    WORKFLOW_NAMESPACE, f"{wf.workflow_id}:replay")),
                workflow_id=wf.workflow_id,
                steps=list(steps),
                invariant="replay_restriction",
                invariant_supporting_refs=supporting,
                hypothesis=(
                    "Re-running the completed observed sequence violates the "
                    "observed state rules (e.g. double completion or state "
                    "corruption)."
                ),
                expected_negative_control=(
                    "First run from a reset state behaves as observed "
                    "(the positive control)."
                ),
                safety="state_mutating" if any(
                    s.method.upper() not in ("GET", "HEAD") for s in steps
                ) else "read_only",
            ))
        # (2) direct final-step replay — state-skip invariant
        if len(steps) >= 2:
            _add(SequenceCandidate(
                sequence_id=str(uuid.uuid5(
                    WORKFLOW_NAMESPACE, f"{wf.workflow_id}:skip")),
                workflow_id=wf.workflow_id,
                steps=[steps[0], steps[-1]],
                invariant="no_state_skip",
                invariant_supporting_refs=supporting,
                hypothesis=(
                    "Executing the final observed transition directly, "
                    "skipping the required intermediate states, is accepted."
                ),
                expected_negative_control=(
                    "Full sequence from reset state reaches the final state "
                    "legitimately."
                ),
                safety="state_mutating" if steps[-1].method.upper() not in (
                    "GET", "HEAD") else "read_only",
            ))
        # (3) approval boundary probe — the FULL observed path up to and
        # including the role-scoped step (the positive control must be
        # able to reach the approval legitimately)
        for index, step in enumerate(steps):
            if step.authorization_boundary == "role_scoped":
                _add(SequenceCandidate(
                    sequence_id=str(uuid.uuid5(
                        WORKFLOW_NAMESPACE,
                        f"{wf.workflow_id}:approval:{step.transition_key}")),
                    workflow_id=wf.workflow_id,
                    steps=list(steps[:index + 1]),
                    invariant="approval_not_self_completable",
                    invariant_supporting_refs=supporting + step.evidence_refs,
                    hypothesis=(
                        f"The approval-requiring transition "
                        f"'{step.transition_key}' can be completed by a "
                        f"principal without the required role."
                    ),
                    expected_negative_control=(
                        "The same sequence under the authorized principal "
                        "succeeds (positive control), and the unauthorized "
                        "principal is denied on a blanket-restricted object "
                        "(negative control)."
                    ),
                    safety="state_mutating" if any(
                        s.method.upper() not in ("GET", "HEAD")
                        for s in steps[:index + 1]
                    ) else "read_only",
                ))
                break
        # (4) ownership/tenant boundary probe (cross-identity workflows)
        cross_identity = [s for s in steps if s.authorization_boundary in (
            "cross_identity", "object_scoped")]
        if cross_identity:
            _add(SequenceCandidate(
                sequence_id=str(uuid.uuid5(
                    WORKFLOW_NAMESPACE, f"{wf.workflow_id}:ownership")),
                workflow_id=wf.workflow_id,
                steps=list(cross_identity[:2]),
                invariant="ownership_boundary_enforced",
                invariant_supporting_refs=supporting,
                hypothesis=(
                    "An ownership/tenant-dependent transition is accepted "
                    "for a principal that does not own the object "
                    f"({objects})."
                ),
                expected_negative_control=(
                    "The owner principal's execution of the same transition "
                    "succeeds (positive control)."
                ),
                safety="state_mutating" if any(
                    s.method.upper() not in ("GET", "HEAD")
                    for s in cross_identity[:2]
                ) else "read_only",
            ))
    return candidates


# ---------------------------------------------------------------------------
# Bounded sequence execution (§7.6) + validation (§7.7)
# ---------------------------------------------------------------------------

def _as_candidate(candidate: Any) -> "SequenceCandidate":
    """Accept a SequenceCandidate or its dict projection (the state
    channel round-trip shape)."""
    if isinstance(candidate, SequenceCandidate):
        return candidate
    return SequenceCandidate(
        sequence_id=str(candidate.get("sequence_id") or ""),
        workflow_id=str(candidate.get("workflow_id") or ""),
        steps=[
            WorkflowStepSpec(
                transition_key=str(s.get("transition_key") or ""),
                endpoint=str(s.get("endpoint") or ""),
                method=str(s.get("method") or "GET"),
                from_state=str(s.get("from_state") or "unknown"),
                to_state=str(s.get("to_state") or "unknown"),
                preconditions=list(s.get("preconditions") or []),
                authorization_boundary=str(
                    s.get("authorization_boundary") or "unknown"),
                identity_ref=str(s.get("identity_ref") or ""),
                object_refs=list(s.get("object_refs") or []),
                destructive=bool(s.get("destructive")),
                evidence_refs=list(s.get("evidence_refs") or []),
            )
            for s in (candidate.get("steps") or [])
            if isinstance(s, Mapping)
        ],
        invariant=str(candidate.get("invariant") or ""),
        invariant_supporting_refs=list(
            candidate.get("invariant_supporting_refs") or []),
        hypothesis=str(candidate.get("hypothesis") or ""),
        expected_negative_control=str(
            candidate.get("expected_negative_control") or ""),
        safety=str(candidate.get("safety") or "read_only"),
    )


class CompositeWorkflowEngine:
    """Executes bounded sequence candidates through the authorized
    client adapter and maps the evidence onto CausalGuard triples."""

    def __init__(
        self,
        client: SequenceClient,
        *,
        safety: FixtureSafetyContract | None = None,
        max_requests_per_sequence: int = MAX_REQUESTS_PER_SEQUENCE_DEFAULT,
        time_limit_seconds: float = SEQUENCE_TIME_LIMIT_SECONDS_DEFAULT,
        evaluate: Callable[..., Any] | None = None,
        reset_fixture: Callable[[], None] | None = None,
    ) -> None:
        self.client = client
        self.safety = safety or FixtureSafetyContract(
            resettable=False, isolated=False, authorized_by_operator=False,
        )
        self.max_requests = max(
            1, min(max_requests_per_sequence, MAX_REQUESTS_PER_SEQUENCE_HARD),
        )
        self.time_limit = time_limit_seconds
        # CausalGuard stays the sole confirmation authority: the engine
        # only constructs the evidence triple.
        if evaluate is None:
            from webpent.cqa_v2 import guarded_causal_evaluate
            evaluate = guarded_causal_evaluate
        self._evaluate = evaluate
        self._reset_fixture = reset_fixture

    # -- execution ----------------------------------------------------------

    def execute(
        self, candidate: SequenceCandidate,
        *, actor_headers: Mapping[str, str] | None = None,
        control_headers: Mapping[str, str] | None = None,
        negative_control_probe: tuple[str, str] | None = None,
    ) -> SequenceOutcome:
        """Run one candidate sequence under bounds + safety contract.

        Two evaluation routes, both INSIDE the existing validation
        architecture (§1.1: no new confirmation path):

          * SAME-ACTOR state invariants (replay restriction, state
            skip, partial-state) — the sequence runs twice from reset
            states (positive control, then experiment) and the final
            observations go through ``cqa_v2.guarded_causal_evaluate``;
          * CROSS-ACTOR boundary invariants (approval/ownership/tenant)
            — the control run uses the authorized actor, the experiment
            run the unauthorized one, and the (authorized-on-R,
            unauthorized-on-R, unauthorized-on-C) triple goes through
            the registered privilege-differential validator
            (``run_validator``), the established route for cross-principal
            evidence. A missing negative-control probe abstains
            honestly (INCONCLUSIVE).

        The engine NEVER promotes anything: it produces evidence and an
        honest candidate status only.
        """
        outcome = SequenceOutcome(
            sequence_id=_as_candidate(candidate).sequence_id,
            status=SequenceOutcomeStatus.BLOCKED,
        )
        candidate = _as_candidate(candidate)
        # safety gate first (§7.6): destructive steps need the contract
        for step in candidate.steps:
            allowed, reason = self.safety.permits(
                step.method, step.destructive)
            if not allowed:
                outcome.block_reason = reason
                return outcome
        # state-mutating sequences need a resettable fixture contract
        if candidate.safety != "read_only" and not (
            self.safety.resettable and self.safety.isolated
        ):
            outcome.block_reason = (
                "state-mutating sequence requires a resettable isolated "
                "fixture contract (§7.6)"
            )
            return outcome

        cross_actor = candidate.invariant in (
            "approval_not_self_completable",
            "ownership_boundary_enforced",
            "tenant_boundary_enforced",
        )
        if cross_actor and negative_control_probe is None:
            outcome.block_reason = (
                "cross-actor invariant requires a negative-control probe "
                "(the unauthorized actor on a blanket-restricted object) — "
                "abstaining rather than confirming without a control"
            )
            return outcome

        started = time.monotonic()
        requests = 0

        def _run_sequence(headers: Mapping[str, str] | None) -> list[dict[str, Any]]:
            nonlocal requests
            trace: list[dict[str, Any]] = []
            for step in candidate.steps:
                if requests >= self.max_requests:
                    trace.append({
                        "step": step.transition_key, "skipped": True,
                        "reason": "per-sequence request budget exhausted",
                    })
                    break
                if time.monotonic() - started > self.time_limit:
                    trace.append({
                        "step": step.transition_key, "skipped": True,
                        "reason": "per-sequence time limit",
                    })
                    break
                try:
                    response = self.client.request(
                        step.method, step.endpoint,
                        headers=dict(headers or {}),
                    )
                except Exception as exc:  # fail-safe, honest telemetry
                    trace.append({
                        "step": step.transition_key,
                        "error": f"{type(exc).__name__}: {exc}"[:200],
                    })
                    break
                requests += 1
                body = response.get("body")
                body_text = body if isinstance(body, str) else str(body or "")
                raw_headers = response.get("headers") or {}
                lowered = {
                    str(k).lower(): str(v) for k, v in dict(raw_headers).items()
                }
                trace.append({
                    "step": step.transition_key,
                    "method": step.method,
                    "endpoint": step.endpoint,
                    "status_code": response.get("status_code"),
                    "body_preview": body_text[:200],
                    "semantic_digest": _digest(body_text),
                    "headers": lowered,
                })
                outcome.steps_executed.append(step.transition_key)
            return trace

        def _run_probe(method: str, path: str, headers: Mapping[str, str] | None):
            nonlocal requests
            if requests >= self.max_requests or (
                time.monotonic() - started > self.time_limit
            ):
                return None
            try:
                response = self.client.request(
                    method, path, headers=dict(headers or {}),
                )
            except Exception as exc:
                return {"error": f"{type(exc).__name__}: {exc}"[:200]}
            requests += 1
            body = response.get("body")
            body_text = body if isinstance(body, str) else str(body or "")
            return {
                "method": method, "endpoint": path,
                "status_code": response.get("status_code"),
                "body_preview": body_text[:200],
                "semantic_digest": _digest(body_text),
                "headers": {
                    str(k).lower(): str(v)
                    for k, v in dict(response.get("headers") or {}).items()
                },
            }

        def _reset() -> bool:
            if self._reset_fixture is not None and candidate.safety != "read_only":
                try:
                    self._reset_fixture()
                    return True
                except Exception as exc:
                    outcome.block_reason = f"fixture reset failed: {exc}"[:200]
                    return False
            return True

        # positive control first: the sequence under the OBSERVED actor
        # (owner/authorized headers when provided), from a reset state.
        if not _reset():
            return outcome
        control_trace = _run_sequence(control_headers or actor_headers)

        # the experimental run: same sequence, experimental actor
        if not _reset():
            return outcome
        experiment_trace = _run_sequence(actor_headers)

        # the authorization negative control probe (cross-actor only)
        control_probe = None
        if cross_actor and negative_control_probe is not None:
            method, path = negative_control_probe
            control_probe = _run_probe(method, path, actor_headers)

        outcome.requests_issued = requests
        outcome.evidence_trace = [
            {"phase": "positive_control", "steps": control_trace},
            {"phase": "experiment", "steps": experiment_trace},
        ]
        if control_probe is not None:
            outcome.evidence_trace.append({
                "phase": "negative_control_probe", "steps": [control_probe],
            })
        if not experiment_trace or not control_trace:
            outcome.status = SequenceOutcomeStatus.INCONCLUSIVE
            outcome.block_reason = "incomplete traces"
            return outcome

        if cross_actor:
            return self._evaluate_cross_actor(
                outcome, candidate, control_trace, experiment_trace,
                control_probe,
            )
        return self._evaluate_state_differential(
            outcome, candidate, control_trace, experiment_trace,
        )

    # -- evaluation routes -------------------------------------------------

    def _evaluate_state_differential(
        self, outcome: SequenceOutcome, candidate: SequenceCandidate,
        control_trace: list[dict[str, Any]],
        experiment_trace: list[dict[str, Any]],
    ) -> SequenceOutcome:
        """SAME-ACTOR state evidence -> CausalGuard (the sole
        confirmation authority for this evidence class)."""
        first_control = next(
            (t for t in control_trace if "status_code" in t), None)
        last_experiment = next(
            (t for t in reversed(experiment_trace) if "status_code" in t), None)
        last_control = next(
            (t for t in reversed(control_trace) if "status_code" in t), None)
        if not (first_control and last_experiment and last_control):
            outcome.status = SequenceOutcomeStatus.INCONCLUSIVE
            return outcome
        try:
            causal = self._evaluate(
                baseline=_observation_from_trace(first_control),
                candidate=_observation_from_trace(last_experiment),
                control=_observation_from_trace(last_control),
                safe_precondition=(
                    "sequence_bounded_state_mutation_with_reset"),
            )
        except Exception as exc:
            outcome.status = SequenceOutcomeStatus.INCONCLUSIVE
            outcome.block_reason = f"causal evaluation error: {exc}"[:200]
            return outcome
        outcome.causal_result = _causal_dict(causal)
        verdict = getattr(causal, "verdict", None)
        verdict_value = getattr(verdict, "value", str(verdict))
        outcome.final_state = str(
            (last_experiment.get("body_preview") or "")[:120])
        if verdict_value == "CONFIRMED":
            outcome.status = SequenceOutcomeStatus.POLICY_VIOLATION_CANDIDATE
        elif verdict_value == "CLEAN":
            outcome.status = SequenceOutcomeStatus.EXPECTED_DENIAL if (
                _denied(last_experiment) and not _denied(last_control)
            ) else SequenceOutcomeStatus.FALSE_HYPOTHESIS
        elif verdict_value == "BLOCKED":
            outcome.status = SequenceOutcomeStatus.BLOCKED
            outcome.block_reason = getattr(
                causal, "block_reason", "") or "causal guard blocked"
        else:
            outcome.status = SequenceOutcomeStatus.INCONCLUSIVE
        return outcome

    def _evaluate_cross_actor(
        self, outcome: SequenceOutcome, candidate: SequenceCandidate,
        control_trace: list[dict[str, Any]],
        experiment_trace: list[dict[str, Any]],
        control_probe: dict[str, Any] | None,
    ) -> SequenceOutcome:
        """CROSS-ACTOR boundary evidence -> the registered
        privilege-differential validator (the established production
        route for cross-principal evidence, §6.5)."""
        last_control = next(
            (t for t in reversed(control_trace) if "status_code" in t), None)
        last_experiment = next(
            (t for t in reversed(experiment_trace) if "status_code" in t), None)
        if not (last_control and last_experiment and control_probe):
            outcome.status = SequenceOutcomeStatus.INCONCLUSIVE
            outcome.block_reason = "missing control/experiment/probe evidence"
            return outcome
        if control_probe.get("error"):
            outcome.status = SequenceOutcomeStatus.INCONCLUSIVE
            outcome.block_reason = f"control probe failed: {control_probe['error']}"
            return outcome
        try:
            from webpent.production.validators import run_validator
            result = run_validator(
                "PRIVILEGE_DIFFERENTIAL",
                baseline=_evidence_from_trace(last_control),
                candidate=_evidence_from_trace(last_experiment),
                negative_control=_evidence_from_trace(control_probe),
            )
        except Exception as exc:
            outcome.status = SequenceOutcomeStatus.INCONCLUSIVE
            outcome.block_reason = f"validator error: {exc}"[:200]
            return outcome
        outcome.causal_result = {
            "verdict": str(getattr(result, "outcome", "")),
            "causal_signal": getattr(result, "outcome", "") == "CONFIRMED",
            "confidence": float(getattr(result, "confidence", 0.5) or 0.5),
            "block_reason": "",
            "authority": "production.validators.run_validator:PRIVILEGE_DIFFERENTIAL",
            "refutation_path": str(getattr(result, "refutation_path", "") or ""),
        }
        outcome.final_state = str(
            (last_experiment.get("body_preview") or "")[:120])
        if result.outcome == "CONFIRMED":
            outcome.status = SequenceOutcomeStatus.POLICY_VIOLATION_CANDIDATE
        elif result.outcome == "REFUTED":
            outcome.status = SequenceOutcomeStatus.FALSE_HYPOTHESIS
        else:
            outcome.status = SequenceOutcomeStatus.INCONCLUSIVE
        return outcome


def _denial_body(trace_entry: Mapping[str, Any]) -> str:
    return str(trace_entry.get("body_preview") or "")


def _denied(trace_entry: Mapping[str, Any]) -> bool:
    status = trace_entry.get("status_code")
    return status in (401, 403)


def _digest(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _observation_from_trace(entry: Mapping[str, Any]) -> dict[str, Any]:
    """Map a trace entry onto the CausalGuard observation shape (the
    same contract make_observation produces)."""
    body = str(entry.get("body_preview") or "")
    return {
        "status_code": int(entry.get("status_code") or 0),
        "body_length": len(body),
        "semantic_digest": entry.get("semantic_digest") or _digest(body),
        "response_shape": "json" if body[:1] in "{[" else "text",
        "request": {
            "method": str(entry.get("method") or "GET"),
            "path": str(entry.get("endpoint") or ""),
            "header_names": sorted(dict(entry.get("headers") or {})),
        },
        "headers": dict(entry.get("headers") or {}),
        "body_preview": body[:200],
    }


def _evidence_from_trace(entry: Mapping[str, Any]) -> dict[str, Any]:
    """Map a trace entry onto the production validator evidence shape
    (the (baseline, candidate, negative_control) dicts run_validator
    consumes — status_code, response_body, headers)."""
    return {
        "status_code": int(entry.get("status_code") or 0),
        "response_body": str(entry.get("body_preview") or ""),
        "headers": dict(entry.get("headers") or {}),
    }


def _causal_dict(causal: Any) -> dict[str, Any]:
    return {
        "verdict": getattr(
            getattr(causal, "verdict", None), "value",
            str(getattr(causal, "verdict", ""))),
        "causal_signal": getattr(causal, "causal_signal", ""),
        "confidence": getattr(causal, "confidence", 0.0),
        "block_reason": getattr(causal, "block_reason", ""),
        "authority": "cqa_v2.guarded_causal_evaluate",
    }
