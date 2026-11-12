"""UM-DR-36.6 — Application Expected Behavior & Business Invariant Model.

Represents what the application is OBSERVED to do and what behavior is
EXPECTED, with explicit uncertainty:

  * ``observed`` rules — transitions/invariants backed by campaign
    observations (workflow_observations channel);
  * ``inferred`` rules — assumptions inferred from bounded evidence
    (never promoted to observed);
  * ``operator`` expectations — operator-declared expectations (when
    provided);
  * ``unknown`` policies — behaviors with NO evidence either way,
    surfaced as unresolved questions, never treated as violations.

The model distinguishes an undocumented behavior from an illegal one: a
transition never observed is an UNKNOWN POLICY (question), not a
forbidden transition, unless an evidenced invariant says otherwise.

Production integration: consumed by the identity_workflow node (the
sanctioned business-logic hypothesis producer) to emit typed
``business_logic`` hypotheses through the EXISTING hypothesis pool —
no second planner. Confirmation stays with CausalGuard; stateful
experiments run only through the authorized executor with isolated,
controlled, authorized test state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

_RULE_CONFIDENCE = {
    "observed": 0.8,
    "operator": 0.95,
    "inferred": 0.4,
    "unknown": 0.1,
}

#: Invariant families the model can express (evidence-backed only).
INVARIANT_FAMILIES: tuple[str, ...] = (
    "state_transition_allowed",
    "state_transition_never_observed",
    "one_time_use_token",
    "replay_restricted_operation",
    "workflow_ordering",
    "ownership_boundary",
    "tenant_boundary",
    "value_constraint",
)


@dataclass
class BehaviorRule:
    """One expected-behavior rule with evidence and uncertainty."""
    rule_id: str
    family: str
    statement: str
    provenance: str          # observed | operator | inferred | unknown
    confidence: float
    evidence_refs: list[str] = field(default_factory=list)
    preconditions: dict[str, Any] = field(default_factory=dict)
    forbidden: bool = False  # True => violating behavior is a candidate finding hypothesis

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "family": self.family,
            "statement": self.statement[:240],
            "provenance": self.provenance,
            "confidence": self.confidence,
            "evidence_refs": self.evidence_refs[:8],
            "preconditions": dict(self.preconditions),
            "forbidden": self.forbidden,
        }


@dataclass
class ExpectedBehaviorModel:
    rules: list[BehaviorRule] = field(default_factory=list)
    unresolved_questions: list[str] = field(default_factory=list)

    def add(self, rule: BehaviorRule) -> None:
        existing = {r.rule_id for r in self.rules}
        if rule.rule_id not in existing:
            self.rules.append(rule)

    def forbidden_rules(self) -> list[BehaviorRule]:
        return [r for r in self.rules if r.forbidden]

    def to_dict(self) -> dict[str, Any]:
        by_provenance: dict[str, int] = {}
        for rule in self.rules:
            by_provenance[rule.provenance] = (
                by_provenance.get(rule.provenance, 0) + 1)
        return {
            "rule_count": len(self.rules),
            "by_provenance": by_provenance,
            "forbidden_rule_count": len(self.forbidden_rules()),
            "unresolved_question_count": len(self.unresolved_questions),
            "rules": [r.to_dict() for r in self.rules[:200]],
            "unresolved_questions": [q[:240] for q in self.unresolved_questions[:32]],
        }


def build_expected_behavior(state: Mapping[str, Any]) -> ExpectedBehaviorModel:
    """Derive the Expected Behavior Model from real campaign channels.

    Sources (all REAL): ``workflow_observations`` (observed transitions),
    ``object_identity_registry`` (ownership/tenant boundaries),
    operator-provided expectations (``operator_expectations`` channel when
    present). Nothing is fabricated: channels that did not materialize
    contribute honest unresolved questions instead of invented rules.
    """
    model = ExpectedBehaviorModel()
    observations = state.get("workflow_observations") if isinstance(state, Mapping) else None

    observed_transitions: dict[tuple[str, str, str], int] = {}
    workflow_endpoints: dict[str, set[str]] = {}
    if isinstance(observations, (list, tuple)):
        for obs in observations[:400]:
            if not isinstance(obs, Mapping):
                continue
            workflow_key = str(obs.get("workflow_key") or "workflow")
            from_state = str(obs.get("from_state") or "").strip()
            to_state = str(obs.get("to_state") or "").strip()
            endpoint = str(obs.get("endpoint") or "").strip()
            if endpoint:
                workflow_endpoints.setdefault(workflow_key, set()).add(endpoint)
            if from_state and to_state:
                key = (workflow_key, from_state, to_state)
                observed_transitions[key] = observed_transitions.get(key, 0) + 1

        # Observed transitions -> allowed rules (evidence-backed).
        for (workflow_key, from_state, to_state), count in sorted(
                observed_transitions.items()):
            model.add(BehaviorRule(
                rule_id=f"transition:{workflow_key}:{from_state}->{to_state}",
                family="state_transition_allowed",
                statement=(f"In workflow '{workflow_key}', state "
                           f"'{from_state}' was observed to transition to "
                           f"'{to_state}' ({count} observation(s))."),
                provenance="observed",
                confidence=_RULE_CONFIDENCE["observed"],
                evidence_refs=[f"workflow-observation:{workflow_key}:{from_state}:{to_state}"],
                preconditions={"workflow": workflow_key, "from_state": from_state,
                               "to_state": to_state},
                forbidden=False,
            ))
            # Inferred replay-restriction question: a state TRANSITION that
            # moves work forward is plausibly one-shot — but that is an
            # ASSUMPTION until tested, so it surfaces as an unresolved
            # question (never a forbidden rule).
            model.unresolved_questions.append(
                f"Is the {workflow_key} transition {from_state}->{to_state} "
                "replay-restricted (one-time-use)?")

    # Ownership / tenant boundaries from the identity registry (evidence).
    registry = state.get("object_identity_registry") if isinstance(state, Mapping) else None
    registry_dict = registry if isinstance(registry, Mapping) else None
    if registry_dict is None and registry is not None:
        as_dict = getattr(registry, "as_dict", None)
        if callable(as_dict):
            try:
                registry_dict = as_dict()
            except (AttributeError, TypeError, ValueError, RuntimeError):
                registry_dict = None
    if isinstance(registry_dict, Mapping):
        identities = registry_dict.get("identities")
        if isinstance(identities, list) and identities:
            model.add(BehaviorRule(
                rule_id="boundary:object_ownership_anchor",
                family="ownership_boundary",
                statement=("Objects are identified by the tenant|type|id "
                           "anchor; access differentials must respect "
                           "ownership as observed in the registry."),
                provenance="observed",
                confidence=_RULE_CONFIDENCE["observed"],
                evidence_refs=["object-identity-registry"],
                forbidden=True,
            ))

    # Operator expectations (declared, never guessed).
    expectations = state.get("operator_expectations") if isinstance(state, Mapping) else None
    if isinstance(expectations, (list, tuple)):
        for idx, expectation in enumerate(expectations[:64]):
            if isinstance(expectation, Mapping) and expectation.get("statement"):
                model.add(BehaviorRule(
                    rule_id=f"operator:{idx}",
                    family=str(expectation.get("family") or "value_constraint"),
                    statement=str(expectation["statement"])[:240],
                    provenance="operator",
                    confidence=_RULE_CONFIDENCE["operator"],
                    evidence_refs=[str(expectation.get("source") or "operator")[:120]],
                    forbidden=bool(expectation.get("forbidden")),
                ))

    # Honest unknowns: no observations means questions, not rules.
    if not observed_transitions:
        model.unresolved_questions.append(
            "No workflow state transitions were observed — expected "
            "transition behavior is unknown (not forbidden).")
    if not model.rules:
        model.unresolved_questions.append(
            "No evidenced behavior rules could be derived from the "
            "campaign channels — the expected-behavior model is empty.")
    return model
