"""UM-DR-37 §7 — structured failure taxonomy and learning events.

Learning from failed discovery attempts as STRUCTURED EVENTS, not a
generic confidence dial. Grounded in this mission's actual root-cause
investigation: the four zero-findings root causes are first-class
reason codes with their corrective actions.

Design rules (mission §7):

  * every failure event carries: stage, reason code, entity IDs,
    hypothesis ID, execution-trace reference, supporting evidence,
    causal attribution status, corrective action, and diagnosis
    confidence;
  * the diagnosis is grounded in a recorded trace — the LLM never
    invents a root cause (attribution is confirmed/suspected/unknown,
    set by the diagnosing code from recorded evidence);
  * a failure influences the NEXT decision only when the evidence
    justifies it: confirmed attribution with sufficient diagnosis
    confidence. Suspected/unknown failures are recorded but do NOT
    steer decisions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class FailureStage(str, Enum):
    """The 16 discovery-pipeline stages a failure can occur in."""

    SURFACE_DISCOVERY = "surface_discovery"
    ENDPOINT_EXTRACTION = "endpoint_extraction"
    PARAMETER_EXTRACTION = "parameter_extraction"
    IDENTITY_RESOLUTION = "identity_resolution"
    RESOURCE_OWNERSHIP = "resource_ownership"
    APPLICATION_UNDERSTANDING = "application_understanding"
    HYPOTHESIS_GENERATION = "hypothesis_generation"
    HYPOTHESIS_RANKING = "hypothesis_ranking"
    EXPERIMENT_SELECTION = "experiment_selection"
    EXPERIMENT_EXECUTION = "experiment_execution"
    OBSERVATION_PARSING = "observation_parsing"
    SECURITY_ORACLE = "security_oracle"
    CAUSAL_CONFIRMATION = "causal_confirmation"
    PROOF_GENERATION = "proof_generation"
    REPLAY = "replay"
    PROMOTION = "promotion"


class CausalAttribution(str, Enum):
    """Who established the cause — and from what."""

    CONFIRMED = "confirmed"      # diagnosed from a recorded trace
    SUSPECTED = "suspected"      # plausible, evidence incomplete
    UNKNOWN = "unknown"          # recorded, not diagnosed


# ---------------------------------------------------------------------------
# The reason-code registry — grounded in measured root causes
# ---------------------------------------------------------------------------

#: reason_code -> (stage, corrective action directive, family gate)
#: The four UM-DR-37 root causes appear with their REAL corrective
#: actions; the remaining codes cover the mission's failure examples.
REASON_CODES: dict[str, dict[str, str]] = {
    # --- UM-DR-37 measured root causes (RC-1..RC-4) -------------------
    "json_manifest_unparsed": {
        "stage": FailureStage.SURFACE_DISCOVERY.value,
        "corrective_action": "reconsider endpoint discovery: parse JSON "
                             "link manifests before the HTML gate",
        "blocks_family": "",
    },
    "identifier_gate_too_strict": {
        "stage": FailureStage.ENDPOINT_EXTRACTION.value,
        "corrective_action": "relax structured-identifier extraction "
                             "without accepting plain words",
        "blocks_family": "",
    },
    "identity_profiles_dropped": {
        "stage": FailureStage.IDENTITY_RESOLUTION.value,
        "corrective_action": "repair the identity model before "
                             "generating more access-control experiments",
        "blocks_family": "access_control",
    },
    "guard_inconclusive_insufficient_auth_context": {
        "stage": FailureStage.CAUSAL_CONFIRMATION.value,
        "corrective_action": "record the authorization context the node "
                             "possesses (actor/owner/outcome) into the "
                             "observation contract; never fabricate "
                             "outcomes",
        "blocks_family": "",
    },
    # --- mission §7 examples ------------------------------------------
    "ownership_assumption_contradicted": {
        "stage": FailureStage.RESOURCE_OWNERSHIP.value,
        "corrective_action": "revise the relevant resource relationship "
                             "(mark CONTRADICTED, keep both sides)",
        "blocks_family": "",
    },
    "experiment_inconclusive": {
        "stage": FailureStage.SECURITY_ORACLE.value,
        "corrective_action": "generate a more discriminating follow-up "
                             "experiment",
        "blocks_family": "",
    },
    "candidate_refuted": {
        "stage": FailureStage.SECURITY_ORACLE.value,
        "corrective_action": "do not repeat an equivalent experiment "
                             "unless new evidence changes the "
                             "preconditions",
        "blocks_family": "",
    },
    "observation_unparseable": {
        "stage": FailureStage.OBSERVATION_PARSING.value,
        "corrective_action": "re-run with a bounded raw-capture fallback "
                             "before interpreting",
        "blocks_family": "",
    },
    "budget_exhausted": {
        "stage": FailureStage.EXPERIMENT_SELECTION.value,
        "corrective_action": "stop: report incomplete discovery honestly, "
                             "never as safety",
        "blocks_family": "",
    },
}


@dataclass
class LearningEvent:
    """One structured failure record."""

    stage: FailureStage
    reason_code: str
    causal_attribution: CausalAttribution
    diagnosis_confidence: float
    entity_ids: tuple[str, ...] = ()
    hypothesis_id: str = ""
    trace_ref: str = ""
    supporting_evidence: tuple[str, ...] = ()
    corrective_action: str = ""

    def __post_init__(self) -> None:
        if self.reason_code not in REASON_CODES:
            raise ValueError(
                f"unregistered reason code: {self.reason_code!r} — the "
                "taxonomy is closed; register the code with its "
                "corrective action first")
        self.corrective_action = (
            self.corrective_action
            or REASON_CODES[self.reason_code]["corrective_action"])
        self.diagnosis_confidence = max(
            0.0, min(1.0, float(self.diagnosis_confidence)))

    def to_dict(self) -> dict:
        return {
            "stage": self.stage.value,
            "reason_code": self.reason_code,
            "causal_attribution": self.causal_attribution.value,
            "diagnosis_confidence": self.diagnosis_confidence,
            "entity_ids": list(self.entity_ids),
            "hypothesis_id": self.hypothesis_id,
            "trace_ref": self.trace_ref,
            "supporting_evidence": list(self.supporting_evidence),
            "corrective_action": self.corrective_action,
        }


#: a failure steers the NEXT decision only with confirmed attribution
#: AND sufficient diagnosis confidence (mission: evidence-justified
#: influence only).
INFLUENCE_THRESHOLD = 0.7


@dataclass
class FailureLedger:
    """The bounded record of failure events for one investigation."""

    events: list[LearningEvent] = field(default_factory=list)
    max_events: int = 500

    def record(self, event: LearningEvent) -> LearningEvent:
        if len(self.events) >= self.max_events:
            self.events = self.events[-self.max_events // 2:]
        self.events.append(event)
        return event

    def events_for(self, stage: FailureStage) -> list[LearningEvent]:
        return [event for event in self.events
                if event.stage is stage]

    def should_influence_decision(self, event: LearningEvent) -> bool:
        return (
            event.causal_attribution is CausalAttribution.CONFIRMED
            and event.diagnosis_confidence >= INFLUENCE_THRESHOLD
        )

    def blocking_family(self) -> tuple[str, str] | None:
        """The (family, reason) a confirmed failure currently BLOCKS —
        e.g. identity-resolution failure defers access-control
        experiments until the identity model is repaired."""
        for event in reversed(self.events):
            if not self.should_influence_decision(event):
                continue
            family = REASON_CODES[event.reason_code].get("blocks_family")
            if family:
                return family, event.reason_code
        return None

    def to_dict(self) -> dict:
        return {
            "events": [event.to_dict() for event in self.events],
            "attribution_counts": {
                status.value: sum(
                    1 for event in self.events
                    if event.causal_attribution is status)
                for status in CausalAttribution
            },
            "influencing_events": sum(
                1 for event in self.events
                if self.should_influence_decision(event)),
        }


def apply_failure_policy(
    candidates: Iterable[tuple[str, str]],
    ledger: FailureLedger,
) -> tuple[list[tuple[str, str]], list[dict]]:
    """Apply the ledger's confirmed corrective policies to a candidate
    list of (experiment_id, family) pairs.

    Returns (kept, deferred): a family blocked by a CONFIRMED failure is
    deferred (with the reason recorded) until the failure is addressed;
    suspected/unknown failures never defer anything — insufficient
    evidence must not steer decisions.
    """
    blocked = ledger.blocking_family()
    kept: list[tuple[str, str]] = []
    deferred: list[dict] = []
    for experiment_id, family in candidates:
        if blocked and blocked[0] == family:
            deferred.append({
                "experiment_id": experiment_id,
                "family": family,
                "reason_code": blocked[1],
                "corrective_action": REASON_CODES[blocked[1]]
                ["corrective_action"],
            })
        else:
            kept.append((experiment_id, family))
    return kept, deferred
