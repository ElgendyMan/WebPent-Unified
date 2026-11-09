"""VABH-FQR v9 contracts: engineering-complete research intelligence, advisory only."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum


class V9Status(StrEnum):
    ADVISORY = "advisory"
    READY = "ready"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    STOPPED = "stopped"


class LoopStage(StrEnum):
    OBSERVE = "observe"
    UNDERSTAND = "understand"
    REASON = "reason"
    PLAN = "plan"
    INVESTIGATE = "investigate"
    VALIDATE = "validate"
    REVIEW = "review"
    LEARN = "learn"
    IMPROVE = "improve"


class HypothesisDisposition(StrEnum):
    HYPOTHESIS = "hypothesis"
    RETAINED = "retained"
    REJECTED = "rejected"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"


class EvidenceDisposition(StrEnum):
    OBSERVATION_ONLY = "observation_only"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    CONFIRMED = "confirmed"


def _bounded(value: float, name: str) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name}_out_of_range")


def _hash(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class SecurityArchitectureMapV9:
    map_id: str
    purpose: str
    critical_assets: tuple[str, ...]
    threat_boundaries: tuple[str, ...]
    privilege_model: tuple[str, ...]
    workflows: tuple[str, ...]
    invariants: tuple[str, ...]
    trust_relationships: tuple[str, ...]
    assumptions: tuple[str, ...]
    source_refs: tuple[str, ...] = ()
    status: V9Status = V9Status.ADVISORY

    def __post_init__(self) -> None:
        required = (self.purpose, self.critical_assets, self.threat_boundaries, self.workflows)
        if not all(required):
            raise ValueError("architecture_map_requires_core_fields")


@dataclass(frozen=True, slots=True)
class ResearchExperimentPlanV9:
    experiment_id: str
    question: str
    selected_action: str
    expected_information_gain: float
    uncertainty_reduction: float
    evidence_value: float
    estimated_cost: float
    risk: float
    available_capability: str
    preconditions: tuple[str, ...]
    success_criteria: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    source_refs: tuple[str, ...] = ()
    execution_requested: bool = False
    status: V9Status = V9Status.ADVISORY

    def __post_init__(self) -> None:
        for name in (
            "expected_information_gain",
            "uncertainty_reduction",
            "evidence_value",
            "estimated_cost",
            "risk",
        ):
            _bounded(getattr(self, name), name)
        if not self.question or not self.selected_action or not self.preconditions:
            raise ValueError("experiment_plan_is_incomplete")
        if self.execution_requested:
            raise ValueError("experiment_plan_cannot_execute")


@dataclass(frozen=True, slots=True)
class SecurityHypothesisV9:
    hypothesis_id: str
    origin: str
    statement: str
    reasoning_chain: tuple[str, ...]
    supporting_evidence: tuple[str, ...]
    conflicting_evidence: tuple[str, ...]
    confidence_history: tuple[float, ...]
    next_validation_action: str
    disposition: HypothesisDisposition = HypothesisDisposition.HYPOTHESIS
    source_refs: tuple[str, ...] = ()
    confirmation_claimed: bool = False
    finding_created: bool = False

    def __post_init__(self) -> None:
        if not self.origin or not self.statement or not self.reasoning_chain:
            raise ValueError("hypothesis_reasoning_is_incomplete")
        if not self.confidence_history or not self.next_validation_action:
            raise ValueError("hypothesis_requires_confidence_and_next_action")
        for value in self.confidence_history:
            _bounded(value, "hypothesis_confidence")
        if self.confirmation_claimed or self.finding_created:
            raise ValueError("hypothesis_cannot_confirm_or_create_finding")


@dataclass(frozen=True, slots=True)
class EvidenceRecordV9:
    evidence_id: str
    subject_id: str
    observation_refs: tuple[str, ...]
    causal_oracle: str
    reproducibility_requirements: tuple[str, ...]
    proof_bundle_ref: str
    seal_verified: bool
    replay_verified: bool
    explanation: str
    disposition: EvidenceDisposition = EvidenceDisposition.BLOCKED
    redacted: bool = True
    finding_created: bool = False

    def __post_init__(self) -> None:
        if not self.redacted:
            raise ValueError("evidence_must_be_redacted")
        if self.finding_created:
            raise ValueError("evidence_cannot_create_finding")
        if self.disposition is EvidenceDisposition.CONFIRMED and not all(
            (
                self.observation_refs,
                self.causal_oracle,
                self.proof_bundle_ref,
                self.seal_verified,
                self.replay_verified,
            )
        ):
            raise ValueError("confirmed_evidence_requires_causal_sealed_replayable_proof")


@dataclass(frozen=True, slots=True)
class ResearchMemorySnapshotV9:
    target_id: str
    engagement_id: str
    version: str
    lessons: tuple[str, ...]
    rejected_hypotheses: tuple[str, ...]
    failed_experiments: tuple[str, ...]
    state_digest: str
    redacted: bool = True

    def __post_init__(self) -> None:
        if not self.redacted or not self.target_id or not self.engagement_id or not self.version:
            raise ValueError("memory_snapshot_scope_or_redaction_invalid")


@dataclass(frozen=True, slots=True)
class LoopStepV9:
    stage: LoopStage
    completed: bool
    rationale: str
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    blocked_reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class VIPBenchmarkCaseV9:
    case_id: str
    scenario_class: str
    realistic_target_behavior: bool
    hidden_assumptions: tuple[str, ...]
    autonomous_opportunity: bool
    causal_oracle: bool
    proof_bundle: bool
    replay_verified: bool
    metric_ready: bool
    disposition: str
    blocked_reasons: tuple[str, ...] = ()
    requests_sent: int = 0

    def __post_init__(self) -> None:
        if self.requests_sent != 0:
            raise ValueError("v9_benchmark_must_send_zero_requests")
        if self.disposition == "scorable" and not all(
            (
                self.realistic_target_behavior,
                self.hidden_assumptions,
                self.autonomous_opportunity,
                self.causal_oracle,
                self.proof_bundle,
                self.replay_verified,
                self.metric_ready,
            )
        ):
            raise ValueError("scorable_case_requires_complete_v9_evidence")


@dataclass(frozen=True, slots=True)
class ResearchQualityScoreV9:
    engagement_id: str
    target_id: str
    engineering_metrics: dict[str, float | None]
    qualification_metrics: dict[str, float | None]
    benchmark_case_count: int
    scorable_case_count: int
    requests_sent: int = 0
    valid_ground_truth: bool = False
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if self.requests_sent != 0 or not self.advisory_only:
            raise ValueError("quality_score_cannot_execute")
        for group in (self.engineering_metrics, self.qualification_metrics):
            for value in group.values():
                if value is not None:
                    _bounded(value, "quality_metric")


@dataclass(frozen=True, slots=True)
class VIPReadinessAssessmentV9:
    engagement_id: str
    target_id: str
    architecture_maturity: str
    autonomy: str
    discovery_intelligence: str
    evidence_pipeline: str
    benchmark_quality: str
    operational_reliability: str
    limitations: tuple[str, ...]
    blockers: tuple[str, ...]
    status: V9Status = V9Status.BLOCKED
    vip_approved: bool = False
    p10_opened: bool = False
    governance_modified: bool = False
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if (
            self.vip_approved
            or self.p10_opened
            or self.governance_modified
            or not self.advisory_only
        ):
            raise ValueError("readiness_cannot_grant_authority")


@dataclass(frozen=True, slots=True)
class UnifiedIntelligenceSnapshotV9:
    """Proposal-only composition result for the generic research core."""

    engagement_id: str
    target_id: str
    hypothesis_ids: tuple[str, ...]
    hypothesis_classes: tuple[str, ...]
    queue_task_ids: tuple[str, ...]
    selected_task_id: str | None
    decision_status: str
    decision_stage: str
    confirmation_posture: str
    confirmation_score: float | None
    engineering_confirmed: bool
    scoring_eligible: bool
    recommendations: tuple[str, ...]
    requests_sent: int = 0
    execution_allowed: bool = False
    mutation_allowed: bool = False
    finding_created: bool = False
    qualification_effect: bool = False

    def __post_init__(self) -> None:
        if self.requests_sent != 0:
            raise ValueError("unified_snapshot_must_send_zero_requests")
        if (
            self.execution_allowed
            or self.mutation_allowed
            or self.finding_created
            or self.qualification_effect
        ):
            raise ValueError("unified_snapshot_cannot_execute_or_promote")
        if self.confirmation_score is not None and not 0.0 <= self.confirmation_score <= 1.0:
            raise ValueError("confirmation_score_out_of_range")

    def digest(self) -> str:
        return _hash(asdict(self))


@dataclass(frozen=True, slots=True)
class VABHFQRV9Result:
    engagement_id: str
    target_id: str
    architecture_map: SecurityArchitectureMapV9
    experiments: tuple[ResearchExperimentPlanV9, ...]
    hypotheses: tuple[SecurityHypothesisV9, ...]
    evidence: tuple[EvidenceRecordV9, ...]
    memory_snapshot: ResearchMemorySnapshotV9
    loop_steps: tuple[LoopStepV9, ...]
    requests_sent: int = 0
    mutations_performed: bool = False
    finding_created: bool = False
    qualification_approved: bool = False

    def __post_init__(self) -> None:
        if (
            self.requests_sent
            or self.mutations_performed
            or self.finding_created
            or self.qualification_approved
        ):
            raise ValueError("v9_result_cannot_execute_or_approve")

    def digest(self) -> str:
        return _hash(asdict(self))


__all__ = [
    "EvidenceDisposition",
    "EvidenceRecordV9",
    "HypothesisDisposition",
    "LoopStage",
    "LoopStepV9",
    "ResearchExperimentPlanV9",
    "ResearchMemorySnapshotV9",
    "ResearchQualityScoreV9",
    "SecurityArchitectureMapV9",
    "SecurityHypothesisV9",
    "V9Status",
    "UnifiedIntelligenceSnapshotV9",
    "VABHFQRV9Result",
    "VIPBenchmarkCaseV9",
    "VIPReadinessAssessmentV9",
]

if __name__ == "__main__":
    raise SystemExit("advisory contracts only")
