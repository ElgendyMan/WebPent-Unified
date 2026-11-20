"""VABHIC v7 typed contracts: autonomous research intelligence, advisory only.

The v7 layer describes expert research decisions and evidence requirements. It
never sends requests, mutates state, creates findings, overrides an oracle, or
grants qualification authority.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class V7Status(StrEnum):
    READY = "ready"
    ADVISORY = "advisory"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    STOPPED = "stopped"


class Disposition(StrEnum):
    HYPOTHESIS = "hypothesis"
    ADVISORY = "advisory"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    REJECTED = "rejected"


class BenchmarkDisposition(StrEnum):
    BLOCKED = "blocked"
    SCORABLE = "scorable"
    INCONCLUSIVE = "inconclusive"


def _bounded(value: float, name: str) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name}_out_of_range")


def _clean(value: object, limit: int = 400) -> str:
    text = " ".join(str(value or "").split())
    return text[:limit]


def _hash(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ResearchCommand:
    command_id: str
    objective: str
    reasoning: str
    expected_value: float
    confidence: float
    cost: float
    risk: float
    success_criteria: tuple[str, ...]
    stop_criteria: tuple[str, ...]
    missing_evidence: tuple[str, ...] = ()
    pivot_if: tuple[str, ...] = ()
    source_refs: tuple[str, ...] = ()
    status: V7Status = V7Status.ADVISORY
    execution_requested: bool = False
    finding_created: bool = False

    def __post_init__(self) -> None:
        for name in ("expected_value", "confidence", "cost", "risk"):
            _bounded(getattr(self, name), name)
        if not self.success_criteria or not self.stop_criteria:
            raise ValueError("command_success_and_stop_criteria_required")
        if self.execution_requested or self.finding_created:
            raise ValueError("command_cannot_execute_or_create_finding")

    def as_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "status": self.status.value,
            "execution_requested": False,
            "finding_created": False,
        }


@dataclass(frozen=True, slots=True)
class ResearchCommandPlan:
    engagement_id: str
    target_id: str
    commands: tuple[ResearchCommand, ...] = ()
    status: V7Status = V7Status.ADVISORY
    stop_reason: str = ""
    budget_reason: str = ""
    source_refs: tuple[str, ...] = ()
    execution_attempted: bool = False
    qualification_approved: bool = False

    def __post_init__(self) -> None:
        if self.execution_attempted or self.qualification_approved:
            raise ValueError("command_plan_cannot_execute_or_approve")

    def digest(self) -> str:
        return _hash(
            {
                "engagement_id": self.engagement_id,
                "target_id": self.target_id,
                "commands": [c.as_dict() for c in self.commands],
                "status": self.status.value,
                "stop_reason": self.stop_reason,
                "budget_reason": self.budget_reason,
                "source_refs": self.source_refs,
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "target_id": self.target_id,
            "commands": [c.as_dict() for c in self.commands],
            "status": self.status.value,
            "stop_reason": _clean(self.stop_reason),
            "budget_reason": _clean(self.budget_reason),
            "source_refs": list(self.source_refs),
            "plan_digest": self.digest(),
            "execution_attempted": False,
            "qualification_approved": False,
        }


@dataclass(frozen=True, slots=True)
class SecurityMentalModel:
    model_id: str
    protected_assets: tuple[str, ...]
    business_logic: tuple[str, ...]
    user_journeys: tuple[str, ...]
    trust_relationships: tuple[str, ...]
    authorization_boundaries: tuple[str, ...]
    state_machines: tuple[str, ...]
    sensitive_workflows: tuple[str, ...]
    security_assumptions: tuple[str, ...]
    unresolved_questions: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    confidence: float = 0.0
    status: V7Status = V7Status.ADVISORY

    def __post_init__(self) -> None:
        _bounded(self.confidence, "mental_model_confidence")
        if not self.security_assumptions:
            raise ValueError("security_assumptions_required")

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "status": self.status.value}


@dataclass(frozen=True, slots=True)
class DiscoveryCandidateV2:
    candidate_id: str
    security_assumption: str
    observed_evidence: tuple[str, ...]
    reasoning_chain: tuple[str, ...]
    possible_impact: str
    validation_path: tuple[str, ...]
    source_refs: tuple[str, ...] = ()
    confidence: float = 0.0
    disposition: Disposition = Disposition.HYPOTHESIS
    causal_confirmation: bool = False
    finding_created: bool = False

    def __post_init__(self) -> None:
        _bounded(self.confidence, "candidate_confidence")
        if not self.security_assumption or not self.reasoning_chain or not self.validation_path:
            raise ValueError("candidate_reasoning_and_validation_required")
        if self.causal_confirmation or self.finding_created:
            raise ValueError("candidate_cannot_confirm_or_create_finding")

    def as_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "disposition": self.disposition.value,
            "causal_confirmation": False,
            "finding_created": False,
        }


@dataclass(frozen=True, slots=True)
class AttackNarrative:
    narrative_id: str
    attacker_goal: str
    required_conditions: tuple[str, ...]
    weakness_hypothesis: str
    possible_impact: str
    evidence_needed: tuple[str, ...]
    dependencies: tuple[str, ...]
    confidence: float = 0.0
    disposition: Disposition = Disposition.HYPOTHESIS
    causally_confirmed: bool = False
    finding_created: bool = False

    def __post_init__(self) -> None:
        _bounded(self.confidence, "narrative_confidence")
        if not self.required_conditions or not self.evidence_needed:
            raise ValueError("narrative_conditions_and_evidence_required")
        if self.causally_confirmed or self.finding_created:
            raise ValueError("narrative_cannot_confirm_or_create_finding")


@dataclass(frozen=True, slots=True)
class BudgetAllocation:
    allocation_id: str
    subject_id: str
    likelihood: float
    impact: float
    uncertainty: float
    evidence_value: float
    exploration_cost: float
    utility: float
    rationale: str
    duplicate_penalty: float = 0.0
    selected: bool = False

    def __post_init__(self) -> None:
        for name in (
            "likelihood",
            "impact",
            "uncertainty",
            "evidence_value",
            "exploration_cost",
            "utility",
            "duplicate_penalty",
        ):
            _bounded(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class SpecialistContribution:
    specialist_id: str
    specialty: str
    question: str
    reasoning: tuple[str, ...]
    evidence_refs: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    disposition: Disposition = Disposition.ADVISORY
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if not self.advisory_only:
            raise ValueError("specialist_contribution_must_be_advisory")


@dataclass(frozen=True, slots=True)
class CoordinationReport:
    coordination_id: str
    contributions: tuple[SpecialistContribution, ...]
    shared_questions: tuple[str, ...]
    resolved_conflicts: tuple[str, ...]
    unresolved_conflicts: tuple[str, ...]
    communication_evidence: tuple[str, ...]
    status: V7Status = V7Status.ADVISORY
    execution_attempted: bool = False

    def __post_init__(self) -> None:
        if self.execution_attempted:
            raise ValueError("coordination_cannot_execute")


@dataclass(frozen=True, slots=True)
class SkepticismAssessment:
    assessment_id: str
    subject_id: str
    intended_behavior_possible: bool
    alternative_explanations: tuple[str, ...]
    attacker_capability_realistic: bool
    impact_demonstrated: bool
    evidence_reproducible: bool
    challenges: tuple[str, ...]
    confidence: float
    disposition: Disposition = Disposition.ADVISORY
    oracle_overridden: bool = False
    finding_created: bool = False

    def __post_init__(self) -> None:
        _bounded(self.confidence, "skepticism_confidence")
        if self.oracle_overridden or self.finding_created:
            raise ValueError("skepticism_cannot_override_or_create")


@dataclass(frozen=True, slots=True)
class BenchmarkCaseV6:
    case_id: str
    scenario_class: str
    realistic_behavior: bool
    hidden_assumptions: tuple[str, ...]
    adaptive_strategy_required: bool
    causal_oracle_present: bool
    proof_bundle_present: bool
    replay_verified: bool
    disposition: BenchmarkDisposition
    blocked_reasons: tuple[str, ...] = ()
    requests_sent: int = 0

    def __post_init__(self) -> None:
        if self.requests_sent != 0:
            raise ValueError("v7_benchmark_must_send_zero_requests")
        if self.disposition == BenchmarkDisposition.SCORABLE and not all(
            (
                self.realistic_behavior,
                self.causal_oracle_present,
                self.proof_bundle_present,
                self.replay_verified,
            )
        ):
            raise ValueError("scorable_case_requires_complete_evidence")


@dataclass(frozen=True, slots=True)
class ResearchAnalytics:
    engagement_id: str
    target_id: str
    research_efficiency: float | None = None
    discovery_depth: float | None = None
    reasoning_quality: float | None = None
    evidence_quality: float | None = None
    strategy_adaptation: float | None = None
    learning_improvement: float | None = None
    benchmark_case_count: int = 0
    scorable_case_count: int = 0
    requests_sent: int = 0
    real_world_detection_rate: None = None
    valid_ground_truth: bool = False
    qualification_approved: bool = False
    advisory_only: bool = True

    def __post_init__(self) -> None:
        for name in (
            "research_efficiency",
            "discovery_depth",
            "reasoning_quality",
            "evidence_quality",
            "strategy_adaptation",
            "learning_improvement",
        ):
            value = getattr(self, name)
            if value is not None:
                _bounded(value, name)
        if self.requests_sent != 0 or self.qualification_approved or not self.advisory_only:
            raise ValueError("analytics_cannot_execute_or_approve")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class VIPReadinessAssessment:
    engagement_id: str
    target_id: str
    architecture_maturity: str
    research_autonomy: str
    detection_capability: str
    evidence_quality: str
    benchmark_performance: str
    remaining_limitations: tuple[str, ...]
    remaining_blockers: tuple[str, ...]
    governance_status: str
    status: V7Status = V7Status.BLOCKED
    vip_granted: bool = False
    p10_opened: bool = False
    policy_overridden: bool = False
    finding_created: bool = False
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if (
            self.vip_granted
            or self.p10_opened
            or self.policy_overridden
            or self.finding_created
            or not self.advisory_only
        ):
            raise ValueError("readiness_review_cannot_grant_authority")

    def as_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "status": self.status.value,
            "vip_granted": False,
            "p10_opened": False,
            "policy_overridden": False,
            "finding_created": False,
            "advisory_only": True,
        }


@dataclass(frozen=True, slots=True)
class VABHICV7Result:
    engagement_id: str
    target_id: str
    command_plan: ResearchCommandPlan
    mental_model: SecurityMentalModel
    candidates: tuple[DiscoveryCandidateV2, ...]
    narratives: tuple[AttackNarrative, ...]
    allocations: tuple[BudgetAllocation, ...]
    coordination: CoordinationReport
    skepticism: tuple[SkepticismAssessment, ...]
    requests_sent: int = 0
    mutations_performed: bool = False
    finding_created: bool = False
    qualification_approved: bool = False

    def __post_init__(self) -> None:
        if (
            self.requests_sent != 0
            or self.mutations_performed
            or self.finding_created
            or self.qualification_approved
        ):
            raise ValueError("vabhic_v7_result_cannot_execute_or_approve")


__all__ = [
    "AttackNarrative",
    "BenchmarkCaseV6",
    "BenchmarkDisposition",
    "BudgetAllocation",
    "CoordinationReport",
    "DiscoveryCandidateV2",
    "Disposition",
    "ResearchAnalytics",
    "ResearchCommand",
    "ResearchCommandPlan",
    "SecurityMentalModel",
    "SkepticismAssessment",
    "SpecialistContribution",
    "V7Status",
    "VABHICV7Result",
    "VIPReadinessAssessment",
]
