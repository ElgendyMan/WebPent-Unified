"""ABHIE v6 typed contracts: deterministic, target-scoped, advisory-only."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class V6Status(StrEnum):
    READY = "ready"
    ADVISORY = "advisory"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"


class InvariantResult(StrEnum):
    SUPPORTED = "supported"
    DISPUTED = "disputed"
    UNASSESSED = "unassessed"
    BLOCKED = "blocked"


class OutcomeKind(StrEnum):
    SUCCESSFUL_DISCOVERY = "successful_discovery"
    REJECTED_HYPOTHESIS = "rejected_hypothesis"
    FALSE_LEAD = "false_lead"
    BLOCKED_CAPABILITY = "blocked_capability"
    INCOMPLETE_EVIDENCE = "incomplete_evidence"


@dataclass(frozen=True, slots=True)
class ResearchDecision:
    decision_id: str
    objective: str
    reasoning: str
    expected_value: float
    confidence: float
    cost: float
    risk: float
    validation_criteria: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    status: V6Status = V6Status.ADVISORY
    execution_requested: bool = False
    finding_created: bool = False

    def __post_init__(self) -> None:
        for name in ("expected_value", "confidence", "cost", "risk"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name}_out_of_range")
        if self.execution_requested or self.finding_created:
            raise ValueError("research_decision_cannot_execute_or_create_finding")

    def as_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "status": self.status.value,
            "execution_requested": False,
            "finding_created": False,
        }


@dataclass(frozen=True, slots=True)
class DiscoveryCandidate:
    candidate_id: str
    violated_assumption: str
    affected_assets: tuple[str, ...]
    reasoning_chain: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    validation_plan: tuple[str, ...]
    source_refs: tuple[str, ...] = ()
    confidence: float = 0.0
    status: V6Status = V6Status.ADVISORY
    confirmed: bool = False
    finding_created: bool = False

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("candidate_confidence_out_of_range")
        if self.confirmed or self.finding_created:
            raise ValueError("discovery_candidate_cannot_confirm_or_create_finding")


@dataclass(frozen=True, slots=True)
class InvariantReasoning:
    invariant_id: str
    statement: str
    result: InvariantResult
    source_evidence: tuple[str, ...]
    confidence: float
    affected_objects: tuple[str, ...]
    validation_strategy: tuple[str, ...]
    rationale: str
    causal_validation_required: bool = True

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("invariant_confidence_out_of_range")
        if not self.causal_validation_required:
            raise ValueError("invariant_requires_causal_validation")


@dataclass(frozen=True, slots=True)
class AttackChainHypothesis:
    chain_id: str
    explanation: str
    steps: tuple[str, ...]
    dependencies: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    validation_path: tuple[str, ...]
    impact_hypothesis: str
    confidence: float = 0.0
    status: V6Status = V6Status.ADVISORY
    causally_confirmed: bool = False
    finding_created: bool = False

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("chain_confidence_out_of_range")
        if not self.dependencies:
            raise ValueError("attack_chain_dependencies_required")
        if self.causally_confirmed or self.finding_created:
            raise ValueError("attack_chain_cannot_confirm_or_create_finding")


@dataclass(frozen=True, slots=True)
class CreativeDirection:
    direction_id: str
    question: str
    alternative_explanation: str
    related_area: str
    evidence_refs: tuple[str, ...]
    rank: int
    rationale: str
    status: V6Status = V6Status.ADVISORY


@dataclass(frozen=True, slots=True)
class DifferentialSignalV6:
    comparison_id: str
    dimension: str
    left_context: str
    right_context: str
    observed_difference: str
    security_question: str
    evidence_refs: tuple[str, ...]
    validation_requirement: str
    signal: bool = False
    promotion_eligible: bool = False

    def __post_init__(self) -> None:
        if self.promotion_eligible:
            raise ValueError("differential_signal_cannot_promote")


@dataclass(frozen=True, slots=True)
class ResearchLessonV4:
    lesson_id: str
    engagement_id: str
    target_id: str
    situation: str
    decision: str
    outcome: OutcomeKind
    future_recommendation: str
    evidence_refs: tuple[str, ...] = ()
    version: str = "abhie-memory-v4"
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if not self.advisory_only:
            raise ValueError("research_lesson_must_be_advisory")


@dataclass(frozen=True, slots=True)
class ResearchIntelligenceScorecard:
    engagement_id: str
    target_id: str
    discovery_depth: float | None = None
    reasoning_quality: float | None = None
    evidence_strength: float | None = None
    research_efficiency: float | None = None
    strategy_improvement: float | None = None
    coverage_growth: float | None = None
    learning_effectiveness: float | None = None
    benchmark_cases: int = 0
    valid_ground_truth: bool = False
    real_world_detection_rate: None = None
    qualification_approved: bool = False
    advisory_only: bool = True

    def __post_init__(self) -> None:
        for name in (
            "discovery_depth",
            "reasoning_quality",
            "evidence_strength",
            "research_efficiency",
            "strategy_improvement",
            "coverage_growth",
            "learning_effectiveness",
        ):
            value = getattr(self, name)
            if value is not None and not 0.0 <= value <= 1.0:
                raise ValueError(f"{name}_out_of_range")
        if self.qualification_approved or not self.advisory_only:
            raise ValueError("scorecard_cannot_approve_qualification")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ArchitectReviewReport:
    engagement_id: str
    target_id: str
    subject_id: str
    validity_challenges: tuple[str, ...]
    evidence_challenges: tuple[str, ...]
    impact_challenges: tuple[str, ...]
    alternative_challenges: tuple[str, ...]
    reproducibility_challenges: tuple[str, ...]
    central_pre_status: str
    central_post_status: str
    status: V6Status = V6Status.BLOCKED
    qualification_approved: bool = False
    oracle_overridden: bool = False
    policy_overridden: bool = False
    finding_created: bool = False
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if (
            any(
                (
                    self.qualification_approved,
                    self.oracle_overridden,
                    self.policy_overridden,
                    self.finding_created,
                )
            )
            or not self.advisory_only
        ):
            raise ValueError("architect_review_cannot_grant_authority")

    def digest(self) -> str:
        payload = asdict(self)
        payload["status"] = self.status.value
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class AgentResearchState:
    engagement_id: str
    target_id: str
    decisions: tuple[ResearchDecision, ...] = ()
    candidates: tuple[DiscoveryCandidate, ...] = ()
    invariant_reasoning: tuple[InvariantReasoning, ...] = ()
    chains: tuple[AttackChainHypothesis, ...] = ()
    creative_directions: tuple[CreativeDirection, ...] = ()
    differentials: tuple[DifferentialSignalV6, ...] = ()
    lessons: tuple[ResearchLessonV4, ...] = ()
    stop_reason: str = ""
    execution_attempted: bool = False
    finding_created: bool = False

    def __post_init__(self) -> None:
        if self.execution_attempted or self.finding_created:
            raise ValueError("agent_state_cannot_execute_or_create_finding")

    def digest(self) -> str:
        payload = asdict(self)
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode()
        ).hexdigest()
