"""VABH-FIL v8 contracts: expert research intelligence, advisory only.

The contracts deliberately stop at research reasoning. They cannot send requests,
mutate target state, create findings, override an oracle, or grant qualification.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class V8Status(StrEnum):
    READY = "ready"
    ADVISORY = "advisory"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    STOPPED = "stopped"


class StrategyMode(StrEnum):
    DEEP_INVESTIGATION = "deep_investigation"
    BROAD_EXPLORATION = "broad_exploration"
    EVIDENCE_COLLECTION = "evidence_collection"
    ALTERNATIVE_TESTING = "alternative_hypothesis_testing"
    STOP = "stopping"


class HypothesisDisposition(StrEnum):
    HYPOTHESIS = "hypothesis"
    RETAINED = "retained"
    REJECTED = "rejected"
    MERGED = "merged"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"


def _bounded(value: float, name: str) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name}_out_of_range")


def _clean(value: object, limit: int = 500) -> str:
    return " ".join(str(value or "").split())[:limit]


def _hash(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ExecutiveResearchDecisionV8:
    decision_id: str
    direction: str
    investigation_priority: str
    reasoning_chain: tuple[str, ...]
    confidence: float
    expected_value: float
    uncertainty: float
    cost: float
    risk: float
    evidence_requirements: tuple[str, ...]
    strategy_change: str
    stop_decision: str
    source_refs: tuple[str, ...] = ()
    status: V8Status = V8Status.ADVISORY
    execution_requested: bool = False
    finding_created: bool = False

    def __post_init__(self) -> None:
        for name in ("confidence", "expected_value", "uncertainty", "cost", "risk"):
            _bounded(getattr(self, name), name)
        if not self.reasoning_chain or not self.evidence_requirements:
            raise ValueError("executive_decision_requires_reasoning_and_evidence")
        if self.execution_requested or self.finding_created:
            raise ValueError("executive_decision_cannot_execute_or_create_finding")

    def as_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "status": self.status.value,
            "execution_requested": False,
            "finding_created": False,
        }


@dataclass(frozen=True, slots=True)
class ExpertSecurityInvestigationV8:
    investigation_id: str
    security_question: str
    assumption: str
    potential_weakness: str
    evidence_needed: tuple[str, ...]
    validation_approach: tuple[str, ...]
    attacker_capability: str
    trust_boundary: str
    business_impact: str
    confidence: float = 0.0
    source_refs: tuple[str, ...] = ()
    status: V8Status = V8Status.ADVISORY
    confirmation_claimed: bool = False

    def __post_init__(self) -> None:
        _bounded(self.confidence, "investigation_confidence")
        if not all(
            (
                self.security_question,
                self.assumption,
                self.potential_weakness,
                self.evidence_needed,
                self.validation_approach,
            )
        ):
            raise ValueError("investigation_chain_is_incomplete")
        if self.confirmation_claimed:
            raise ValueError("investigation_cannot_confirm")


@dataclass(frozen=True, slots=True)
class AdaptiveHuntingStrategyV8:
    strategy_id: str
    mode: StrategyMode
    rationale: str
    decision_factors: tuple[str, ...]
    selected_paths: tuple[str, ...]
    next_actions: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    adapted_from: tuple[str, ...] = ()
    status: V8Status = V8Status.ADVISORY
    execution_requested: bool = False

    def __post_init__(self) -> None:
        if not self.rationale or not self.stop_conditions:
            raise ValueError("strategy_requires_rationale_and_stop_conditions")
        if self.execution_requested:
            raise ValueError("strategy_cannot_execute")


@dataclass(frozen=True, slots=True)
class DynamicAttackGraphUpdateV8:
    graph_id: str
    added_nodes: tuple[str, ...]
    added_edges: tuple[tuple[str, str, str], ...]
    boundary_crossings: tuple[str, ...]
    unresolved_dependencies: tuple[str, ...]
    trust_relationships: tuple[str, ...]
    confidence: float
    evidence_refs: tuple[str, ...] = ()
    confirmation_claimed: bool = False
    finding_created: bool = False

    def __post_init__(self) -> None:
        _bounded(self.confidence, "graph_confidence")
        if self.confirmation_claimed or self.finding_created:
            raise ValueError("graph_update_cannot_confirm_or_create_finding")


@dataclass(frozen=True, slots=True)
class SecurityHypothesisV8:
    hypothesis_id: str
    statement: str
    supporting_evidence: tuple[str, ...]
    conflicting_evidence: tuple[str, ...]
    confidence_history: tuple[float, ...]
    next_validation_action: str
    disposition: HypothesisDisposition = HypothesisDisposition.HYPOTHESIS
    merged_into: str = ""
    source_refs: tuple[str, ...] = ()
    confirmation_claimed: bool = False
    finding_created: bool = False

    def __post_init__(self) -> None:
        if not self.statement or not self.next_validation_action:
            raise ValueError("hypothesis_statement_and_next_action_required")
        if not self.confidence_history:
            raise ValueError("hypothesis_confidence_history_required")
        for value in self.confidence_history:
            _bounded(value, "hypothesis_confidence")
        if self.confirmation_claimed or self.finding_created:
            raise ValueError("hypothesis_cannot_confirm_or_create_finding")

    @property
    def confidence(self) -> float:
        return self.confidence_history[-1]


@dataclass(frozen=True, slots=True)
class ResearchConfidenceReportV8:
    report_id: str
    subject_id: str
    intended_behavior_possible: bool
    attacker_capability_realistic: bool
    impact_proven: bool
    alternative_explanations: tuple[str, ...]
    reproducible_by_another_researcher: bool
    missing_evidence: tuple[str, ...]
    confidence: float
    disposition: HypothesisDisposition = HypothesisDisposition.INCONCLUSIVE
    oracle_overridden: bool = False
    confirmation_created: bool = False

    def __post_init__(self) -> None:
        _bounded(self.confidence, "confidence_report_confidence")
        if self.oracle_overridden or self.confirmation_created:
            raise ValueError("confidence_report_cannot_override_or_confirm")


@dataclass(frozen=True, slots=True)
class ResearchMemoryLessonV8:
    lesson_id: str
    target_id: str
    engagement_id: str
    pattern: str
    successful_approaches: tuple[str, ...]
    failed_approaches: tuple[str, ...]
    rejected_theories: tuple[str, ...]
    important_assumptions: tuple[str, ...]
    validation_lesson: str
    version: str
    update_reason: str
    source_refs: tuple[str, ...] = ()
    redacted: bool = True

    def __post_init__(self) -> None:
        if not self.redacted:
            raise ValueError("memory_lesson_must_be_redacted")
        if not self.target_id or not self.engagement_id or not self.version:
            raise ValueError("memory_scope_and_version_required")


@dataclass(frozen=True, slots=True)
class BenchmarkCaseV7:
    case_id: str
    scenario_class: str
    realistic_target_model: bool
    hidden_security_assumptions: tuple[str, ...]
    autonomous_investigation: bool
    multiple_research_paths: bool
    causal_oracle: bool
    proof_bundle: bool
    replay_verified: bool
    disposition: str
    blocked_reasons: tuple[str, ...] = ()
    requests_sent: int = 0

    def __post_init__(self) -> None:
        if self.requests_sent != 0:
            raise ValueError("v8_benchmark_must_send_zero_requests")
        if self.disposition == "scorable" and not all(
            (
                self.realistic_target_model,
                self.hidden_security_assumptions,
                self.autonomous_investigation,
                self.multiple_research_paths,
                self.causal_oracle,
                self.proof_bundle,
                self.replay_verified,
            )
        ):
            raise ValueError("scorable_case_requires_complete_v8_evidence")


@dataclass(frozen=True, slots=True)
class AutonomousResearchIntelligenceScoreV8:
    engagement_id: str
    target_id: str
    autonomy: float | None = None
    reasoning_depth: float | None = None
    evidence_quality: float | None = None
    investigation_efficiency: float | None = None
    adaptability: float | None = None
    learning_improvement: float | None = None
    benchmark_case_count: int = 0
    scorable_case_count: int = 0
    requests_sent: int = 0
    valid_ground_truth: bool = False
    advisory_only: bool = True
    real_world_detection_rate: None = None

    def __post_init__(self) -> None:
        for name in (
            "autonomy",
            "reasoning_depth",
            "evidence_quality",
            "investigation_efficiency",
            "adaptability",
            "learning_improvement",
        ):
            value = getattr(self, name)
            if value is not None:
                _bounded(value, name)
        if self.requests_sent != 0 or not self.advisory_only:
            raise ValueError("score_cannot_execute")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class VIPReadinessReportV8:
    engagement_id: str
    target_id: str
    architecture: str
    autonomy: str
    research_intelligence: str
    evidence_pipeline: str
    benchmark_quality: str
    remaining_limitations: tuple[str, ...]
    remaining_blockers: tuple[str, ...]
    governance_status: str
    status: V8Status = V8Status.BLOCKED
    vip_approved: bool = False
    p10_opened: bool = False
    qualification_gates_modified: bool = False
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if (
            self.vip_approved
            or self.p10_opened
            or self.qualification_gates_modified
            or not self.advisory_only
        ):
            raise ValueError("readiness_report_cannot_grant_authority")


@dataclass(frozen=True, slots=True)
class VABHFILV8Result:
    engagement_id: str
    target_id: str
    executive_decision: ExecutiveResearchDecisionV8
    investigations: tuple[ExpertSecurityInvestigationV8, ...]
    strategy: AdaptiveHuntingStrategyV8
    graph_update: DynamicAttackGraphUpdateV8
    hypotheses: tuple[SecurityHypothesisV8, ...]
    confidence_reports: tuple[ResearchConfidenceReportV8, ...]
    memory_lessons: tuple[ResearchMemoryLessonV8, ...]
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
            raise ValueError("v8_result_cannot_execute_or_approve")

    def digest(self) -> str:
        return _hash(
            {
                "engagement_id": self.engagement_id,
                "target_id": self.target_id,
                "executive_decision": self.executive_decision.as_dict(),
                "investigations": [asdict(item) for item in self.investigations],
                "strategy": asdict(self.strategy),
                "graph_update": asdict(self.graph_update),
                "hypotheses": [asdict(item) for item in self.hypotheses],
                "confidence_reports": [asdict(item) for item in self.confidence_reports],
                "memory_lessons": [asdict(item) for item in self.memory_lessons],
            }
        )


__all__ = [
    "AdaptiveHuntingStrategyV8",
    "AutonomousResearchIntelligenceScoreV8",
    "BenchmarkCaseV7",
    "DynamicAttackGraphUpdateV8",
    "ExecutiveResearchDecisionV8",
    "ExpertSecurityInvestigationV8",
    "HypothesisDisposition",
    "ResearchConfidenceReportV8",
    "ResearchMemoryLessonV8",
    "SecurityHypothesisV8",
    "StrategyMode",
    "V8Status",
    "VABHFILV8Result",
    "VIPReadinessReportV8",
]


if __name__ == "__main__":
    raise SystemExit("advisory contracts only")
