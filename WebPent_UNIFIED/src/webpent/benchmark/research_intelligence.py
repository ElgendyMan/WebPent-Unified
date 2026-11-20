"""Repeatable internal metrics for the autonomous research intelligence layer.

These metrics are intentionally lab-scoped.  They do not estimate real-world
detection rate and do not grant qualification or finding authority.
"""

from __future__ import annotations

from statistics import mean
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ValidationOutcome = Literal["confirmed", "inconclusive", "blocked", "not_run"]


class ResearchEvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    case_id: str = Field(min_length=1, max_length=160)
    target_id: str = Field(min_length=1, max_length=160)
    vulnerability_class: str = Field(default="unclassified", min_length=1, max_length=120)
    ground_truth_source: str | None = Field(default=None, max_length=240)
    hypothesis_generated: bool = False
    rank: int | None = Field(default=None, ge=1)
    expected_rank: int | None = Field(default=None, ge=1)
    information_gain: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_quality: float = Field(default=0.0, ge=0.0, le=1.0)
    validation_outcome: ValidationOutcome = "not_run"
    ground_truth_outcome: ValidationOutcome | None = None
    proof_complete: bool = False
    requests_used: int = Field(default=0, ge=0)
    candidate_paths_considered: int = Field(default=0, ge=0)
    unnecessary_paths_executed: int = Field(default=0, ge=0)


class ResearchIntelligenceReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: str = "research-intelligence-evaluation-v1"
    engagement_id: str = Field(min_length=1, max_length=160)
    target_ids: tuple[str, ...] = Field(default=(), max_length=64)
    case_count: int = Field(ge=0)
    research_efficiency: float = Field(ge=0.0, le=1.0)
    hypothesis_quality: float = Field(ge=0.0, le=1.0)
    evidence_quality: float = Field(ge=0.0, le=1.0)
    validation_accuracy: float | None = Field(default=None, ge=0.0, le=1.0)
    proof_completeness: float = Field(ge=0.0, le=1.0)
    unnecessary_exploration_reduction: float = Field(ge=0.0, le=1.0)
    vulnerability_classes: tuple[str, ...] = Field(default=(), max_length=64)
    requests_used: int = Field(ge=0)
    controlled_experiment: bool = True
    real_world_detection_rate_measured: bool = False
    qualification_effect: bool = False
    cases: tuple[ResearchEvaluationCase, ...] = Field(default=(), max_length=1000)


def evaluate_research_intelligence(
    *,
    engagement_id: str,
    cases: list[ResearchEvaluationCase] | tuple[ResearchEvaluationCase, ...],
) -> ResearchIntelligenceReport:
    """Compute deterministic lab metrics from already recorded case summaries."""
    ordered = tuple(sorted(cases, key=lambda case: (case.target_id, case.case_id)))
    ranked = [case for case in ordered if case.hypothesis_generated and case.rank is not None]
    rank_scores = [
        1.0 if case.expected_rank is None or case.rank == case.expected_rank else 0.0
        for case in ranked
    ]
    grounded = [
        case
        for case in ordered
        if case.ground_truth_outcome is not None and case.validation_outcome != "not_run"
    ]
    accuracy_scores = [
        1.0 if case.validation_outcome == case.ground_truth_outcome else 0.0 for case in grounded
    ]
    total_requests = sum(case.requests_used for case in ordered)
    considered_paths = sum(case.candidate_paths_considered for case in ordered)
    unnecessary_paths = sum(case.unnecessary_paths_executed for case in ordered)
    completed = [case for case in ordered if case.validation_outcome != "not_run"]
    efficiency = (
        mean(case.information_gain for case in completed)
        / (1.0 + total_requests / max(1, len(completed)))
        if completed
        else 0.0
    )
    return ResearchIntelligenceReport(
        engagement_id=engagement_id,
        target_ids=tuple(sorted({case.target_id for case in ordered})),
        case_count=len(ordered),
        research_efficiency=round(min(1.0, efficiency), 6),
        hypothesis_quality=round(mean(rank_scores), 6) if rank_scores else 0.0,
        evidence_quality=round(mean(case.evidence_quality for case in ordered), 6)
        if ordered
        else 0.0,
        validation_accuracy=round(mean(accuracy_scores), 6) if accuracy_scores else None,
        proof_completeness=round(mean(1.0 if case.proof_complete else 0.0 for case in ordered), 6)
        if ordered
        else 0.0,
        unnecessary_exploration_reduction=round(
            max(0.0, min(1.0, 1.0 - unnecessary_paths / considered_paths))
            if considered_paths
            else 0.0,
            6,
        ),
        vulnerability_classes=tuple(sorted({case.vulnerability_class for case in ordered})),
        requests_used=total_requests,
        cases=ordered,
    )


__all__ = [
    "ResearchEvaluationCase",
    "ResearchIntelligenceReport",
    "evaluate_research_intelligence",
]
