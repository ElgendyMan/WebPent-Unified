"""Passive business-logic workflow analysis facade."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from webpent.models.workflows import BusinessLogicHypothesisSpec, WorkflowObservation
from webpent.shared.workflow_understanding import (
    extract_workflow_observations,
    generate_business_logic_hypotheses,
)


class WorkflowAnalysis(BaseModel):
    """Target-scoped workflow projection; never a finding or an action plan."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target_id: str = Field(..., min_length=1, max_length=200)
    engagement_id: str = Field(..., min_length=1, max_length=200)
    observations: list[WorkflowObservation] = Field(default_factory=list, max_length=512)
    hypotheses: list[BusinessLogicHypothesisSpec] = Field(default_factory=list, max_length=512)
    coverage_gaps: list[str] = Field(default_factory=list, max_length=64)
    promotion_status: str = "candidate_only"


class WorkflowAnalyzer:
    """Adapter over the canonical workflow-understanding implementation."""

    def analyze(
        self,
        crawled_data: dict[str, Any] | None,
        *,
        target_url: str,
        target_id: str,
        engagement_id: str,
        scope_checker: Any = None,
    ) -> WorkflowAnalysis:
        if not target_id.strip() or not engagement_id.strip():
            raise ValueError("target_and_engagement_context_required")
        observations = extract_workflow_observations(
            crawled_data,
            target_url=target_url,
            scope_checker=scope_checker,
        )
        hypotheses = generate_business_logic_hypotheses(observations, target_url=target_url)
        gaps: set[str] = set()
        if not observations:
            gaps.add("workflow_observations_missing")
        if not any(item.evidence_refs for item in observations):
            gaps.add("workflow_evidence_refs_missing")
        if any(item.scope_decision == "unknown" for item in observations):
            gaps.add("workflow_scope_decision_unknown")
        return WorkflowAnalysis(
            target_id=target_id.strip()[:200],
            engagement_id=engagement_id.strip()[:200],
            observations=observations,
            hypotheses=hypotheses,
            coverage_gaps=sorted(gaps),
        )


__all__ = ["WorkflowAnalysis", "WorkflowAnalyzer"]
