"""Bounded orchestration for autonomous research planning.

This layer produces an auditable plan only. Action execution remains owned by
ActionAuthority, ActionExecutor, the existing validators, and the central
ProofBundle gate.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from webpent.research_engine.knowledge_gap import KnowledgeGap, KnowledgeGapEngine
from webpent.research_engine.priority_engine import PrioritySignals, priority_score
from webpent.research_engine.projection_adapter import ProjectionPlanningInput
from webpent.research_engine.research_budget import (
    BudgetDecision,
    BudgetUsage,
    ResearchBudget,
    evaluate_budget,
)
from webpent.research_engine.research_state import ResearchState, ResearchTask


class ResearchPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    engagement_id: str = Field(min_length=1, max_length=160)
    target_id: str = Field(min_length=1, max_length=160)
    budget_decision: BudgetDecision
    gaps: tuple[KnowledgeGap, ...] = Field(default=(), max_length=64)
    tasks: tuple[ResearchTask, ...] = Field(default=(), max_length=64)
    stop_reason: str = Field(default="", max_length=240)
    projection_hints: tuple[str, ...] = Field(default=(), max_length=64)


class ResearchOrchestrator:
    """Build a target-scoped plan without invoking tools or external services."""

    def __init__(self, budget: ResearchBudget | None = None) -> None:
        self.budget = budget or ResearchBudget()

    def plan(
        self,
        *,
        engagement_id: str,
        target_id: str,
        usage: BudgetUsage | None = None,
        has_target_backed_observation: bool = False,
        has_negative_control: bool = False,
        has_replayable_proof: bool = False,
        has_application_model: bool = False,
        planning_hints: tuple[str, ...] = (),
    ) -> ResearchPlan:
        current_usage = usage or BudgetUsage()
        normalized_hints = tuple(
            dict.fromkeys(str(item).strip()[:240] for item in planning_hints if str(item).strip())
        )[:64]
        decision = evaluate_budget(self.budget, current_usage)
        gaps = KnowledgeGapEngine.identify(
            engagement_id=engagement_id,
            target_id=target_id,
            has_target_backed_observation=has_target_backed_observation,
            has_negative_control=has_negative_control,
            has_replayable_proof=has_replayable_proof,
            has_application_model=has_application_model,
        )
        if not decision.allowed:
            return ResearchPlan(
                engagement_id=engagement_id,
                target_id=target_id,
                budget_decision=decision,
                gaps=gaps,
                stop_reason=decision.reason,
                projection_hints=normalized_hints,
            )
        gap_tasks = [
            ResearchTask(
                task_id=f"{gap.gap_id}:research",
                engagement_id=engagement_id,
                target_id=target_id,
                objective=gap.description,
                reason="knowledge_gap",
                priority=priority_score(
                    PrioritySignals(
                        impact=gap.severity,
                        exploitability=0.5,
                        novelty=0.5,
                        knowledge_gap=1.0,
                        estimated_cost=0.5,
                    )
                ),
                required_evidence=gap.required_evidence,
                operation="plan",
            )
            for gap in gaps
        ]
        projection_tasks = [
            ResearchTask(
                task_id=f"projection:{index}:research",
                engagement_id=engagement_id,
                target_id=target_id,
                objective=hint,
                reason="projection_gap",
                priority=priority_score(
                    PrioritySignals(
                        impact=0.6,
                        exploitability=0.4,
                        novelty=0.6,
                        knowledge_gap=0.9,
                        estimated_cost=0.3,
                    )
                ),
                required_evidence=("projection_observation",),
                operation="plan",
            )
            for index, hint in enumerate(normalized_hints, start=1)
        ]
        tasks = tuple(gap_tasks + projection_tasks)
        state = ResearchState(
            engagement_id=engagement_id,
            target_id=target_id,
            budget=self.budget,
            usage=current_usage,
        )
        admitted: list[ResearchTask] = []
        for task in tasks:
            state = state.admit_task(task)
            if any(existing.task_id == task.task_id for existing in state.tasks):
                admitted.append(task)
        return ResearchPlan(
            engagement_id=engagement_id,
            target_id=target_id,
            budget_decision=decision,
            gaps=gaps,
            tasks=tuple(admitted),
            stop_reason=state.stop_reason,
            projection_hints=normalized_hints,
        )

    def plan_from_projections(self, projections: ProjectionPlanningInput) -> ResearchPlan:
        """Plan from advisory projections; never invokes graph execution."""
        if not isinstance(projections, ProjectionPlanningInput):
            raise TypeError("projection_planning_input_required")
        return self.plan(
            engagement_id=projections.engagement_id,
            target_id=projections.target_id,
            has_target_backed_observation=projections.has_target_backed_observation,
            has_negative_control=projections.has_negative_control,
            has_replayable_proof=projections.has_replayable_proof,
            has_application_model=projections.has_application_model,
            planning_hints=projections.planning_hints,
        )


__all__ = ["ProjectionPlanningInput", "ResearchOrchestrator", "ResearchPlan"]
