"""Autonomous Research Orchestrator v2: bounded mission planning only."""

from __future__ import annotations

from collections.abc import Sequence

from webpent.research_engine.orchestrator import ResearchOrchestrator
from webpent.research_engine.research_budget import BudgetUsage, ResearchBudget
from webpent.shared.research_intelligence import (
    ActionClass,
    InformationAction,
    SmartNextBestActionEngine,
)

from .contracts import MissionObjective, MissionStatus, ResearchMissionPlan, SecurityQuestion
from .target_graph import TargetIntelligenceGraphBuilder


class AutonomousResearchOrchestratorV2:
    """Select explainable research objectives without invoking execution."""

    def __init__(
        self,
        *,
        budget: ResearchBudget | None = None,
        max_objectives: int = 16,
    ) -> None:
        self.budget = budget or ResearchBudget()
        self.max_objectives = max(1, min(64, int(max_objectives)))
        self.base_orchestrator = ResearchOrchestrator(self.budget)
        self.ranker = SmartNextBestActionEngine()
        self.graph_builder = TargetIntelligenceGraphBuilder()

    def plan(
        self,
        *,
        graph,
        questions: Sequence[SecurityQuestion] = (),
        usage: BudgetUsage | None = None,
        has_target_backed_observation: bool = False,
        has_negative_control: bool = False,
        has_replayable_proof: bool = False,
        available_capabilities: Sequence[str] = (),
        attempted_action_ids: Sequence[str] = (),
        new_evidence: bool = False,
    ) -> ResearchMissionPlan:
        """Build a mission plan from explicit graph/questions and existing budget gates."""
        from .contracts import TargetIntelligenceGraph

        if not isinstance(graph, TargetIntelligenceGraph):
            raise TypeError("target_intelligence_graph_required")
        base = self.base_orchestrator.plan(
            engagement_id=graph.engagement_id,
            target_id=graph.target_id,
            usage=usage,
            has_target_backed_observation=has_target_backed_observation,
            has_negative_control=has_negative_control,
            has_replayable_proof=has_replayable_proof,
            has_application_model=bool(graph.nodes),
            planning_hints=graph.coverage_gaps,
        )
        actions = tuple(
            InformationAction(
                action_id=f"{question.question_id}:research",
                action_class=ActionClass.DISCOVERY,
                objective=question.question,
                target_ref=graph.target_id,
                expected_information_gain=question.priority,
                cost=1.0,
                scope_risk=0.0,
                capability="read_only_observation",
                justification=question.security_assumption,
            )
            for question in questions
        )
        ranked = self.ranker.rank(
            actions,
            attempted_fingerprints=attempted_action_ids,
            new_evidence=new_evidence,
        )
        rank_by_id = {item.action.action_id: item.score for item in ranked}
        capabilities = {str(item).strip() for item in available_capabilities if str(item).strip()}
        objectives: list[MissionObjective] = []
        for question in questions:
            action_id = f"{question.question_id}:research"
            blocked: list[str] = []
            if capabilities and "read_only_observation" not in capabilities:
                blocked.append("required_capability_unavailable")
            score = rank_by_id.get(action_id, question.priority)
            objectives.append(
                MissionObjective(
                    objective_id=question.question_id,
                    objective=question.question,
                    reasoning=question.security_assumption,
                    expected_value=question.priority,
                    required_capabilities=("read_only_observation",),
                    validation_criteria=question.expected_evidence,
                    stopping_conditions=(
                        "stop_when_causal_oracle_is_missing",
                        "stop_when_scope_or_budget_is_exhausted",
                    ),
                    priority=max(0.0, min(1.0, score)),
                    dependencies=question.source_refs,
                    blocked_reasons=tuple(blocked),
                )
            )
        objectives.sort(key=lambda item: (-item.priority, item.objective_id))
        objectives = objectives[: self.max_objectives]
        if not base.budget_decision.allowed:
            status = MissionStatus.STOPPED
            stop_reason = base.stop_reason or base.budget_decision.reason
        elif not objectives:
            status = MissionStatus.BLOCKED
            stop_reason = "no_explicit_research_question"
        else:
            status = MissionStatus.READY
            stop_reason = ""
        return ResearchMissionPlan(
            engagement_id=graph.engagement_id,
            target_id=graph.target_id,
            objectives=tuple(objectives),
            status=status,
            budget_reason=base.budget_decision.reason,
            stop_reason=stop_reason,
            source_refs=(graph.digest(),),
        )


AutonomousResearchOrchestrator = AutonomousResearchOrchestratorV2

__all__ = ["AutonomousResearchOrchestrator", "AutonomousResearchOrchestratorV2"]
