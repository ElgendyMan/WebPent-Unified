"""Bounded autonomous research loop v3 for recorded inputs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .contracts import (
    LoopEvent,
    LoopPhase,
    ResearchLoopCheckpoint,
    ResearchMissionPlan,
    SecurityQuestion,
    TargetIntelligenceGraph,
)
from .orchestrator import AutonomousResearchOrchestratorV2
from .questions import SecurityQuestionGenerator


@dataclass(frozen=True, slots=True)
class ResearchLoopResult:
    checkpoint: ResearchLoopCheckpoint
    selected_objective_ids: tuple[str, ...] = ()
    recovered_paths: tuple[str, ...] = ()
    repeated_paths_skipped: tuple[str, ...] = ()
    evidence_status: str = "observation_only"
    execution_attempted: bool = False
    findings_created: bool = False
    promotion_eligible: bool = False

    def __post_init__(self) -> None:
        if self.execution_attempted or self.findings_created or self.promotion_eligible:
            raise ValueError("research_loop_cannot_execute_or_promote")


class AutonomousResearchLoopV3:
    """Run deterministic planning/reasoning steps over supplied records only."""

    def __init__(
        self,
        *,
        orchestrator: AutonomousResearchOrchestratorV2 | None = None,
        question_generator: SecurityQuestionGenerator | None = None,
        max_cycles: int = 8,
    ) -> None:
        self.orchestrator = orchestrator or AutonomousResearchOrchestratorV2()
        self.question_generator = question_generator or SecurityQuestionGenerator()
        self.max_cycles = max(1, min(32, int(max_cycles)))

    @staticmethod
    def _event(
        sequence: int,
        phase: LoopPhase,
        summary: str,
        *,
        input_refs: Sequence[str] = (),
        output_refs: Sequence[str] = (),
        status: str = "advisory",
    ) -> LoopEvent:
        return LoopEvent(
            sequence=sequence,
            phase=phase,
            summary=str(summary)[:320],
            input_refs=tuple(str(item)[:240] for item in input_refs)[:24],
            output_refs=tuple(str(item)[:240] for item in output_refs)[:24],
            status=str(status)[:80],
        )

    def run(
        self,
        *,
        graph: TargetIntelligenceGraph,
        questions: Sequence[SecurityQuestion] = (),
        mission: ResearchMissionPlan | None = None,
        recorded_observations: Sequence[Mapping[str, object]] = (),
        attempted_action_ids: Sequence[str] = (),
        failed_paths: Sequence[str] = (),
        evidence_status: str = "observation_only",
        max_cycles: int | None = None,
    ) -> ResearchLoopResult:
        """Advance a bounded checkpoint; no callback, request, or mutation is accepted."""
        if not isinstance(graph, TargetIntelligenceGraph):
            raise TypeError("target_intelligence_graph_required")
        if mission is not None and not isinstance(mission, ResearchMissionPlan):
            raise TypeError("research_mission_plan_required")
        cycles = max(1, min(self.max_cycles, int(max_cycles or self.max_cycles)))
        generated = tuple(questions) or self.question_generator.generate(graph)
        selected = tuple(
            item.objective_id
            for item in (mission.objectives if mission else ())
            if item.eligible
        )
        if not selected:
            selected = tuple(item.question_id for item in generated[:cycles])
        attempted = tuple(dict.fromkeys(str(item) for item in attempted_action_ids if str(item)))
        selected_new = tuple(
            item for item in selected if item not in attempted and len(selected) <= cycles
        )
        repeated = tuple(item for item in selected if item in attempted)
        failed = tuple(dict.fromkeys(str(item)[:240] for item in failed_paths if str(item)))
        recovered = tuple(item for item in failed if item not in attempted)
        observations = tuple(recorded_observations)
        status = str(evidence_status or "observation_only").strip().lower()
        graph_ref = graph.digest()
        events = (
            self._event(
                1,
                LoopPhase.OBSERVE,
                "consume recorded observations only",
                output_refs=(graph_ref,),
            ),
            self._event(
                2,
                LoopPhase.UNDERSTAND,
                "project target knowledge into intelligence graph",
                input_refs=(graph_ref,),
            ),
            self._event(
                3,
                LoopPhase.QUESTION,
                "generate explicit security questions",
                output_refs=selected_new,
            ),
            self._event(
                4,
                LoopPhase.HYPOTHESIS,
                "retain competing explanations until evidence resolves them",
                input_refs=selected_new,
            ),
            self._event(
                5,
                LoopPhase.EXPERIMENT,
                "execution boundary closed; no experiment invoked",
                status="blocked",
            ),
            self._event(
                6,
                LoopPhase.EVIDENCE,
                f"recorded evidence state: {status}",
                input_refs=(str(len(observations)),),
            ),
            self._event(
                7,
                LoopPhase.EVALUATE,
                "evaluate only advisory completeness and missing controls",
            ),
            self._event(
                8,
                LoopPhase.LEARN,
                "retain scoped lessons without promoting findings",
            ),
        )
        stop_reason = (
            "execution_boundary_closed"
            if not observations
            else "central_oracle_required_before_confirmation"
        )
        checkpoint = ResearchLoopCheckpoint(
            engagement_id=graph.engagement_id,
            target_id=graph.target_id,
            events=events,
            attempted_action_ids=attempted,
            failed_paths=failed,
            stop_reason=stop_reason,
            cycle_count=min(cycles, len(events)),
        )
        return ResearchLoopResult(
            checkpoint=checkpoint,
            selected_objective_ids=selected_new,
            recovered_paths=recovered,
            repeated_paths_skipped=repeated,
            evidence_status=status,
        )


ResearchLoopV3 = AutonomousResearchLoopV3

__all__ = ["AutonomousResearchLoopV3", "ResearchLoopResult", "ResearchLoopV3"]
