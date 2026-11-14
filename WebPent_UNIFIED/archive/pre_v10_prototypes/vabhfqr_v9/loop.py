"""Closed-loop autonomous research lifecycle with no transport authority."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import LoopStage, VABHFQRV9Result
from .core import VABHFQRV9Core


@dataclass(frozen=True, slots=True)
class ResearchStateV9:
    engagement_id: str
    target_id: str
    cycle: int = 0
    completed_stages: tuple[str, ...] = ()
    failures: tuple[str, ...] = ()

    def snapshot(self) -> dict[str, object]:
        return {
            "engagement_id": self.engagement_id,
            "target_id": self.target_id,
            "cycle": self.cycle,
            "completed_stages": self.completed_stages,
            "failures": self.failures,
        }

    @classmethod
    def restore(cls, snapshot: dict[str, object]) -> ResearchStateV9:
        return cls(
            engagement_id=str(snapshot["engagement_id"]),
            target_id=str(snapshot["target_id"]),
            cycle=int(snapshot.get("cycle", 0)),
            completed_stages=tuple(str(item) for item in snapshot.get("completed_stages", ())),
            failures=tuple(str(item) for item in snapshot.get("failures", ())),
        )


@dataclass(frozen=True, slots=True)
class AutonomousResearchLoopV9:
    core: VABHFQRV9Core = VABHFQRV9Core()

    def run(
        self,
        *,
        engagement_id: str,
        target_id: str,
        recorded_state: object | None = None,
        evidence_refs: tuple[str, ...] = (),
        previous_failures: tuple[str, ...] = (),
    ) -> tuple[VABHFQRV9Result, ResearchStateV9]:
        result = self.core.run(
            engagement_id=engagement_id,
            target_id=target_id,
            recorded_state=recorded_state,
            evidence_refs=evidence_refs,
            previous_failures=previous_failures,
        )
        completed = tuple(step.stage.value for step in result.loop_steps if step.completed)
        state = ResearchStateV9(
            engagement_id=engagement_id,
            target_id=target_id,
            cycle=1,
            completed_stages=completed,
            failures=previous_failures,
        )
        return result, state

    @staticmethod
    def recover(state: ResearchStateV9, failure: str) -> ResearchStateV9:
        return ResearchStateV9(
            engagement_id=state.engagement_id,
            target_id=state.target_id,
            cycle=state.cycle,
            completed_stages=state.completed_stages,
            failures=state.failures + (str(failure),),
        )

    @staticmethod
    def closed_loop_stages() -> tuple[LoopStage, ...]:
        return tuple(LoopStage)


__all__ = ["AutonomousResearchLoopV9", "ResearchStateV9"]
