"""Target-scoped research learning v4."""

from __future__ import annotations

from collections.abc import Iterable

from webpent.abhip.memory import AutonomousResearchMemoryV3
from webpent.models.evidence import redact_sensitive

from .contracts import OutcomeKind, ResearchLessonV4


class ResearchLearningV4:
    """Store explainable lessons through the existing scoped memory boundary."""

    VERSION = "abhie-learning-v4"

    def __init__(self, *, engagement_id: str, target_id: str) -> None:
        self.engagement_id = str(engagement_id).strip()
        self.target_id = str(target_id).strip()
        if not self.engagement_id or not self.target_id:
            raise ValueError("engagement_and_target_scope_required")
        self.memory = AutonomousResearchMemoryV3(
            engagement_id=self.engagement_id,
            target_id=self.target_id,
        )

    @staticmethod
    def _memory_outcome(outcome: OutcomeKind) -> str:
        mapping = {
            OutcomeKind.SUCCESSFUL_DISCOVERY: "supported",
            OutcomeKind.REJECTED_HYPOTHESIS: "rejected",
            OutcomeKind.FALSE_LEAD: "rejected",
            OutcomeKind.BLOCKED_CAPABILITY: "blocked",
            OutcomeKind.INCOMPLETE_EVIDENCE: "inconclusive",
        }
        return mapping[OutcomeKind(outcome)]

    def learn(
        self,
        *,
        lesson_id: str,
        situation: str,
        decision: str,
        outcome: OutcomeKind,
        future_recommendation: str,
        evidence_refs: Iterable[str] = (),
    ) -> ResearchLessonV4 | None:
        clean_situation, _ = redact_sensitive(str(situation))
        clean_decision, _ = redact_sensitive(str(decision))
        clean_recommendation, _ = redact_sensitive(str(future_recommendation))
        refs_value, _ = redact_sensitive(
            tuple(str(item).strip() for item in evidence_refs if str(item).strip())
        )
        refs = tuple(str(item) for item in refs_value)
        lesson = ResearchLessonV4(
            lesson_id=str(lesson_id).strip(),
            engagement_id=self.engagement_id,
            target_id=self.target_id,
            situation=str(clean_situation).strip(),
            decision=str(clean_decision).strip(),
            outcome=OutcomeKind(outcome),
            future_recommendation=str(clean_recommendation).strip(),
            evidence_refs=refs,
        )
        return (
            lesson
            if self.memory.learn_from_outcome(
                lesson_id=lesson.lesson_id,
                category=lesson.outcome.value,
                summary=f"{lesson.situation}; decision={lesson.decision}",
                outcome=self._memory_outcome(lesson.outcome),
                evidence_refs=lesson.evidence_refs,
                rationale=lesson.future_recommendation,
                relevance=0.5,
            )
            is not None
            else None
        )

    def summary(self) -> dict[str, object]:
        return {
            **self.memory.summary(),
            "learning_version": self.VERSION,
            "lesson_categories": [item.value for item in OutcomeKind],
            "authoritative": False,
            "execution_capability": False,
        }


__all__ = ["ResearchLearningV4"]
