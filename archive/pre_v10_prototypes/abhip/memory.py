"""Scoped research memory v3 delegating to the existing memory boundary."""

from __future__ import annotations

from collections.abc import Iterable

from webpent.shared.security_reasoning_memory import SecurityReasoningMemory

from .contracts import ResearchLesson


class AutonomousResearchMemoryV3:
    """Versioned, target/engagement-isolated memory projection."""

    VERSION = "abhip-memory-v3"

    def __init__(self, *, engagement_id: str, target_id: str) -> None:
        self.engagement_id = str(engagement_id).strip()
        self.target_id = str(target_id).strip()
        if not self.engagement_id or not self.target_id:
            raise ValueError("engagement_and_target_scope_required")
        self._memory = SecurityReasoningMemory(
            engagement_id=self.engagement_id,
            target_id=self.target_id,
        )

    @property
    def scope(self) -> str:
        return self._memory.scope

    @property
    def records(self):
        return self._memory.records

    def remember(
        self,
        *,
        lesson_id: str,
        category: str,
        summary: str,
        evidence_refs: Iterable[str] = (),
        rationale: str = "",
        relevance: float = 0.0,
    ) -> ResearchLesson | None:
        lesson = ResearchLesson(
            lesson_id=str(lesson_id).strip(),
            engagement_id=self.engagement_id,
            target_id=self.target_id,
            category=str(category).strip(),
            summary=str(summary).strip(),
            evidence_refs=tuple(str(item).strip() for item in evidence_refs if str(item).strip()),
            rationale=str(rationale).strip(),
            version=self.VERSION,
        )
        record = self._memory.remember_research(
            category=("successful_path" if category == "successful_path" else "reasoning_chain"),
            content=f"{lesson.category}: {lesson.summary}; rationale={lesson.rationale}",
            source_ref=f"lesson:{lesson.lesson_id}",
            evidence_refs=lesson.evidence_refs,
            relevance=relevance,
            metadata={"lesson_id": lesson.lesson_id, "memory_version": self.VERSION},
        )
        return lesson if record is not None else None

    def learn_from_outcome(
        self,
        *,
        lesson_id: str,
        category: str,
        summary: str,
        outcome: str,
        evidence_refs: Iterable[str] = (),
        rationale: str = "",
        relevance: float = 0.0,
    ) -> ResearchLesson | None:
        lesson = self.remember(
            lesson_id=lesson_id,
            category=category,
            summary=summary,
            evidence_refs=evidence_refs,
            rationale=f"outcome={outcome}; {rationale}",
            relevance=relevance,
        )
        if lesson is not None:
            self._memory.learn_from_outcome(
                hypothesis_id=lesson.lesson_id,
                outcome=outcome,
                rationale=rationale,
                evidence_refs=lesson.evidence_refs,
                relevance=relevance,
            )
        return lesson

    def retrieve(self, query: str = "", *, limit: int | None = None):
        return self._memory.retrieve_learning(query, limit=limit)

    def summary(self, query: str = "", *, limit: int | None = None) -> dict[str, object]:
        return {
            **self._memory.researcher_summary(query, limit=limit),
            "memory_version": self.VERSION,
            "target_isolated": True,
            "engagement_isolated": True,
            "authoritative": False,
            "execution_capability": False,
        }


ResearchMemoryV3 = AutonomousResearchMemoryV3

__all__ = ["AutonomousResearchMemoryV3", "ResearchMemoryV3"]
