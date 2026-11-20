"""AVRIP v2 scoped research memory facade."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from webpent.shared.security_reasoning_memory import SecurityReasoningMemory


class MemoryLessonV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    lesson_id: str = Field(min_length=1, max_length=240)
    category: str = Field(min_length=1, max_length=80)
    summary: str = Field(min_length=3, max_length=700)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    outcome: str = Field(min_length=1, max_length=80)
    advisory_only: bool = True


class ResearchMemorySnapshotV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: int = Field(default=2, frozen=True)
    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    summary: dict[str, object]
    isolated: bool = True
    authoritative: bool = False
    execution_capability: bool = False


class AutonomousResearchMemoryV2:
    """No independent store: all writes delegate to the existing memory boundary."""

    def __init__(self, *, engagement_id: str, target_id: str) -> None:
        self._memory = SecurityReasoningMemory(
            engagement_id=engagement_id,
            target_id=target_id,
        )

    @property
    def engagement_id(self) -> str:
        return self._memory.engagement_id

    @property
    def target_id(self) -> str:
        return self._memory.target_id

    @property
    def scope(self) -> str:
        return self._memory.scope

    def remember_lesson(
        self,
        *,
        category: str,
        summary: str,
        outcome: str,
        evidence_refs: Iterable[str] = (),
        relevance: float = 0.0,
    ) -> MemoryLessonV2 | None:
        record = self._memory.remember_research(
            category=category,
            content=summary,
            source_ref=f"avrip:{category}",
            evidence_refs=evidence_refs,
            relevance=relevance,
            metadata={"avrip_version": 2},
        )
        if record is None:
            return None
        return MemoryLessonV2(
            lesson_id=record.id,
            category=category,
            summary=record.content,
            evidence_refs=tuple(record.provenance.evidence_refs),
            outcome=outcome,
        )

    def learn_outcome(
        self,
        *,
        hypothesis_id: str,
        outcome: str,
        rationale: str,
        evidence_refs: Iterable[str] = (),
    ) -> MemoryLessonV2 | None:
        record = self._memory.learn_from_outcome(
            hypothesis_id=hypothesis_id,
            outcome=outcome,
            rationale=rationale,
            evidence_refs=evidence_refs,
        )
        if record is None:
            return None
        return MemoryLessonV2(
            lesson_id=record.id,
            category="experience_lesson",
            summary=record.content,
            evidence_refs=tuple(record.provenance.evidence_refs),
            outcome=outcome,
        )

    def retrieve(self, query: str = "", *, limit: int | None = None) -> tuple[MemoryLessonV2, ...]:
        summary = self._memory.researcher_summary(query, limit=limit)
        lessons: list[MemoryLessonV2] = []
        for category, values in summary["items"].items():
            for item in values:
                lessons.append(
                    MemoryLessonV2(
                        lesson_id=str(item["id"]),
                        category=str(category),
                        summary=str(item["content"]),
                        evidence_refs=tuple(str(ref) for ref in item["evidence_refs"]),
                        outcome="recorded",
                    )
                )
        return tuple(lessons)

    def snapshot(self) -> ResearchMemorySnapshotV2:
        summary = self._memory.summary()
        return ResearchMemorySnapshotV2(
            engagement_id=self.engagement_id,
            target_id=self.target_id,
            summary=summary,
        )


__all__ = [
    "AutonomousResearchMemoryV2",
    "MemoryLessonV2",
    "ResearchMemorySnapshotV2",
]
