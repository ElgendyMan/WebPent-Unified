"""Scoped expert-memory accumulation; no filesystem, network, or credential storage."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .contracts import ResearchMemoryLessonV8
from .utils import stable_id, unique_sorted

_SECRET = re.compile(r"(?i)(token|cookie|password|secret|authorization)\s*[:=]\s*[^,; ]+")


def _redact(value: object) -> str:
    return _SECRET.sub(r"\1=[REDACTED]", " ".join(str(value or "").split()))[:500]


@dataclass(slots=True)
class AutonomousResearchMemoryIntelligenceV8:
    _lessons: list[ResearchMemoryLessonV8] = field(default_factory=list)

    def learn(
        self,
        *,
        engagement_id: str,
        target_id: str,
        pattern: str,
        successful_approaches: tuple[str, ...] = (),
        failed_approaches: tuple[str, ...] = (),
        rejected_theories: tuple[str, ...] = (),
        important_assumptions: tuple[str, ...] = (),
        validation_lesson: str = "",
        update_reason: str = "recorded research outcome",
        source_refs: tuple[str, ...] = (),
        version: str = "v8.0",
    ) -> ResearchMemoryLessonV8:
        lesson = ResearchMemoryLessonV8(
            lesson_id=stable_id("lesson", engagement_id, target_id, pattern, version),
            target_id=_redact(target_id),
            engagement_id=_redact(engagement_id),
            pattern=_redact(pattern),
            successful_approaches=unique_sorted(_redact(item) for item in successful_approaches),
            failed_approaches=unique_sorted(_redact(item) for item in failed_approaches),
            rejected_theories=unique_sorted(_redact(item) for item in rejected_theories),
            important_assumptions=unique_sorted(_redact(item) for item in important_assumptions),
            validation_lesson=_redact(validation_lesson),
            version=_redact(version),
            update_reason=_redact(update_reason),
            source_refs=unique_sorted(_redact(item) for item in source_refs),
            redacted=True,
        )
        self._lessons.append(lesson)
        return lesson

    def for_scope(
        self, *, engagement_id: str, target_id: str
    ) -> tuple[ResearchMemoryLessonV8, ...]:
        return tuple(
            item
            for item in self._lessons
            if item.engagement_id == _redact(engagement_id) and item.target_id == _redact(target_id)
        )

    def all_lessons(self) -> tuple[ResearchMemoryLessonV8, ...]:
        return tuple(self._lessons)


__all__ = ["AutonomousResearchMemoryIntelligenceV8"]
