"""Scoped reflection lessons for bounded research improvement."""

from __future__ import annotations

from dataclasses import replace

from webpent.models.evidence import redact_sensitive

from .contracts import ReflectionLesson, ResearchBrainState, stable_digest


def _clean(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(str(redact_sensitive(value)[0]) for value in values)


class ReflectionMemory:
    def __init__(self) -> None:
        self._lessons: dict[tuple[str, str, str], ReflectionLesson] = {}

    def record(
        self,
        *,
        target_ref: str,
        engagement_ref: str,
        worked: tuple[str, ...] = (),
        failed: tuple[str, ...] = (),
        wrong_assumptions: tuple[str, ...] = (),
        patterns: tuple[str, ...] = (),
        next_changes: tuple[str, ...] = (),
    ) -> ReflectionLesson:
        clean_worked = _clean(worked)
        clean_failed = _clean(failed)
        clean_wrong = _clean(wrong_assumptions)
        clean_patterns = _clean(patterns)
        clean_next = _clean(next_changes)
        key = (
            target_ref,
            engagement_ref,
            stable_digest(
                (clean_worked, clean_failed, clean_wrong, clean_patterns, clean_next)
            ),
        )
        lesson = ReflectionLesson(
            lesson_id=f"lesson-{stable_digest(key)[:16]}",
            target_ref=target_ref,
            engagement_ref=engagement_ref,
            worked=clean_worked,
            failed=clean_failed,
            wrong_assumptions=clean_wrong,
            patterns=clean_patterns,
            next_changes=clean_next,
        )
        self._lessons[key] = lesson
        return lesson

    def for_scope(self, *, target_ref: str, engagement_ref: str) -> tuple[ReflectionLesson, ...]:
        return tuple(
            sorted(
                (
                    lesson
                    for lesson in self._lessons.values()
                    if lesson.target_ref == target_ref and lesson.engagement_ref == engagement_ref
                ),
                key=lambda item: item.lesson_id,
            )
        )

    def apply_to_brain(self, brain: ResearchBrainState) -> ResearchBrainState:
        lessons = self.for_scope(target_ref=brain.target_ref, engagement_ref=brain.engagement_ref)
        history = tuple(
            sorted(set(brain.research_history).union(item.lesson_id for item in lessons))
        )
        return replace(brain, research_history=history)

    def snapshot(self) -> tuple[ReflectionLesson, ...]:
        return tuple(sorted(self._lessons.values(), key=lambda item: item.lesson_id))
