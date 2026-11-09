"""Engagement-scoped experience memory contracts.

This store is intentionally in-process and bounded. Persistence adapters may
serialize its records later, but retrieval remains advisory and never grants
execution or finding authority.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from webpent.models.memory import MemoryBudget, MemoryKind, MemoryRecord
from webpent.shared.memory_boundary import MemoryBoundary


class ExperienceMemory:
    """Separate failure and success lessons behind the existing memory boundary."""

    def __init__(
        self,
        *,
        engagement_id: str,
        client_id: str | None = None,
        budget: MemoryBudget | None = None,
    ) -> None:
        clean_engagement = str(engagement_id or "").strip()
        if not clean_engagement:
            raise ValueError("engagement_id is required")
        self.engagement_id = clean_engagement
        self.client_id = str(client_id).strip() if client_id else None
        self._boundary = MemoryBoundary(engagement_scope=clean_engagement, budget=budget)
        self._categories: dict[str, str] = {}

    @property
    def records(self) -> tuple[MemoryRecord, ...]:
        return self._boundary.records

    def add_success(
        self,
        *,
        content: str,
        evidence_refs: Iterable[str] = (),
        source_ref: str = "operator-review",
    ) -> MemoryRecord | None:
        return self._add_lesson(
            category="success",
            content=content,
            evidence_refs=evidence_refs,
            source_ref=source_ref,
        )

    def add_failure(
        self,
        *,
        content: str,
        evidence_refs: Iterable[str] = (),
        source_ref: str = "operator-review",
    ) -> MemoryRecord | None:
        return self._add_lesson(
            category="failure",
            content=content,
            evidence_refs=evidence_refs,
            source_ref=source_ref,
        )

    def _add_lesson(
        self,
        *,
        category: str,
        content: str,
        evidence_refs: Iterable[str],
        source_ref: str,
    ) -> MemoryRecord | None:
        clean = str(content or "").strip()
        if not clean:
            return None
        record = self._boundary.add_experience_lesson(
            content=clean,
            source_ref=source_ref,
            target_scope=self.engagement_id,
            relevance=1.0 if category == "success" else 0.5,
        )
        if record is not None:
            record.metadata.update(
                {
                    "experience_category": category,
                    "client_id": self.client_id,
                    "evidence_refs": list(dict.fromkeys(str(ref) for ref in evidence_refs if ref)),
                }
            )
            self._categories[record.id] = category
        return record

    def list_category(self, category: str) -> tuple[MemoryRecord, ...]:
        return tuple(
            record
            for record in self.records
            if self._categories.get(record.id) == category
        )

    def success_patterns(self) -> tuple[MemoryRecord, ...]:
        return self.list_category("success")

    def failure_memory(self) -> tuple[MemoryRecord, ...]:
        return self.list_category("failure")

    def retrieve(self, query: str, *, category: str | None = None) -> list[MemoryRecord]:
        kinds = [MemoryKind.EXPERIENCE_LESSON]
        result = self._boundary.retrieve(query, kinds=kinds)
        if category is None:
            return result.items
        return [item for item in result.items if self._categories.get(item.id) == category]

    def export(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "client_id": self.client_id,
            "records": [record.model_dump(mode="json") for record in self.records],
            "categories": dict(self._categories),
            "authoritative": False,
        }


__all__ = ["ExperienceMemory"]
