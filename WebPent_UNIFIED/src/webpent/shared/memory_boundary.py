from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any
from uuid import uuid4

from webpent.models.evidence import redact_sensitive
from webpent.models.memory import (
    FeedbackStatus,
    MemoryBudget,
    MemoryFeedback,
    MemoryKind,
    MemoryRecord,
    MemoryRetrieval,
)


class MemoryBoundary:
    """Small deterministic boundary for three non-interchangeable memories.

    The boundary is intentionally not a Finding store and exposes no request
    execution capability. Retrieval is advisory only; callers must validate
    every hypothesis with target evidence before promoting it.
    """

    def __init__(
        self,
        *,
        engagement_scope: str | None = None,
        budget: MemoryBudget | None = None,
        retriever: Callable[[str, int, MemoryKind], Iterable[Any]] | None = None,
    ) -> None:
        self.engagement_scope = engagement_scope
        self.budget = budget or MemoryBudget()
        self._records: dict[str, MemoryRecord] = {}
        self._feedback: list[MemoryFeedback] = []
        self._retrievals = 0
        self._retriever = retriever

    @property
    def records(self) -> tuple[MemoryRecord, ...]:
        return tuple(self._records.values())

    @property
    def feedback(self) -> tuple[MemoryFeedback, ...]:
        return tuple(self._feedback)

    def add(self, record: MemoryRecord) -> bool:
        """Add a record only when its trust boundary is valid."""
        if len(self._records) >= self.budget.max_records and record.id not in self._records:
            return False
        if record.kind is MemoryKind.TARGET_FACT:
            if not self.engagement_scope or record.target_scope != self.engagement_scope:
                return False
        elif record.target_scope is not None and record.target_scope != self.engagement_scope:
            # Do not allow lessons or facts from another engagement to bleed in.
            return False
        if len(record.content) > self.budget.max_content_chars:
            record = record.model_copy(
                update={"content": record.content[: self.budget.max_content_chars]}
            )
        self._records[record.id] = record
        return True

    def add_target_fact(
        self,
        *,
        content: str,
        source_ref: str = "",
        evidence_refs: list[str] | None = None,
        relevance: float = 1.0,
    ) -> MemoryRecord | None:
        if not self.engagement_scope:
            return None
        record = MemoryRecord(
            id=f"target-fact-{uuid4().hex[:16]}",
            kind=MemoryKind.TARGET_FACT,
            content=content,
            target_scope=self.engagement_scope,
            provenance={
                "source": "observation",
                "source_ref": source_ref,
                "relevance": relevance,
                "evidence_refs": evidence_refs or [],
            },
        )
        return record if self.add(record) else None

    def add_security_knowledge(
        self, *, content: str, source: str, source_ref: str = "", relevance: float = 0.0
    ) -> MemoryRecord | None:
        record = MemoryRecord(
            id=f"knowledge-{uuid4().hex[:16]}",
            kind=MemoryKind.SECURITY_KNOWLEDGE,
            content=content,
            provenance={"source": source, "source_ref": source_ref, "relevance": relevance},
        )
        return record if self.add(record) else None

    def add_experience_lesson(
        self,
        *,
        content: str,
        source_ref: str = "operator-review",
        target_scope: str | None = None,
        relevance: float = 0.0,
    ) -> MemoryRecord | None:
        record = MemoryRecord(
            id=f"lesson-{uuid4().hex[:16]}",
            kind=MemoryKind.EXPERIENCE_LESSON,
            content=content,
            target_scope=target_scope,
            provenance={
                "source": "operator_feedback",
                "source_ref": source_ref,
                "relevance": relevance,
            },
        )
        return record if self.add(record) else None

    def retrieve(
        self,
        query: str,
        *,
        kinds: list[MemoryKind] | None = None,
        limit: int | None = None,
        max_chars: int | None = None,
    ) -> MemoryRetrieval:
        clean_query, _ = redact_sensitive(query or "")
        if self._retrievals >= self.budget.max_retrievals:
            return MemoryRetrieval(
                query=clean_query, truncated=True, stop_reason="budget_exhausted"
            )
        self._retrievals += 1
        selected_kinds = kinds or list(MemoryKind)
        allowed = set(selected_kinds)
        item_limit = min(
            limit or self.budget.max_items_per_retrieval, self.budget.max_items_per_retrieval
        )
        char_limit = min(
            max_chars or self.budget.max_chars_per_retrieval, self.budget.max_chars_per_retrieval
        )

        candidates = [
            record
            for record in self._records.values()
            if record.kind in allowed and self._visible(record)
        ]
        if self._retriever is not None and clean_query.strip():
            for kind in selected_kinds:
                try:
                    for raw in self._retriever(clean_query, item_limit, kind):
                        record = (
                            raw
                            if isinstance(raw, MemoryRecord)
                            else MemoryRecord.model_validate(raw)
                        )
                        if (
                            record.id not in self._records
                            and record.kind is kind
                            and self._visible(record)
                        ):
                            candidates.append(record)
                except Exception:
                    # Corpus absence or provider failure is non-fatal.
                    continue
        query_terms = {term.lower() for term in clean_query.split() if len(term) > 2}
        ranked = sorted(
            candidates,
            key=lambda item: (
                len(query_terms.intersection(set(item.content.lower().split())))
                if query_terms
                else 0,
                item.provenance.relevance,
                item.provenance.age_days == 0,
                item.id,
            ),
            reverse=True,
        )
        items: list[MemoryRecord] = []
        used_chars = 0
        truncated = False
        for record in ranked:
            if len(items) >= item_limit:
                truncated = True
                break
            projected = used_chars + len(record.content)
            if projected > char_limit:
                truncated = True
                break
            items.append(record)
            used_chars = projected
        return MemoryRetrieval(
            query=clean_query,
            items=items,
            retrieval_count=self._retrievals,
            truncated=truncated,
            stop_reason="completed" if not truncated else "budget_exhausted",
            source_kinds=sorted({item.kind for item in items}, key=lambda value: value.value),
        )

    def record_feedback(
        self,
        memory_id: str,
        status: FeedbackStatus | str,
        *,
        reviewer: str = "operator",
        note: str = "",
    ) -> MemoryFeedback | None:
        if (
            memory_id not in self._records
            or len(self._feedback) >= self.budget.max_feedback_records
        ):
            return None
        clean_note, _ = redact_sensitive(note or "")
        feedback = MemoryFeedback(
            id=f"feedback-{uuid4().hex[:16]}",
            memory_id=memory_id,
            status=status,
            reviewer=reviewer,
            note=clean_note,
        )
        self._feedback.append(feedback)
        return feedback

    def summary(self) -> dict[str, Any]:
        """Return safe counters, not raw memory content."""
        by_kind = {kind.value: 0 for kind in MemoryKind}
        for record in self._records.values():
            by_kind[record.kind.value] += 1
        return {
            "engagement_scope": self.engagement_scope,
            "records": len(self._records),
            "by_kind": by_kind,
            "feedback_records": len(self._feedback),
            "retrievals": self._retrievals,
            "retrieval_budget_remaining": max(0, self.budget.max_retrievals - self._retrievals),
        }

    def _visible(self, record: MemoryRecord) -> bool:
        if record.kind is MemoryKind.TARGET_FACT:
            return bool(self.engagement_scope and record.target_scope == self.engagement_scope)
        return record.target_scope is None or record.target_scope == self.engagement_scope


__all__ = ["MemoryBoundary"]
