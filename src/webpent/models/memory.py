from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import redact_sensitive


class MemoryKind(StrEnum):
    """The trust boundary a memory item belongs to."""

    TARGET_FACT = "target_fact"
    SECURITY_KNOWLEDGE = "security_knowledge"
    EXPERIENCE_LESSON = "experience_lesson"


class FeedbackStatus(StrEnum):
    """Operator review outcome; it never changes historical evidence."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"


class MemoryProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, max_length=120)
    source_ref: str = Field(default="", max_length=240)
    observed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    age_days: float = Field(default=0.0, ge=0.0, le=36500.0)
    relevance: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("source", "source_ref", "observed_at", "evidence_refs", mode="before")
    @classmethod
    def _redact(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class MemoryRecord(BaseModel):
    """A bounded, provenance-carrying memory item.

    Content is advisory context. It is never a Finding and does not by
    itself increase confidence or authorize a request.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=120)
    kind: MemoryKind
    content: str = Field(min_length=1, max_length=8000)
    target_scope: str | None = Field(default=None, max_length=240)
    provenance: MemoryProvenance
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    immutable: bool = True

    @field_validator("id", "content", "target_scope", "metadata", "created_at", mode="before")
    @classmethod
    def _redact(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean

    @field_validator("target_scope")
    @classmethod
    def _scope_required_for_target_facts(cls, value: str | None, info: Any) -> str | None:
        if info.data.get("kind") == MemoryKind.TARGET_FACT and not value:
            raise ValueError("target_fact memory requires target_scope")
        return value


class MemoryFeedback(BaseModel):
    """Review metadata stored separately from the original memory record."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=120)
    memory_id: str = Field(min_length=1, max_length=120)
    status: FeedbackStatus
    reviewer: str = Field(default="operator", min_length=1, max_length=120)
    note: str = Field(default="", max_length=1000)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @field_validator("id", "memory_id", "reviewer", "note", "created_at", mode="before")
    @classmethod
    def _redact(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class MemoryBudget(BaseModel):
    """Per-engagement retrieval/write limits."""

    model_config = ConfigDict(extra="forbid")

    max_records: int = Field(default=200, ge=1, le=5000)
    max_retrievals: int = Field(default=50, ge=0, le=1000)
    max_items_per_retrieval: int = Field(default=8, ge=1, le=50)
    max_chars_per_retrieval: int = Field(default=6000, ge=100, le=50000)
    max_content_chars: int = Field(default=8000, ge=100, le=20000)
    max_feedback_records: int = Field(default=200, ge=0, le=5000)


class MemoryRetrieval(BaseModel):
    """A non-authoritative retrieval result with explicit boundary metadata."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(default="", max_length=1000)
    items: list[MemoryRecord] = Field(default_factory=list, max_length=50)
    retrieval_count: int = Field(default=0, ge=0)
    truncated: bool = False
    stop_reason: Literal[
        "completed", "budget_exhausted", "corpus_unavailable", "scope_filtered"
    ] = "completed"
    source_kinds: list[MemoryKind] = Field(default_factory=list, max_length=3)

    @field_validator("query", mode="before")
    @classmethod
    def _redact(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean
