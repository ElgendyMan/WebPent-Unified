"""Isolated, advisory security reasoning memory.

This store is deliberately scoped to one engagement and target.  It stores only
redacted reasoning summaries and evidence references; it cannot execute a
request or promote a finding.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Literal

from webpent.models.evidence import redact_sensitive
from webpent.models.memory import MemoryBudget, MemoryKind, MemoryRecord
from webpent.shared.memory_boundary import MemoryBoundary

LearningOutcome = Literal[
    "supported",
    "rejected",
    "blocked",
    "inconclusive",
    "duplicate",
]
ResearcherMemoryCategory = Literal[
    "investigation_decision",
    "reasoning_chain",
    "successful_path",
    "failed_path",
    "environment_limitation",
    "oracle_failure",
]


class SecurityReasoningMemory:
    """A deterministic target-isolated facade over the existing memory boundary."""

    def __init__(
        self,
        *,
        engagement_id: str,
        target_id: str,
        budget: MemoryBudget | None = None,
    ) -> None:
        if not engagement_id.strip() or not target_id.strip():
            raise ValueError("engagement_and_target_scope_required")
        self.engagement_id = engagement_id.strip()
        self.target_id = target_id.strip()
        self.scope = f"{self.engagement_id}:{self.target_id}"
        self._boundary = MemoryBoundary(engagement_scope=self.scope, budget=budget)

    @property
    def records(self) -> tuple[MemoryRecord, ...]:
        return self._boundary.records

    @property
    def feedback_records(self):
        return self._boundary.feedback

    def remember(
        self,
        *,
        category: MemoryKind | str,
        content: str,
        source_ref: str = "",
        evidence_refs: Iterable[str] = (),
        relevance: float = 0.0,
        metadata: dict[str, object] | None = None,
    ) -> MemoryRecord | None:
        """Write a bounded record with a stable ID and mandatory target scope."""
        kind = category if isinstance(category, MemoryKind) else MemoryKind(str(category))
        clean_content, _ = redact_sensitive(content)
        clean_source, _ = redact_sensitive(source_ref)
        refs = tuple(redact_sensitive(str(ref))[0] for ref in evidence_refs if str(ref).strip())[
            :20
        ]
        digest = hashlib.sha256(
            f"{self.scope}|{kind.value}|{clean_content}|{clean_source}|{','.join(refs)}".encode()
        ).hexdigest()[:24]
        record = MemoryRecord(
            id=f"security-memory:{digest}",
            kind=kind,
            content=clean_content,
            target_scope=self.scope,
            provenance={
                "source": "security_reasoning",
                "source_ref": clean_source,
                "relevance": relevance,
                "evidence_refs": list(refs),
            },
            metadata=metadata or {},
        )
        return record if self._boundary.add(record) else None

    def retrieve(
        self,
        query: str,
        *,
        kinds: list[MemoryKind] | None = None,
        limit: int | None = None,
    ):
        """Return advisory memories already filtered to this exact scope."""
        return self._boundary.retrieve(query, kinds=kinds, limit=limit)

    def record_feedback(self, memory_id: str, status: str, *, note: str = ""):
        return self._boundary.record_feedback(
            memory_id, status, reviewer="ai_technical_review", note=note
        )

    def learn_from_outcome(
        self,
        *,
        hypothesis_id: str,
        outcome: LearningOutcome | str,
        rationale: str,
        evidence_refs: Iterable[str] = (),
        relevance: float = 0.0,
    ) -> MemoryRecord | None:
        """Store a scoped lesson without changing hypothesis or finding status.

        This is learning support only: the resulting lesson cannot authorize a
        request, replace a causal oracle, or promote a finding.  Outcomes that
        lack proof are deliberately mapped to ``needs_more_evidence`` feedback.
        """
        clean_hypothesis, _ = redact_sensitive(hypothesis_id)
        clean_outcome, _ = redact_sensitive(str(outcome))
        clean_rationale, _ = redact_sensitive(rationale)
        allowed: set[str] = {
            "supported",
            "rejected",
            "blocked",
            "inconclusive",
            "duplicate",
        }
        if clean_outcome not in allowed:
            raise ValueError("unsupported_learning_outcome")
        content = (
            f"hypothesis={clean_hypothesis}; outcome={clean_outcome}; rationale={clean_rationale}"
        )
        record = self.remember(
            category=MemoryKind.EXPERIENCE_LESSON,
            content=content,
            source_ref=f"hypothesis:{clean_hypothesis}",
            evidence_refs=evidence_refs,
            relevance=relevance,
            metadata={
                "learning_outcome": clean_outcome,
                "hypothesis_id": clean_hypothesis,
                "advisory_only": True,
            },
        )
        if record is None:
            return None
        status = {
            "supported": "accepted",
            "rejected": "rejected",
            "duplicate": "duplicate",
            "blocked": "needs_more_evidence",
            "inconclusive": "needs_more_evidence",
        }[clean_outcome]
        self.record_feedback(record.id, status, note=clean_rationale)
        return record

    def retrieve_learning(self, query: str, *, limit: int | None = None):
        """Retrieve only scoped experience lessons for advisory reuse."""
        return self.retrieve(
            query,
            kinds=[MemoryKind.EXPERIENCE_LESSON],
            limit=limit,
        )

    def remember_research(
        self,
        *,
        category: ResearcherMemoryCategory | str,
        content: str,
        source_ref: str = "",
        evidence_refs: Iterable[str] = (),
        relevance: float = 0.0,
        metadata: dict[str, object] | None = None,
    ) -> MemoryRecord | None:
        """Store a redacted researcher lesson in the exact target scope.

        This is a memory projection only.  It cannot execute a task, change
        policy, replace an oracle, or promote a hypothesis/finding.
        """
        allowed = {
            "investigation_decision",
            "reasoning_chain",
            "successful_path",
            "failed_path",
            "environment_limitation",
            "oracle_failure",
        }
        clean_category = str(category).strip()
        if clean_category not in allowed:
            raise ValueError("unsupported_researcher_memory_category")
        merged = dict(metadata or {})
        merged.update({"researcher_category": clean_category, "advisory_only": True})
        return self.remember(
            category=MemoryKind.EXPERIENCE_LESSON,
            content=content,
            source_ref=source_ref,
            evidence_refs=evidence_refs,
            relevance=relevance,
            metadata=merged,
        )

    def researcher_summary(self, query: str = "", *, limit: int | None = None) -> dict[str, object]:
        """Return categorized, scope-filtered memory for advisory reuse."""
        retrieval = self.retrieve_learning(query, limit=limit)
        items = getattr(retrieval, "items", ())
        grouped: dict[str, list[dict[str, object]]] = {
            "investigation_decision": [],
            "reasoning_chain": [],
            "successful_path": [],
            "failed_path": [],
            "environment_limitation": [],
            "oracle_failure": [],
        }
        for item in items:
            category = str(item.metadata.get("researcher_category", ""))
            if category in grouped:
                grouped[category].append(
                    {
                        "id": item.id,
                        "content": item.content,
                        "evidence_refs": list(item.provenance.evidence_refs),
                    }
                )
        return {
            "scope": self.scope,
            "isolated": True,
            "items": grouped,
            "authoritative": False,
            "execution_capability": False,
        }

    def summary(self) -> dict[str, object]:
        return {
            **self._boundary.summary(),
            "engagement_id": self.engagement_id,
            "target_id": self.target_id,
            "isolated": True,
            "authoritative": False,
            "execution_capability": False,
        }


__all__ = ["LearningOutcome", "ResearcherMemoryCategory", "SecurityReasoningMemory"]
