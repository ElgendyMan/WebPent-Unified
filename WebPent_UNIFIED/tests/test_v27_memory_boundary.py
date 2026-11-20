from __future__ import annotations

from types import SimpleNamespace

import pytest

from webpent.agents.hypothesis_analyzer import agent as hypothesis_agent
from webpent.models.hypothesis import HypothesisOrigin
from webpent.models.memory import FeedbackStatus, MemoryBudget, MemoryKind, MemoryRecord
from webpent.models.targets import Target
from webpent.shared.memory_boundary import MemoryBoundary


def test_memory_boundary_separates_scope_and_records_feedback_without_raw_summary():
    boundary = MemoryBoundary(
        engagement_scope="https://example.test",
        budget=MemoryBudget(max_records=2, max_retrievals=1, max_items_per_retrieval=1),
    )
    fact = boundary.add_target_fact(
        content="Observed endpoint https://example.test/account",
        source_ref="crawler",
    )
    assert fact is not None
    assert (
        boundary.add_security_knowledge(
            content="Authorization: Bearer super-secret-value",
            source="owasp",
        )
        is not None
    )
    assert (
        boundary.add_experience_lesson(
            content="Review object ownership before changing method",
            target_scope="https://other.test",
        )
        is None
    )

    retrieval = boundary.retrieve("authorization endpoint", kinds=[MemoryKind.SECURITY_KNOWLEDGE])
    assert retrieval.items
    assert "super-secret-value" not in retrieval.items[0].content
    feedback = boundary.record_feedback(fact.id, FeedbackStatus.ACCEPTED, note="validated")
    assert feedback is not None
    summary = boundary.summary()
    assert summary["by_kind"][MemoryKind.TARGET_FACT.value] == 1
    assert summary["feedback_records"] == 1
    assert "content" not in summary
    assert boundary.retrieve("again").stop_reason == "budget_exhausted"


def test_memory_boundary_rejects_cross_engagement_target_fact():
    record = MemoryRecord(
        id="fact-other",
        kind=MemoryKind.TARGET_FACT,
        content="foreign target fact",
        target_scope="https://other.test",
        provenance={"source": "observation"},
    )
    boundary = MemoryBoundary(engagement_scope="https://example.test")
    assert boundary.add(record) is False


def test_hypothesis_node_boundary_is_advisory_and_redacted(monkeypatch: pytest.MonkeyPatch):
    settings = SimpleNamespace(
        enable_memory_boundary=True,
        memory_max_records=20,
        memory_max_retrievals=2,
        memory_max_items_per_retrieval=3,
        memory_max_chars_per_retrieval=2000,
        memory_max_content_chars=2000,
        memory_max_feedback_records=5,
    )

    class FakeVectorStore:
        def search_knowledge(self, query: str, k: int = 3, doc_type=None, stack=None):
            # GOED's curated-RAG contract calls search_knowledge once per
            # doc_type with explicit doc_type/stack kwargs — see
            # RECONCILIATION_REPORT.md.
            return ["Authorization: Bearer super-secret-value"]

        def search_lessons(self, query: str, k: int = 5):
            return ["Past lesson: inspect ownership and method changes"]

    monkeypatch.setattr(hypothesis_agent, "get_settings", lambda: settings)
    monkeypatch.setattr(hypothesis_agent, "get_vector_store_manager", lambda: FakeVectorStore())

    result = hypothesis_agent.hypothesis_node(
        {
            "target": Target(url="https://example.test/search?q=one"),
            "crawled_data": {"endpoints": ["https://example.test/search?q=one"]},
            "skip_recon": True,
        }
    )

    assert result["memory_summary"]["retrieval_items"] >= 1
    assert result["memory_summary"]["by_kind"][MemoryKind.TARGET_FACT.value] == 1
    assert result["memory_feedback"] == []
    assert result["hypotheses"]
    assert all(h.origin != HypothesisOrigin.RAG_INFORMED.value for h in result["hypotheses"])
    serialized = str(result["hypotheses"])
    assert "super-secret-value" not in serialized
    assert "advisory" in result["messages"][0].content.lower()


def test_hypothesis_node_legacy_rag_path_remains_available(monkeypatch: pytest.MonkeyPatch):
    settings = SimpleNamespace(enable_memory_boundary=False)
    monkeypatch.setattr(hypothesis_agent, "get_settings", lambda: settings)
    monkeypatch.setattr(
        hypothesis_agent,
        "_retrieve_relevant_knowledge",
        lambda target_url: "legacy writeup",
    )
    monkeypatch.setattr(
        hypothesis_agent,
        "get_vector_store_manager",
        lambda: SimpleNamespace(search_lessons=lambda *a, **k: []),
    )

    result = hypothesis_agent.hypothesis_node(
        {
            "target": Target(url="https://example.test/xss/search"),
            "crawled_data": {"endpoints": ["https://example.test/xss/search"]},
        }
    )
    assert result["hypotheses"]
    assert any(h.origin == HypothesisOrigin.RAG_INFORMED.value for h in result["hypotheses"])
    assert "memory_summary" not in result
