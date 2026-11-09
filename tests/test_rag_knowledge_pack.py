from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

from webpent.shared import knowledge_retrieval

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INGEST_PATH = PROJECT_ROOT / "scripts" / "ingest_payloads.py"


def _load_ingest_module():
    spec = importlib.util.spec_from_file_location("webpent_test_ingest_payloads", INGEST_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_curated_retrieval_calls_each_requested_type_and_bounds_context(monkeypatch):
    calls: list[tuple[str, str, int, str | None]] = []

    class FakeManager:
        def search_knowledge(self, query, k=3, doc_type=None, stack=None):
            calls.append((query, doc_type, k, stack))
            return [f"content for {doc_type}"]

    monkeypatch.setattr(knowledge_retrieval, "get_vector_store_manager", lambda: FakeManager())
    result = knowledge_retrieval.retrieve_knowledge_context(
        "authorization ownership GraphQL",
        doc_types=("methodology", "repository", "report", "writeup", "scenario"),
        per_type_k=9,
        max_chars=1000,
    )

    assert {call[1] for call in calls} == {
        "methodology",
        "repository",
        "report",
        "writeup",
        "scenario",
    }
    assert all(call[2] == 5 for call in calls)
    assert all(f"[RAG type={doc_type}" in result for doc_type in {call[1] for call in calls})
    assert len(result) <= 1000


def test_planner_and_hypothesis_use_curated_retrieval(monkeypatch):
    from webpent.agents.hypothesis_analyzer import agent as hypothesis_agent
    from webpent.agents.planner import agent as planner_agent

    observed: list[tuple[str, tuple[str, ...]]] = []

    def fake_retrieve(query, *, doc_types, **kwargs):
        observed.append((query, tuple(doc_types)))
        return "curated advisory context"

    monkeypatch.setattr(planner_agent, "retrieve_knowledge_context", fake_retrieve)
    monkeypatch.setattr(hypothesis_agent, "retrieve_knowledge_context", fake_retrieve)

    assert planner_agent._retrieve_methodologies() == "curated advisory context"
    assert hypothesis_agent._retrieve_relevant_knowledge("https://lab.test/search?q=x") == (
        "curated advisory context"
    )

    types_seen = {doc_type for _, types in observed for doc_type in types}
    assert {"methodology", "repository", "scenario"}.issubset(types_seen)
    assert {"writeup", "report", "scenario"}.issubset(types_seen)


def test_local_manifest_dry_run_is_safe_and_counts_all_pack_entries(monkeypatch):
    module = _load_ingest_module()
    fake_manager = SimpleNamespace()
    monkeypatch.setattr(module, "_load_manifest", lambda path: {})
    monkeypatch.setattr(module, "get_vector_store_manager", lambda: fake_manager, raising=False)

    manifest = {
        "_base_dir": str(PROJECT_ROOT / "knowledge_pack"),
        "sources": [
            {
                "type": "local_file",
                "path": "methodologies/web-application-testing.md",
                "doc_type": "methodology",
            },
            {
                "type": "local_file",
                "path": "repositories/security-repositories.md",
                "doc_type": "repository",
            },
        ],
    }

    result = module.ingest_manifest(manifest, dry_run=True)
    assert result == {"fetched": 2, "ingested": 0, "failed": 0, "total_chunks": 0}


def test_vectorstore_source_id_dedupe_is_fail_open_for_legacy_store(monkeypatch):
    from webpent.memory import vectorstore

    class Store:
        def get(self, **kwargs):
            return {"ids": ["existing"]}

        def add_texts(self, **kwargs):
            raise AssertionError("duplicate source must not be written")

    manager = vectorstore.VectorStoreManager()
    monkeypatch.setattr(manager, "_get_store", lambda name: Store())
    assert (
        manager.add_knowledge_batch(
            texts=["same source"],
            metadatas=[{"source_id": "pack.example.v1"}],
            doc_type="scenario",
        )
        == 0
    )
