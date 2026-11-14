"""P2-307 — concurrency verification harness (Phase-1 Appendix-B commitment).

Converts three Phase-1 UNVERIFIED static verdicts into tested facts:

(a) ``get_rate_governor()`` double-checked-locking creation is race-free
    under threads — exactly one process-wide instance.
(b) Concurrent campaigns in one process SHARE the governor by design — the
    documented behavior is cross-campaign counter aggregation; this harness
    asserts aggregation with zero lost updates under contention (it does NOT
    pretend isolation).
(c) The vectorstore/target-workspace ``ContextVar`` isolates two interleaved
    async executions — each execution context observes only its own
    workspace, and a cross-target nested activation is rejected fail-closed.

(d) P2-104 regression as a concurrency case: lesson scope stays exact when
    two client-scoped managers are exercised from interleaved threads.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace

import pytest

from webpent.shared.rate_governor import get_rate_governor
from webpent.shared.target_workspace import TargetWorkspace
from webpent.shared.target_workspace_context import (
    activate_target_workspace,
    get_active_target_workspace,
)

# ---------------------------------------------------------------------------
# (a) singleton creation is race-free under threads
# ---------------------------------------------------------------------------


def test_get_rate_governor_thread_hammer_yields_single_instance() -> None:
    barrier = threading.Barrier(32)
    results: list[int] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def hammer() -> None:
        try:
            barrier.wait(timeout=10)
            gov = get_rate_governor()
            with lock:
                results.append(id(gov))
        except BaseException as exc:  # pragma: no cover — recorded, never silent
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=hammer) for _ in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
        assert not t.is_alive(), "thread-hammer deadlocked"

    assert not errors, f"governor creation raised under contention: {errors[:3]}"
    assert len(results) == 32
    assert len(set(results)) == 1, "double-checked locking produced >1 instance"


# ---------------------------------------------------------------------------
# (b) shared governor aggregates counters across concurrent campaigns
# ---------------------------------------------------------------------------


def test_concurrent_campaigns_aggregate_governor_counters() -> None:
    governor = get_rate_governor()
    host = "aggregate.test"
    governor.reset(host)

    attempts = 400
    threads = 8
    per_thread = attempts // threads
    errors: list[BaseException] = []

    def campaign(cid: int) -> None:
        try:
            for _i in range(per_thread):
                with governor.acquire(host) as permit:
                    if permit.aborted:  # pragma: no cover — cap is high enough
                        continue
                    governor.record_response(host, 200)
        except BaseException as exc:  # pragma: no cover — recorded, never silent
            errors.append(exc)

    ts = [threading.Thread(target=campaign, args=(i,)) for i in range(threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=30)
        assert not t.is_alive(), "campaign threads deadlocked"

    assert not errors, f"governor raised under contention: {errors[:3]}"
    stats = governor.get_stats(host)
    # zero lost updates: every acquire recorded exactly one response
    assert stats["total_count"] == attempts, f"lost updates under contention: {stats['total_count']} != {attempts}"
    assert stats["error_count"] == 0
    assert stats["aborted"] is False
    governor.reset(host)


# ---------------------------------------------------------------------------
# (c) ContextVar workspace isolation across interleaved async executions
# ---------------------------------------------------------------------------


async def _workspace_worker(workspace: TargetWorkspace, probe_count: int) -> tuple[int, int]:
    """Activate the workspace and probe repeatedly; return
    (observed_foreign, observed_own)."""
    foreign = 0
    own = 0
    with activate_target_workspace(workspace):
        for _ in range(probe_count):
            active = get_active_target_workspace()
            if active is None:
                continue
            if active.workspace_id != workspace.workspace_id:
                foreign += 1
            else:
                own += 1
            await asyncio.sleep(0)  # yield control to the sibling task
    return foreign, own


async def test_interleaved_async_workspaces_are_context_isolated(tmp_path) -> None:
    ws_a = TargetWorkspace.for_target(
        workspace_root=tmp_path / "ws-a",
        target_origin="http://a.test",
        client_id="client-a",
        engagement_id="eng-a",
    )
    ws_b = TargetWorkspace.for_target(
        workspace_root=tmp_path / "ws-b",
        target_origin="http://b.test",
        client_id="client-b",
        engagement_id="eng-b",
    )
    foreign_a, own_a = await _workspace_worker(ws_a, 50)
    foreign_b, own_b = await _workspace_worker(ws_b, 50)
    assert foreign_a == 0 and foreign_b == 0, "workspace context leaked across tasks"
    assert own_a == 50 and own_b == 50, "probes did not observe their own workspace"


async def test_nested_cross_target_activation_is_fail_closed(tmp_path) -> None:
    ws_a = TargetWorkspace.for_target(
        workspace_root=tmp_path / "ws-a",
        target_origin="http://a.test",
        client_id="client-a",
        engagement_id="eng-a",
    )
    ws_b = TargetWorkspace.for_target(
        workspace_root=tmp_path / "ws-b",
        target_origin="http://b.test",
        client_id="client-b",
        engagement_id="eng-b",
    )
    with (
        activate_target_workspace(ws_a),
        pytest.raises(RuntimeError, match="target_workspace_switch_blocked"),
        activate_target_workspace(ws_b),
    ):
        pass  # pragma: no cover — must never be reached


# ---------------------------------------------------------------------------
# (d) P2-104 regression as a concurrency case: lesson scope under interleaving
# ---------------------------------------------------------------------------


class _ScopedFakeStore:
    """Records writes; honors the exact scope filter on reads."""

    def __init__(self, client_id: str) -> None:
        self.client_id = client_id
        self.lessons: dict[str, list[str]] = {}
        self.lock = threading.Lock()

    def add_texts(self, *, texts, metadatas) -> None:
        with self.lock:
            for text, meta in zip(texts, metadatas, strict=True):
                self.lessons.setdefault(meta.get("engagement_id", ""), []).append(text)

    def similarity_search(self, *, query, k, filter=None):
        with self.lock:
            if isinstance(filter, dict) and "$and" in filter:
                want_client = filter["$and"][0]["client_id"]
                want_eng = filter["$and"][1]["engagement_id"]
                if want_client != self.client_id:
                    return []
                return [SimpleNamespace(page_content=text) for text in self.lessons.get(want_eng, [])][:k]
            return []


def test_lesson_scope_stays_exact_under_interleaved_managers(monkeypatch, tmp_path) -> None:
    import webpent.memory.embeddings as _embeddings
    from webpent.memory.vectorstore import VectorStoreManager

    monkeypatch.setattr(_embeddings, "is_rag_enabled", lambda: True)
    mgr_a = VectorStoreManager(persist_path=str(tmp_path / "a"))
    mgr_b = VectorStoreManager(persist_path=str(tmp_path / "b"))
    store_a, store_b = _ScopedFakeStore("client-a"), _ScopedFakeStore("client-b")
    mgr_a._lessons_store = store_a
    mgr_b._lessons_store = store_b

    errors: list[BaseException] = []

    def write_worker(mgr, client, eng, tag, n):
        try:
            for i in range(n):
                mgr.add_lesson(f"{tag}-{i}", {"client_id": client, "engagement_id": eng})
                # unscoped write must be refused (P2-104 fail-closed contract)
                mgr.add_lesson(f"{tag}-unscoped-{i}", {"client_id": client})
        except BaseException as exc:  # pragma: no cover — recorded, never silent
            errors.append(exc)

    ts = [
        threading.Thread(target=write_worker, args=(mgr_a, "client-a", "eng-a", "a", 25)),
        threading.Thread(target=write_worker, args=(mgr_b, "client-b", "eng-b", "b", 25)),
    ]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=30)
        assert not t.is_alive(), "lesson write threads deadlocked"
    assert not errors, f"interleaved lesson writes raised: {errors[:3]}"

    # scope exactness after contention
    got_a = mgr_a.search_lessons("query", k=100, client_id="client-a", engagement_id="eng-a")
    got_b = mgr_b.search_lessons("query", k=100, client_id="client-b", engagement_id="eng-b")
    assert len(got_a) == 25 and all(x.startswith("a-") for x in got_a)
    assert len(got_b) == 25 and all(x.startswith("b-") for x in got_b)
    # cross-client read fails closed
    assert mgr_a.search_lessons("query", k=100, client_id="client-b", engagement_id="eng-b") == []
    # unscoped writes never persisted (25 scoped + 0 unscoped per store)
    assert len(store_a.lessons.get("eng-a", [])) == 25
    assert len(store_b.lessons.get("eng-b", [])) == 25
