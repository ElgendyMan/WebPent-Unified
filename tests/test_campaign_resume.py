# tests/test_campaign_resume.py
"""Proposal 8 (2026-10-25) test suite: campaign resume + probe ledger.

Covers the pure helpers (probe ids, backoff), the interrupt-marker
lifecycle with bounded retries, the probe ledger's SAFE read direction,
and the default-off flag contract.
"""
from __future__ import annotations

import time
from typing import Any

import pytest

from webpent.config.settings import Settings
from webpent.resume.campaign_checkpoints import (
    BACKOFF_BASE_S,
    BACKOFF_CAP_S,
    MAX_CAMPAIGN_RETRIES,
    CampaignCheckpointStore,
    ProbeLedger,
    backoff_seconds,
    derive_probe_id,
    filter_pending_probes,
    state_fingerprint,
)


class TestDefaultOffFlag:
    def test_enable_campaign_resume_defaults_false(self) -> None:
        assert Settings().enable_campaign_resume is False


class TestProbeIds:
    def test_deterministic_and_distinct(self) -> None:
        a = derive_probe_id("https://t.example", "graphql_op", "/api")
        b = derive_probe_id("https://t.example", "graphql_op", "/api")
        c = derive_probe_id("https://t.example", "rest_probe", "/api")
        d = derive_probe_id("https://other.example", "graphql_op", "/api")
        assert a == b
        assert a != c
        assert a != d

    def test_no_separator_collision(self) -> None:
        # ("\x1f" join): ("a|b", "c") must never equal ("a", "b|c")
        left = derive_probe_id("a|b", "c", "p")
        right = derive_probe_id("a", "b|c", "p")
        assert left != right


class TestBackoff:
    def test_exponential_then_cap(self) -> None:
        assert backoff_seconds(0) == BACKOFF_BASE_S
        assert backoff_seconds(1) == 60.0
        assert backoff_seconds(2) == 120.0
        assert backoff_seconds(6) == BACKOFF_CAP_S
        assert backoff_seconds(99) == BACKOFF_CAP_S

    def test_negative_retries_clamped(self) -> None:
        assert backoff_seconds(-1) == backoff_seconds(0)


class TestMarkerLifecycle:
    @pytest.fixture()
    def store(self, tmp_path: Any) -> CampaignCheckpointStore:
        return CampaignCheckpointStore(db_path=str(tmp_path / "markers.db"))

    def test_mark_get_clear(self, store: CampaignCheckpointStore) -> None:
        assert store.get("eng1") is None
        assert store.mark("eng1", reason="worker_crash", node="recon", state_hash="h1")
        marker = store.get("eng1")
        assert marker is not None
        assert marker["reason"] == "worker_crash"
        assert marker["node"] == "recon"
        assert marker["resume_count"] == 0
        store.clear("eng1")
        assert store.get("eng1") is None

    def test_mark_keeps_first_reason(self, store: CampaignCheckpointStore) -> None:
        store.mark("eng1", reason="worker_crash", node=None, state_hash="h1")
        store.mark("eng1", reason="soft_time_limit", node=None, state_hash="h2")
        marker = store.get("eng1")
        assert marker is not None
        assert marker["reason"] == "worker_crash"  # first wins, idempotent

    def test_increment_resume(self, store: CampaignCheckpointStore) -> None:
        store.mark("eng1", reason="worker_crash", node=None, state_hash="h")
        store.increment_resume("eng1")
        store.increment_resume("eng1")
        marker = store.get("eng1")
        assert marker is not None
        assert marker["resume_count"] == 2

    def test_empty_engagement_never_marked(self, store: CampaignCheckpointStore) -> None:
        assert store.mark("", reason="worker_crash", node=None, state_hash="h") is False

    def test_memory_degradation_on_bad_path(self, tmp_path: Any) -> None:
        # An unusable directory must degrade to the memory store, not raise.
        store = CampaignCheckpointStore(db_path=str(tmp_path / "no-such-dir" / "x.db" / "sub"))
        assert store.mark("eng1", reason="worker_crash", node=None, state_hash="h") is True
        assert store.get("eng1") is not None


class TestAutoResume:
    @pytest.fixture()
    def store(self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> CampaignCheckpointStore:
        from webpent.resume import campaign_checkpoints as cc

        store = CampaignCheckpointStore(db_path=str(tmp_path / "markers.db"))
        monkeypatch.setattr(cc, "get_marker_store", lambda: store)
        return store

    def test_fresh_marker_within_budget_resumes(
        self, store: CampaignCheckpointStore
    ) -> None:
        from webpent.resume.campaign_checkpoints import should_auto_resume

        store.mark("eng1", reason="worker_crash", node=None, state_hash="h")
        assert should_auto_resume("eng1", retries=0) is True
        assert should_auto_resume("eng1", retries=1) is True

    def test_no_marker_never_resumes(self, store: CampaignCheckpointStore) -> None:
        from webpent.resume.campaign_checkpoints import should_auto_resume

        assert should_auto_resume("eng-missing", retries=0) is False

    def test_retry_budget_exhausted_fails_closed(
        self, store: CampaignCheckpointStore
    ) -> None:
        from webpent.resume.campaign_checkpoints import should_auto_resume

        store.mark("eng1", reason="soft_time_limit", node=None, state_hash="h")
        assert should_auto_resume("eng1", retries=MAX_CAMPAIGN_RETRIES) is False
        assert should_auto_resume("eng1", retries=MAX_CAMPAIGN_RETRIES + 5) is False

    def test_unknown_reason_never_resumes(self, store: CampaignCheckpointStore) -> None:
        from webpent.resume.campaign_checkpoints import should_auto_resume

        # HITL pauses (or any non-interrupt reason) never auto-resume.
        store.mark("eng1", reason="human_review", node=None, state_hash="h")
        assert should_auto_resume("eng1", retries=0) is False

    def test_snapshot_reports_resumable(self, store: CampaignCheckpointStore) -> None:
        store.mark("eng1", reason="worker_crash", node=None, state_hash="h")
        rows = store.resumable()
        assert any(r["engagement_id"] == "eng1" for r in rows)


class TestProbeLedger:
    @pytest.fixture()
    def ledger(self, tmp_path: Any) -> ProbeLedger:
        return ProbeLedger(db_path=str(tmp_path / "probes.db"))

    def test_mark_then_was_executed(self, ledger: ProbeLedger) -> None:
        pid = derive_probe_id("https://t.example", "rest_probe", "/api/x")
        assert ledger.was_executed("eng1", pid) is False
        assert ledger.mark("eng1", pid) is True
        assert ledger.was_executed("eng1", pid) is True

    def test_engagement_scoped(self, ledger: ProbeLedger) -> None:
        pid = derive_probe_id("https://t.example", "rest_probe", "/api/x")
        ledger.mark("eng1", pid)
        assert ledger.was_executed("eng2", pid) is False

    def test_read_fails_in_SAFE_direction_on_error(self, tmp_path: Any) -> None:
        # A corrupted store must answer False (duplicate probe = safe),
        # never raise or answer True (which would skip a probe).
        ledger = ProbeLedger(db_path=str(tmp_path / "probes.db"))
        if ledger._conn is not None:
            ledger._conn.close()
        ledger._conn = None
        ledger._memory = None  # type: ignore[assignment]  # force read error
        pid = derive_probe_id("https://t.example", "rest_probe", "/api/x")
        assert ledger.was_executed("eng1", pid) is False

    def test_pending_filters_executed(self, ledger: ProbeLedger) -> None:
        probes = [
            ("https://t.example", "rest_probe", "/a"),
            ("https://t.example", "rest_probe", "/b"),
        ]
        ids = [derive_probe_id(*p) for p in probes]
        ledger.mark("eng1", ids[0])
        pending = filter_pending_probes("eng1", probes, ledger=ledger)
        assert pending == [probes[1]]
        # All executed -> nothing pending.
        ledger.mark("eng1", ids[1])
        assert filter_pending_probes("eng1", probes, ledger=ledger) == []

    def test_row_count(self, ledger: ProbeLedger) -> None:
        pid = derive_probe_id("https://t.example", "rest_probe", "/a")
        ledger.mark("eng1", pid)
        ledger.mark("eng1", pid)  # idempotent
        assert ledger.row_count("eng1") == 1


class TestStateFingerprint:
    def test_deterministic_and_audit_only(self) -> None:
        state: dict[str, Any] = {
            "current_phase": "exploit",
            "findings": [{"id": "F-1"}, {"title": "T-2"}],
            "crawled_data": {"routes": ["/a"], "params": []},
        }
        fp1 = state_fingerprint(state)
        fp2 = state_fingerprint(state)
        assert fp1 == fp2
        assert len(fp1) == 64  # sha256 hex
        assert fp1 != state_fingerprint({})

    def test_never_raises_on_garbage(self) -> None:
        assert state_fingerprint(None)
        assert state_fingerprint({"findings": "not-a-list"})
        assert state_fingerprint({"findings": [{"id": {"weird": 1}}]})

    def test_dict_finding_ids_recorded(self) -> None:
        fp = state_fingerprint({"findings": [{"id": "F-9"}]})
        assert fp != "unavailable"


class TestV31LedgerBoundsAndPruning:
    """The v3.1 fixes: MAX_PROBE_ROWS enforced, stale SQLite markers
    pruned, re-mark resume_count preservation pinned in both backends."""

    def test_probe_ledger_enforces_max_rows_sql(self, tmp_path) -> None:
        from webpent.resume.campaign_checkpoints import (
            MAX_PROBE_ROWS,
            ProbeLedger,
        )

        ledger = ProbeLedger(db_path=str(tmp_path / "l.db"))
        # 50k inserts is too slow for a unit test; shrink the bound via
        # monkeypatching the module constant used by _prune_sql.
        import webpent.resume.campaign_checkpoints as cc

        original = cc.MAX_PROBE_ROWS
        cc.MAX_PROBE_ROWS = 20
        try:
            for i in range(30):
                assert ledger.mark("eng-bnd", f"probe-{i:04d}")
            assert ledger.row_count("eng-bnd") == 20
            # oldest executed first: probe-0000 evicted, probe-0029 kept
            assert not ledger.was_executed("eng-bnd", "probe-0000")
            assert ledger.was_executed("eng-bnd", "probe-0029")
        finally:
            cc.MAX_PROBE_ROWS = original

    def test_probe_ledger_enforces_max_rows_memory(self, tmp_path) -> None:
        from webpent.resume.campaign_checkpoints import ProbeLedger
        import webpent.resume.campaign_checkpoints as cc

        ledger = ProbeLedger(db_path=None)
        original = cc.MAX_PROBE_ROWS
        cc.MAX_PROBE_ROWS = 15
        try:
            for i in range(25):
                assert ledger.mark("eng-mem", f"probe-{i:04d}")
            assert ledger.row_count("eng-mem") == 15
            assert not ledger.was_executed("eng-mem", "probe-0000")
            assert ledger.was_executed("eng-mem", "probe-0024")
        finally:
            cc.MAX_PROBE_ROWS = original

    def test_stale_sql_markers_are_deleted(self, tmp_path) -> None:
        import sqlite3
        import time as _time

        from webpent.resume.campaign_checkpoints import (
            MARKER_TTL_S,
            CampaignCheckpointStore,
        )

        db = str(tmp_path / "c.db")
        store = CampaignCheckpointStore(db_path=db)
        store.mark("fresh", reason="soft_time_limit", node="n", state_hash="h")
        # a stale row inserted directly, predating the TTL
        old_ts = _time.time() - MARKER_TTL_S - 60
        store._conn.execute(
            "INSERT INTO campaign_checkpoints (engagement_id, reason, node, "
            "state_hash, interrupted_at, resume_count) VALUES ('stale', "
            "'worker_crash', 'n', 'h', ?, 0)",
            (old_ts,),
        )
        store._conn.commit()
        # get() ignores the stale row...
        assert store.get("stale") is None
        # ...and a write prunes it from the table for real
        store.mark("fresh2", reason="soft_time_limit", node="n", state_hash="h")
        with sqlite3.connect(db) as conn:
            n = conn.execute(
                "SELECT COUNT(*) FROM campaign_checkpoints WHERE engagement_id = 'stale'"
            ).fetchone()[0]
        assert n == 0, "stale marker must be DELETED, not merely ignored"

    def test_remark_preserves_resume_count_both_backends(self, tmp_path) -> None:
        from webpent.resume.campaign_checkpoints import CampaignCheckpointStore

        for store in (
            CampaignCheckpointStore(db_path=str(tmp_path / "a.db")),
            CampaignCheckpointStore(db_path=None),
        ):
            store.mark("e1", reason="soft_time_limit", node="n", state_hash="h")
            store.increment_resume("e1")
            store.increment_resume("e1")
            store.mark("e1", reason="worker_crash", node="n2", state_hash="h2")
            assert store.get("e1")["resume_count"] == 2, type(store._conn)
