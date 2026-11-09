# tests/test_worker_coordination.py
"""Track 12 item 3 — multi-worker coordination (claims + dedup + log).

Covers: atomic first-wins claims, renew, TTL takeover, scope-conflict
refusal, client isolation, cross-worker fingerprint dedup (first seen /
duplicate / indeterminate), the append-only change log, snapshots, and
safe degradation when the ledger directory is unusable.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from webpent.production.worker_coordination import (
    ClaimOutcome,
    DedupVerdict,
    WorkerCoordinator,
)

FP_XSS = "fp:xss:reflected:/search:q"
FP_Sqli = "fp:sqli:error:/item:id"


@pytest.fixture()
def coord(tmp_path: Path) -> WorkerCoordinator:
    return WorkerCoordinator(tmp_path / "coord", claim_ttl_seconds=2.0)


class TestWorkClaims:
    def test_first_wins_then_busy(self, coord):
        a = coord.claim_work("client-1", "scope-A", "campaign-1")
        assert a.outcome is ClaimOutcome.ACQUIRED
        assert a.holder_worker_id == coord.worker_id
        # The SAME worker re-claiming a live claim renews it.
        assert coord.claim_work("client-1", "scope-A", "campaign-1").outcome is (
            ClaimOutcome.RENEWED
        )
        # A DIFFERENT worker on the same unit is busy.
        other = WorkerCoordinator(
            coord.coord_dir, worker_id="worker-B", claim_ttl_seconds=2.0
        )
        b = other.claim_work("client-1", "scope-A", "campaign-1")
        assert b.outcome is ClaimOutcome.BUSY
        assert b.holder_worker_id == coord.worker_id

    def test_renew_same_worker_extends(self, coord):
        first = coord.claim_work("client-1", "scope-A", "unit-1")
        time.sleep(0.05)
        renewed = coord.claim_work("client-1", "scope-A", "unit-1")
        assert renewed.outcome is ClaimOutcome.RENEWED
        assert renewed.expires_at is not None
        assert first.expires_at is not None
        assert renewed.expires_at >= first.expires_at

    def test_release_then_reacquire(self, coord):
        coord.claim_work("client-1", "scope-A", "unit-1")
        assert coord.release_claim("client-1", "unit-1") is True
        second = WorkerCoordinator(
            coord.coord_dir, worker_id="worker-B", claim_ttl_seconds=2.0
        )
        decision = second.claim_work("client-1", "scope-A", "unit-1")
        assert decision.outcome is ClaimOutcome.ACQUIRED
        assert decision.holder_worker_id == "worker-B"
        # Releasing a foreign claim is refused.
        assert coord.release_claim("client-1", "unit-1") is False

    def test_ttl_takeover_after_expiry(self, coord):
        coord.claim_work("client-1", "scope-A", "unit-1", work_kind="retest")
        other = WorkerCoordinator(
            coord.coord_dir, worker_id="worker-B", claim_ttl_seconds=2.0
        )
        # Still live → busy.
        assert other.claim_work("client-1", "scope-A", "unit-1").outcome is (
            ClaimOutcome.BUSY
        )
        # Simulate the holder dying without release: force expiry.
        time.sleep(2.1)
        decision = other.claim_work("client-1", "scope-A", "unit-1")
        assert decision.outcome is ClaimOutcome.TAKEOVER

    def test_scope_conflict_never_taken_over(self, coord):
        coord.claim_work("client-1", "scope-hash-A", "unit-1")
        other = WorkerCoordinator(
            coord.coord_dir, worker_id="worker-B", claim_ttl_seconds=2.0
        )
        time.sleep(2.1)  # even expired, a scope mismatch must not take over
        decision = other.claim_work("client-1", "scope-hash-B", "unit-1")
        assert decision.outcome is ClaimOutcome.SCOPE_CONFLICT

    def test_client_isolation_same_unit_id(self, coord):
        """Same work-unit id under different clients NEVER collides."""
        assert coord.claim_work("client-1", "scope-A", "unit-1").outcome is (
            ClaimOutcome.ACQUIRED
        )
        assert coord.claim_work("client-2", "scope-A", "unit-1").outcome is (
            ClaimOutcome.ACQUIRED
        )

    def test_claim_status_view(self, coord):
        assert coord.claim_status("client-1", "ghost") is None
        coord.claim_work("client-1", "scope-A", "unit-1")
        meta = coord.claim_status("client-1", "unit-1")
        assert meta is not None
        assert meta["expired"] is False
        assert meta["work_kind"] == "campaign"


class TestCrossWorkerDedup:
    def test_first_seen_then_duplicate_for_other_worker(self, coord):
        assert coord.register_result("client-1", "scope-A", FP_XSS) is (
            DedupVerdict.FIRST_SEEN
        )
        other = WorkerCoordinator(
            coord.coord_dir, worker_id="worker-B", claim_ttl_seconds=2.0
        )
        assert other.register_result("client-1", "scope-A", FP_XSS) is (
            DedupVerdict.DUPLICATE
        )
        # Same worker re-registering is also a duplicate (idempotent).
        assert coord.register_result("client-1", "scope-A", FP_XSS) is (
            DedupVerdict.DUPLICATE
        )

    def test_different_fingerprints_both_first(self, coord):
        assert coord.register_result("client-1", "scope-A", FP_XSS) is (
            DedupVerdict.FIRST_SEEN
        )
        assert coord.register_result("client-1", "scope-A", FP_Sqli) is (
            DedupVerdict.FIRST_SEEN
        )

    def test_client_isolation_of_fingerprints(self, coord):
        assert coord.register_result("client-1", "scope-A", FP_XSS) is (
            DedupVerdict.FIRST_SEEN
        )
        other = WorkerCoordinator(
            coord.coord_dir, worker_id="worker-B", claim_ttl_seconds=2.0
        )
        # Cross-client duplicates are impossible: client-2 has its own
        # namespace, so the SAME logical finding is FIRST_SEEN there.
        assert other.register_result("client-2", "scope-A", FP_XSS) is (
            DedupVerdict.FIRST_SEEN
        )

    def test_empty_fingerprint_is_indeterminate(self, coord):
        assert coord.register_result("client-1", "scope-A", "  ") is (
            DedupVerdict.INDETERMINATE
        )

    def test_unwritable_ledger_degrades_to_indeterminate(self, tmp_path):
        blocker = tmp_path / "blocker"
        blocker.write_text("file, not dir")
        coord = WorkerCoordinator(
            tmp_path / "coord2", worker_id="w", claim_ttl_seconds=2.0
        )
        # Force the fingerprints dir to collide with a regular file.
        fp_dir = coord.coord_dir / "clients"
        # Claim path works (dir exists); now sabotage fingerprint storage
        # by replacing the fingerprints directory with a file.
        import shutil

        shutil.rmtree(coord._fingerprints_dir("client-1"))
        fp_dir.joinpath("x").unlink(missing_ok=True)
        (coord._client_dir("client-1") / "fingerprints").write_text("not a dir")
        assert coord.register_result("client-1", "scope-A", FP_XSS) is (
            DedupVerdict.INDETERMINATE
        )


class TestChangeLog:
    def test_events_appended_and_readable(self, coord):
        coord.claim_work("client-1", "scope-A", "unit-1")
        coord.release_claim("client-1", "unit-1", note="done")
        coord.register_result("client-1", "scope-A", FP_XSS)
        events = [r["event"] for r in coord.read_change_log(limit=100)]
        assert "claim_acquired" in events
        assert "claim_released" in events
        assert "result_first_seen" in events
        records = coord.read_change_log(limit=2)
        assert len(records) == 2
        for record in records:
            assert record["worker_id"] == coord.worker_id
            assert "ts" in record

    def test_takeover_and_scope_conflict_logged(self, coord):
        coord.claim_work("client-1", "scope-hash-A", "unit-1")
        other = WorkerCoordinator(
            coord.coord_dir, worker_id="worker-B", claim_ttl_seconds=2.0
        )
        time.sleep(2.1)
        other.claim_work("client-1", "scope-hash-A", "unit-1")  # takeover
        coord.claim_work("client-1", "scope-hash-B", "unit-1")  # conflict
        events = [r["event"] for r in coord.read_change_log(limit=100)]
        assert "claim_takeover" in events
        assert "claim_scope_conflict" in events


class TestSnapshot:
    def test_snapshot_counts_and_scoping(self, coord):
        coord.claim_work("client-1", "scope-A", "unit-1")
        coord.claim_work("client-2", "scope-A", "unit-2")
        coord.register_result("client-1", "scope-A", FP_XSS)
        scoped = coord.snapshot("client-1")
        assert scoped["active_claims"] == 1
        assert scoped["registered_fingerprints"] == 1
        assert scoped["active_claim_records"][0]["work_unit_id"] == "unit-1"
        aggregate = coord.snapshot()
        assert aggregate["active_claims"] == 2
        assert aggregate["registered_fingerprints"] == 1
        assert "active_claim_records" not in aggregate

    def test_expired_claims_not_counted_active(self, coord):
        coord.claim_work("client-1", "scope-A", "unit-1")
        time.sleep(2.1)
        snap = coord.snapshot("client-1")
        assert snap["active_claims"] == 0
        assert snap["total_claim_files"] == 1
