# tests/test_cross_process_leases.py
"""Track 12 item 2 (phase 2) — cross-process lease backend.

Covers: flock slot semantics (busy/free), all-or-nothing acquisition,
governor integration behind the same interface, crash safety (kernel
releases flocks when a holder dies), snapshot monitoring, and the
fail-open posture when the lease directory is unusable.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from webpent.production.concurrency_governor import ConcurrencyGovernor
from webpent.production.cross_process_leases import FileLeaseBackend

T_A = "https://app.example.com/login"
T_B = "https://api.example.com/v2"

HOLD_CHILD = textwrap.dedent(
    """
    import os, sys, time
    sys.path.insert(0, {src!r})
    from webpent.production.cross_process_leases import FileLeaseBackend
    backend = FileLeaseBackend(
        {lease_dir!r}, max_global={max_global}, max_per_target={max_per_target}
    )
    ok = backend.try_acquire_slots({campaign!r}, {target!r})
    print("HELD" if ok else "BUSY", flush=True)
    if ok:
        with open({signal_path!r}, "w") as fh:
            fh.write("ready")
        time.sleep(300)
    """
)


@pytest.fixture()
def lease_dir(tmp_path: Path) -> Path:
    return tmp_path / "leases"


def _spawn_holder(
    lease_dir: Path, campaign: str, target: str, signal_path: Path, tmp_path: Path
) -> subprocess.Popen:
    """Spawn a real child process that holds lease slots."""
    src_root = str(Path(__file__).resolve().parents[1] / "src")
    script = HOLD_CHILD.format(
        src=src_root,
        lease_dir=str(lease_dir),
        max_global=2,
        max_per_target=1,
        campaign=campaign,
        target=target,
        signal_path=str(signal_path),
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(tmp_path),
    )
    deadline = time.time() + 15
    while time.time() < deadline:
        if signal_path.exists():
            return proc
        if proc.poll() is not None:
            out, err = proc.communicate(timeout=5)
            raise AssertionError(
                f"holder exited early rc={proc.returncode} out={out!r} err={err!r}"
            )
        time.sleep(0.05)
    proc.kill()
    raise AssertionError("holder never signalled readiness")


class TestFileLeaseBackend:
    def test_acquire_and_release_roundtrip(self, lease_dir):
        backend = FileLeaseBackend(lease_dir, max_global=1, max_per_target=1)
        assert backend.try_acquire_slots("c1", T_A) is True
        assert backend.holds("c1") is True
        backend.release_slots("c1", T_A)
        assert backend.holds("c1") is False
        # Slot is free again.
        assert backend.try_acquire_slots("c2", T_A) is True

    def test_same_target_second_campaign_denied(self, lease_dir):
        backend = FileLeaseBackend(lease_dir, max_global=2, max_per_target=1)
        assert backend.try_acquire_slots("c1", T_A) is True
        assert backend.try_acquire_slots("c2", T_A) is False
        # Different target still fits the global cap.
        assert backend.try_acquire_slots("c2", T_B) is True

    def test_global_cap_enforced_across_targets(self, lease_dir):
        backend = FileLeaseBackend(lease_dir, max_global=1, max_per_target=2)
        assert backend.try_acquire_slots("c1", T_A) is True
        assert backend.try_acquire_slots("c2", T_B) is False

    def test_all_or_nothing_on_global_shortage(self, lease_dir):
        """Target slot taken then global refused → target must NOT leak."""
        backend = FileLeaseBackend(lease_dir, max_global=1, max_per_target=2)
        assert backend.try_acquire_slots("c1", T_A) is True
        # c2 gets the free target slot for T_B, then global is refused.
        assert backend.try_acquire_slots("c2", T_B) is False
        backend.release_slots("c1", T_A)
        # Global freed and NO leaked T_B slot: c2 takes it cleanly now.
        assert backend.try_acquire_slots("c2", T_B) is True
        # The global cap (1) is the binding constraint for the next one.
        assert backend.try_acquire_slots("c3", T_B) is False

    def test_zero_cap_means_unlimited(self, lease_dir):
        backend = FileLeaseBackend(lease_dir, max_global=0, max_per_target=0)
        for i in range(5):
            assert backend.try_acquire_slots(f"c{i}", T_A) is True

    def test_snapshot_reports_active_leases(self, lease_dir):
        backend = FileLeaseBackend(lease_dir, max_global=2, max_per_target=1)
        assert backend.try_acquire_slots("c1", T_A) is True
        snap = backend.snapshot()
        assert snap.global_slots_total == 2
        assert snap.global_slots_active == 1
        assert snap.target_slots_active == 1
        assert any(
            lease.get("campaign_id") == "c1" for lease in snap.active_leases
        )

    def test_blocking_acquire_succeeds_after_release(self, lease_dir):
        backend = FileLeaseBackend(lease_dir, max_global=1, max_per_target=1)
        assert backend.try_acquire_slots("c1", T_A) is True

        import threading

        result: dict[str, bool] = {}

        def waiter():
            result["ok"] = backend.acquire_slots("c2", T_A, timeout=10.0)

        thread = threading.Thread(target=waiter, daemon=True)
        thread.start()
        time.sleep(0.3)
        backend.release_slots("c1", T_A)
        thread.join(timeout=15)
        assert result["ok"] is True

    def test_blocking_acquire_times_out_when_held(self, lease_dir):
        backend = FileLeaseBackend(lease_dir, max_global=1, max_per_target=1)
        assert backend.try_acquire_slots("c1", T_A) is True
        assert backend.acquire_slots("c2", T_A, timeout=0.5) is False
        backend.release_slots("c1", T_A)

    def test_unwritable_dir_raises_for_caller_policy(self, tmp_path):
        # A file where the directory should be → construction fails loudly
        # (the factory converts this into "backend disabled" + loud log).
        blocker = tmp_path / "blocker"
        blocker.write_text("not a dir")
        with pytest.raises(OSError):
            FileLeaseBackend(blocker)


class TestCrossProcessReality:
    def test_second_process_denied_then_slot_freed_after_crash(self, lease_dir, tmp_path):
        """THE phase-2 proof: a live child process holds the slot; the
        parent is denied. SIGKILL the child → the kernel drops the flock
        → the parent acquires. No stale-lease cleanup involved."""
        signal_path = tmp_path / "holder_ready.txt"
        proc = _spawn_holder(lease_dir, "child-c1", T_A, signal_path, tmp_path)
        try:
            parent = FileLeaseBackend(lease_dir, max_global=2, max_per_target=1)
            assert parent.try_acquire_slots("parent-c1", T_A) is False
            # Different target is fine (global cap 2, one slot in use).
            assert parent.try_acquire_slots("parent-c1", T_B) is True
            parent.release_slots("parent-c1", T_B)
        finally:
            os.kill(proc.pid, signal.SIGKILL)
            proc.wait(timeout=10)
        # Crash safety: the OS released the flock — parent now admits.
        deadline = time.time() + 5
        acquired = False
        while time.time() < deadline and not acquired:
            acquired = FileLeaseBackend(
                lease_dir, max_global=2, max_per_target=1
            ).try_acquire_slots("parent-c2", T_A)
            if not acquired:
                time.sleep(0.1)
        assert acquired, "slot not reclaimable after holder crash"

    def test_release_by_holder_frees_slot_for_parent(self, lease_dir, tmp_path):
        release_signal = tmp_path / "RELEASE"
        child = textwrap.dedent(
            f"""
            import sys, time
            sys.path.insert(0, {str(Path(__file__).resolve().parents[1] / 'src')!r})
            from webpent.production.cross_process_leases import FileLeaseBackend
            backend = FileLeaseBackend({str(lease_dir)!r}, max_global=1, max_per_target=1)
            assert backend.try_acquire_slots("child-c1", {T_A!r})
            with open({str(tmp_path / 'holder_ready.txt')!r}, "w") as fh:
                fh.write("ready")
            while not __import__("os").path.exists({str(release_signal)!r}):
                time.sleep(0.05)
            backend.release_slots("child-c1", {T_A!r})
            print("RELEASED", flush=True)
            """
        )
        signal_path = tmp_path / "holder_ready.txt"
        proc = subprocess.Popen(
            [sys.executable, "-c", child],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(tmp_path),
        )
        try:
            deadline = time.time() + 15
            while time.time() < deadline and not signal_path.exists():
                assert proc.poll() is None, f"child died rc={proc.returncode}"
                time.sleep(0.05)
            assert signal_path.exists(), "child never became ready"
            parent = FileLeaseBackend(lease_dir, max_global=1, max_per_target=1)
            assert parent.try_acquire_slots("parent-c1", T_A) is False
            release_signal.write_text("go")
            deadline = time.time() + 10
            acquired = False
            while time.time() < deadline and not acquired:
                acquired = parent.try_acquire_slots("parent-c1", T_A)
                if not acquired:
                    time.sleep(0.1)
            assert acquired, "clean release did not free the slot"
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=10)


class TestGovernorIntegration:
    def test_backend_none_preserves_phase1_behavior(self, lease_dir):
        gov = ConcurrencyGovernor(max_global=1, max_per_target=1, lease_backend=None)
        ticket = gov.try_acquire("c1", T_A)
        assert ticket is not None
        gov.release(ticket)

    def test_two_governors_share_caps_via_backend(self, lease_dir):
        """Two governor instances + one shared backend = cross-process
        semantics without spawning processes (same files, same flocks)."""
        shared = FileLeaseBackend(lease_dir, max_global=1, max_per_target=1)
        gov1 = ConcurrencyGovernor(max_global=1, max_per_target=1, lease_backend=shared)
        gov2 = ConcurrencyGovernor(max_global=1, max_per_target=1, lease_backend=shared)
        t1 = gov1.try_acquire("c1", T_A)
        assert t1 is not None
        # gov2 has local capacity but NO shared slots left.
        assert gov2.try_acquire("c2", T_B) is None
        # Release frees both layers → gov2 admitted.
        gov1.release(t1)
        t2 = gov2.try_acquire("c2", T_A)
        assert t2 is not None
        gov2.release(t2)

    def test_local_cap_rolls_back_backend_slots(self, lease_dir):
        """Local caps checked first; a local refusal must not consume
        shared slots (all-or-nothing across both layers)."""
        backend = FileLeaseBackend(lease_dir, max_global=2, max_per_target=1)
        gov = ConcurrencyGovernor(max_global=1, max_per_target=1, lease_backend=backend)
        t1 = gov.try_acquire("c1", T_A)
        assert t1 is not None
        assert gov.try_acquire("c2", T_B) is None  # local global cap hit
        # Shared backend untouched: a fresh governor with same backend
        # still has BOTH global slots available for another target key.
        probe = FileLeaseBackend(lease_dir, max_global=2, max_per_target=1)
        assert probe.try_acquire_slots("probe", "https://other.example.com/") is True

    def test_blocking_acquire_waits_for_shared_slots(self, lease_dir):
        import threading

        backend = FileLeaseBackend(lease_dir, max_global=1, max_per_target=1)
        gov1 = ConcurrencyGovernor(max_global=1, max_per_target=1, lease_backend=backend)
        gov2 = ConcurrencyGovernor(max_global=1, max_per_target=1, lease_backend=backend)
        t1 = gov1.try_acquire("c1", T_A)
        assert t1 is not None
        result: dict[str, object] = {}

        def waiter():
            try:
                ticket = gov2.acquire("c2", T_A, timeout=10.0)
                result["ticket"] = ticket
            except Exception as exc:  # noqa: BLE001
                result["error"] = exc

        thread = threading.Thread(target=waiter, daemon=True)
        thread.start()
        time.sleep(0.4)
        gov1.release(t1)
        thread.join(timeout=15)
        assert isinstance(result.get("ticket"), object) and "error" not in result
        ticket = result["ticket"]
        gov2.release(ticket)  # type: ignore[arg-type]

    def test_fail_open_when_backend_errors(self, lease_dir):
        class ExplodingBackend:
            def try_acquire_slots(self, campaign_id: str, target_key: str) -> bool:
                raise RuntimeError("backend down")

            def release_slots(self, campaign_id: str, target_key: str) -> None:
                raise RuntimeError("backend down")

        gov = ConcurrencyGovernor(
            max_global=1, max_per_target=1, lease_backend=ExplodingBackend()
        )
        # Availability over strictness: admission fails OPEN.
        ticket = gov.try_acquire("c1", T_A)
        assert ticket is not None
        gov.release(ticket)  # must not raise despite backend errors

    def test_snapshot_includes_cross_process_view(self, lease_dir):
        backend = FileLeaseBackend(lease_dir, max_global=1, max_per_target=1)
        gov = ConcurrencyGovernor(max_global=1, max_per_target=1, lease_backend=backend)
        ticket = gov.try_acquire("c1", T_A)
        assert ticket is not None
        snap = gov.snapshot().as_dict()
        assert "cross_process" in snap
        assert snap["cross_process"]["global_slots_active"] == 1
        gov.release(ticket)
