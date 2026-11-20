# tests/test_concurrency_governor.py
"""Track 12 item 2 (phase 1) — shared concurrency governor.

Covers: global/per-target caps, FIFO fairness (no starvation), release
promotion, timeout expiry, disabled limits (0), monitoring snapshot,
and the fail-open internal-error posture.
"""

from __future__ import annotations

import threading
import time

import pytest

from webpent.production.concurrency_governor import (
    AdmissionDenied,
    AdmissionTicket,
    ConcurrencyGovernor,
    _target_key,
)

T_A = "https://app.example.com/login"
T_B = "https://api.example.com/v2"
T_A2 = "https://app.example.com:8443/admin"  # same host, different port


class TestTargetKey:
    def test_host_normalization_case_insensitive(self):
        assert _target_key("https://APP.example.com/x") == _target_key("https://app.example.com/y")

    def test_port_makes_distinct_targets(self):
        assert _target_key(T_A) != _target_key(T_A2)

    def test_garbage_is_unknown(self):
        assert _target_key("") == "unknown"


class TestAdmission:
    def test_acquire_and_release_roundtrip(self):
        gov = ConcurrencyGovernor(max_global=1, max_per_target=1)
        ticket = gov.try_acquire("c1", T_A)
        assert ticket is not None
        gov.release(ticket)
        snap = gov.snapshot()
        assert snap.active_total == 0
        assert snap.admitted_total == 1

    def test_global_cap_rejected(self):
        gov = ConcurrencyGovernor(max_global=2, max_per_target=1)
        t1 = gov.try_acquire("c1", T_A)
        t2 = gov.try_acquire("c2", T_B)
        assert t1 is not None and t2 is not None
        assert gov.try_acquire("c3", T_A) is None  # global cap (2)
        assert gov.snapshot().rejected_total == 1

    def test_per_target_cap_same_target_denied_other_allowed(self):
        gov = ConcurrencyGovernor(max_global=10, max_per_target=1)
        t1 = gov.try_acquire("c1", T_A)
        assert t1 is not None
        assert gov.try_acquire("c2", T_A) is None  # same target
        t2 = gov.try_acquire("c2", T_B)
        assert t2 is not None  # different target OK
        assert gov.try_acquire("c3", T_A2) is not None  # port-differentiated OK

    def test_zero_limit_disables_cap(self):
        gov = ConcurrencyGovernor(max_global=0, max_per_target=0)
        tickets = [gov.try_acquire(f"c{i}", T_A) for i in range(5)]
        assert all(t is not None for t in tickets)
        assert gov.snapshot().active_total == 5

    def test_release_is_idempotent(self):
        gov = ConcurrencyGovernor(max_global=1, max_per_target=1)
        ticket = gov.try_acquire("c1", T_A)
        gov.release(ticket)
        gov.release(ticket)
        assert gov.snapshot().active_total == 0
        assert gov.try_acquire("c2", T_A) is not None

    def test_fail_open_on_internal_error(self, monkeypatch):
        gov = ConcurrencyGovernor(max_global=1, max_per_target=1)

        def _boom(*args, **kwargs):
            raise RuntimeError("internal")

        monkeypatch.setattr(gov, "_would_admit_locked", _boom)
        ticket = gov.try_acquire("c1", T_A)
        assert ticket is not None  # availability over strictness


class TestFairness:
    def test_fifo_no_starvation(self):
        gov = ConcurrencyGovernor(max_global=1, max_per_target=1)
        first = gov.try_acquire("c-active", T_A)
        assert first is not None

        order: list[str] = []
        gate = threading.Event()

        def _waiter(name: str) -> None:
            ticket = gov.acquire(name, T_A, timeout=10.0)
            order.append(name)
            gate.wait(timeout=5.0)
            gov.release(ticket)

        threads = [threading.Thread(target=_waiter, args=(f"c{i}",)) for i in range(4)]
        for t in threads:
            t.start()
            time.sleep(0.05)  # deterministic arrival order

        time.sleep(0.3)
        gov.release(first)
        # All four must eventually be granted, in FIFO order.
        deadline = time.monotonic() + 8.0
        while len(order) < 1 and time.monotonic() < deadline:
            time.sleep(0.05)
        gate.set()
        for t in threads:
            t.join(timeout=10.0)
        assert order == [f"c{i}" for i in range(4)]
        snap = gov.snapshot()
        assert snap.active_total == 0
        assert snap.admitted_total >= 5

    def test_acquire_timeout_raises_denied(self):
        gov = ConcurrencyGovernor(max_global=1, max_per_target=1)
        holder = gov.try_acquire("c-holder", T_A)
        assert holder is not None
        with pytest.raises(AdmissionDenied):
            gov.acquire("c-victim", T_A, timeout=0.1)
        gov.release(holder)

    def test_same_target_waiter_does_not_jump_queue(self):
        """Global free + per-target busy: waiting same-target stays queued."""
        gov = ConcurrencyGovernor(max_global=4, max_per_target=1)
        a1 = gov.try_acquire("c-a1", T_A)
        assert a1 is not None
        # Same target denied non-blocking...
        assert gov.try_acquire("c-a2", T_A) is None
        # ...and blocking acquire times out rather than bypassing the cap.
        with pytest.raises(AdmissionDenied):
            gov.acquire("c-a3", T_A, timeout=0.15)
        # Different target admits immediately even while one is waiting elsewhere.
        b1 = gov.try_acquire("c-b1", T_B)
        assert b1 is not None
        gov.release(a1)
        gov.release(b1)


class TestSnapshot:
    def test_snapshot_reflects_state_and_counters(self):
        gov = ConcurrencyGovernor(max_global=2, max_per_target=2)
        t1 = gov.try_acquire("c1", T_A)
        t2 = gov.try_acquire("c2", T_A)
        snap = gov.snapshot()
        assert snap.active_total == 2
        assert snap.active_by_target[_target_key(T_A)] == 2
        assert snap.admitted_total == 2
        gov.release(t1)
        gov.release(t2)
        assert gov.snapshot().active_total == 0

    def test_ticket_fields(self):
        gov = ConcurrencyGovernor(max_global=1, max_per_target=1)
        ticket = gov.try_acquire("c1", T_A)
        assert isinstance(ticket, AdmissionTicket)
        assert ticket.campaign_id == "c1"
        assert ticket.released is False
        gov.release(ticket)
        assert ticket.released is True


class TestSettingsSingleton:
    def test_settings_singleton_respects_limits(self, monkeypatch):
        from webpent.production import concurrency_governor as mod

        monkeypatch.setenv("WEBPENT_MAX_CONCURRENT_CAMPAIGNS", "3")
        monkeypatch.setenv("WEBPENT_MAX_CONCURRENT_PER_TARGET", "2")
        mod.reset_concurrency_governor()
        try:
            from webpent.config.settings import get_settings

            get_settings.cache_clear() if hasattr(get_settings, "cache_clear") else None
            gov = mod.get_concurrency_governor()
            assert gov.max_global == 3
            assert gov.max_per_target == 2
        finally:
            mod.reset_concurrency_governor()
