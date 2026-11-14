"""Tests for webpent.shared.global_rate_governor (Ultimate plan, proposal 6).

All tests run without Redis (duck-typed fakes) and without network.
"""

from __future__ import annotations

import threading
import time

import pytest

from webpent.shared.global_rate_governor import (
    GlobalRateGovernor,
    RateWindow,
    get_global_rate_governor,
    reset_global_rate_governor,
)


class FakeRedis:
    """Duck-typed in-memory stand-in for a redis client (get/set/incr)."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    def get(self, key: str):
        return self.store.get(key)

    def set(self, key: str, value) -> None:
        self.store[key] = str(value)

    def incr(self, key: str, amount: int = 1) -> int:
        current = int(self.store.get(key, "0")) + amount
        self.store[key] = str(current)
        return current


class BrokenRedis:
    """Every call raises AttributeError (misconfigured / half-mock client)."""

    def get(self, key: str):
        raise AttributeError("broken client: get")

    def set(self, key: str, value) -> None:
        raise AttributeError("broken client: set")

    def incr(self, key: str, amount: int = 1) -> int:
        raise AttributeError("broken client: incr")


# ---------------------------------------------------------------------------
# In-memory backend: caps
# ---------------------------------------------------------------------------


def test_memory_concurrency_cap_enforced() -> None:
    governor = GlobalRateGovernor(max_concurrent=2, requests_per_minute=100)
    assert governor.try_acquire("camp-a") is True
    assert governor.try_acquire("camp-b") is True
    assert governor.try_acquire("camp-c") is False  # cap of 2 reached


def test_memory_per_minute_budget_enforced() -> None:
    governor = GlobalRateGovernor(max_concurrent=10, requests_per_minute=3)
    assert governor.try_acquire("camp-a") is True
    assert governor.try_acquire("camp-a") is True
    assert governor.try_acquire("camp-a") is True
    assert governor.try_acquire("camp-a") is False  # budget of 3 exhausted


def test_memory_release_frees_the_slot() -> None:
    governor = GlobalRateGovernor(max_concurrent=2, requests_per_minute=100)
    assert governor.try_acquire("camp-a") is True
    assert governor.try_acquire("camp-b") is True
    assert governor.try_acquire("camp-c") is False
    governor.release("camp-a")
    assert governor.try_acquire("camp-c") is True


def test_memory_tokens_count_toward_the_concurrency_cap() -> None:
    governor = GlobalRateGovernor(max_concurrent=3, requests_per_minute=100)
    assert governor.try_acquire("camp-a", tokens=2) is True
    # 2 of 3 tokens held -> only one more single-token acquire fits.
    assert governor.try_acquire("camp-b") is True
    assert governor.try_acquire("camp-c") is False
    governor.release("camp-a")
    assert governor.try_acquire("camp-c") is True


def test_memory_release_unknown_campaign_is_a_noop() -> None:
    governor = GlobalRateGovernor()
    governor.release("never-acquired")  # must not raise
    assert governor.try_acquire("camp-a") is True


def test_invalid_campaign_ids_fail_closed() -> None:
    governor = GlobalRateGovernor()
    assert governor.try_acquire("") is False
    assert governor.try_acquire("a" * 500) is False  # > MAX_CAMPAIGN_ID_LENGTH
    assert governor.try_acquire("has,comma") is False  # breaks redis bookkeeping
    assert governor.try_acquire("camp", tokens="not-an-int") is False


# ---------------------------------------------------------------------------
# In-memory backend: window rollover
# ---------------------------------------------------------------------------


def test_memory_window_rollover_resets_request_counter(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = {"now": 1000.0}
    monkeypatch.setattr(time, "time", lambda: clock["now"])
    governor = GlobalRateGovernor(max_concurrent=10, requests_per_minute=2)
    assert governor.try_acquire("camp-a") is True
    assert governor.try_acquire("camp-a") is True
    assert governor.try_acquire("camp-a") is False  # window budget spent
    clock["now"] += 61.0  # a new 60s window opens
    assert governor.try_acquire("camp-a") is True
    snapshot = governor.snapshot()
    assert snapshot["requests_last_minute"] == 1


def test_memory_snapshot_shape() -> None:
    governor = GlobalRateGovernor(max_concurrent=7, requests_per_minute=42)
    governor.try_acquire("camp-a")
    snapshot = governor.snapshot()
    # UM-DR-34 §5.3: ``coordination_scope`` is a REQUIRED field — a
    # memory backend must be reported as "process-local" so callers can
    # never describe it as a globally coordinated multi-process limit.
    assert set(snapshot.keys()) == {
        "active_campaigns",
        "requests_last_minute",
        "max_concurrent",
        "requests_per_minute",
        "backend",
        "backend_degraded",
        "coordination_scope",
    }
    assert snapshot["active_campaigns"] == ["camp-a"]
    assert snapshot["coordination_scope"] == "process-local"
    assert snapshot["requests_last_minute"] == 1
    assert snapshot["max_concurrent"] == 7
    assert snapshot["requests_per_minute"] == 42
    assert snapshot["backend"] == "memory"
    assert snapshot["backend_degraded"] is False


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


def test_memory_thread_safety_smoke_ten_threads() -> None:
    governor = GlobalRateGovernor(max_concurrent=5, requests_per_minute=1000)
    grants: list[bool] = []
    lock = threading.Lock()

    def acquire(index: int) -> None:
        granted = governor.try_acquire(f"camp-{index}")
        with lock:
            grants.append(granted)

    threads = [threading.Thread(target=acquire, args=(i,)) for i in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    # Exactly the cap may be granted, no exception, no over-grant.
    assert len(grants) == 10
    assert sum(1 for g in grants if g) == 5
    assert len(governor.snapshot()["active_campaigns"]) == 5


# ---------------------------------------------------------------------------
# Redis backend (duck-typed fake — no real Redis anywhere)
# ---------------------------------------------------------------------------


def test_redis_backend_happy_path_and_snapshot() -> None:
    fake = FakeRedis()
    governor = GlobalRateGovernor(max_concurrent=2, requests_per_minute=5, redis_client=fake)
    assert governor.try_acquire("camp-a") is True
    assert governor.try_acquire("camp-b") is True
    snapshot = governor.snapshot()
    assert snapshot["backend"] == "redis"
    assert snapshot["backend_degraded"] is False
    assert sorted(snapshot["active_campaigns"]) == ["camp-a", "camp-b"]
    assert snapshot["requests_last_minute"] == 2


def test_redis_concurrency_cap_enforced() -> None:
    fake = FakeRedis()
    governor = GlobalRateGovernor(max_concurrent=2, requests_per_minute=100, redis_client=fake)
    assert governor.try_acquire("camp-a") is True
    assert governor.try_acquire("camp-b") is True
    assert governor.try_acquire("camp-c") is False
    assert fake.store["webpent:grg:concurrency"] == "2"  # rolled back to the cap
    governor.release("camp-a")
    assert governor.try_acquire("camp-c") is True


def test_redis_per_minute_budget_enforced_and_rollover(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 2000.0}
    monkeypatch.setattr(time, "time", lambda: clock["now"])
    fake = FakeRedis()
    governor = GlobalRateGovernor(max_concurrent=10, requests_per_minute=2, redis_client=fake)
    assert governor.try_acquire("camp-a") is True
    assert governor.try_acquire("camp-a") is True
    assert governor.try_acquire("camp-a") is False
    assert fake.store["webpent:grg:window_tokens"] == "2"  # rollback kept the cap
    clock["now"] += 61.0  # new window
    assert governor.try_acquire("camp-a") is True


def test_redis_backend_failure_degrades_gracefully() -> None:
    # A broken client must never break the governor: every call falls
    # back to the in-memory path and snapshots stay honest.
    governor = GlobalRateGovernor(
        max_concurrent=3, requests_per_minute=10, redis_client=BrokenRedis()
    )
    assert governor.try_acquire("camp-a") is True  # served by the memory fallback
    assert governor.try_acquire("camp-b") is True
    snapshot = governor.snapshot()
    assert snapshot["backend_degraded"] is True
    assert snapshot["backend"] == "memory"  # the data source is the fallback
    assert sorted(snapshot["active_campaigns"]) == ["camp-a", "camp-b"]
    governor.release("camp-a")  # must not raise either
    assert "camp-a" not in governor.snapshot()["active_campaigns"]


def test_redis_failure_never_leaks_exceptions_on_release() -> None:
    governor = GlobalRateGovernor(redis_client=BrokenRedis())
    governor.try_acquire("camp-a")
    governor.release("camp-a")  # degrades to memory release, no raise
    governor.release("camp-a")  # idempotent
    assert governor.snapshot()["backend_degraded"] is True


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------


def test_singleton_accessor_and_reset() -> None:
    reset_global_rate_governor()
    try:
        first = get_global_rate_governor()
        second = get_global_rate_governor()
        assert first is second
        assert isinstance(first, GlobalRateGovernor)
        assert first.snapshot()["backend"] == "memory"
        reset_global_rate_governor()
        third = get_global_rate_governor()
        assert third is not first
    finally:
        reset_global_rate_governor()


def test_rate_window_dataclass_fields() -> None:
    window = RateWindow(window_start=123.5, tokens=7)
    assert window.window_start == 123.5
    assert window.tokens == 7
