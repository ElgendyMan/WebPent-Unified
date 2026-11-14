"""v83 T4 / U-CEM-4: the polite scheduler, kill switch, and brakes."""

from __future__ import annotations

import tempfile
from pathlib import Path

from webpent.autonomous.cem.scheduler import (
    KillSwitch,
    PoliteScheduler,
    is_active_hour,
    parse_active_hours,
)

NOON = 1_700_000_000.0  # a UTC day at 22:00 UTC actually; compute properly below
# 1700000000 -> 2023-11-14T22:13:20Z. Use hour-aware fixtures instead.


def _ts(hour: int, minute: int = 0) -> float:
    """UTC epoch for 2023-11-14 at HH:MM (deterministic, no real time)."""
    from datetime import datetime, timezone

    return datetime(2023, 11, 14, hour, minute, tzinfo=timezone.utc).timestamp()


def test_parse_active_hours_defaults_and_wrap() -> None:
    assert parse_active_hours("08:00-20:00") == (8, 20)
    assert parse_active_hours("22:00-06:00") == (22, 6)
    assert parse_active_hours(None) == (8, 20)
    assert parse_active_hours("garbage") == (8, 20)
    assert parse_active_hours("25:99-x") == (8, 20)


def test_is_active_hour_respects_window_and_wrap() -> None:
    assert is_active_hour(_ts(10), (8, 20))
    assert not is_active_hour(_ts(21), (8, 20))
    assert is_active_hour(_ts(23), (22, 6))
    assert is_active_hour(_ts(3), (22, 6))
    assert not is_active_hour(_ts(12), (22, 6))
    assert is_active_hour(_ts(10), (5, 5))  # degenerate means always


def test_scheduler_allows_within_hours_and_caps(tmp_path: Path) -> None:
    scheduler = PoliteScheduler(
        tmp_path / "sched.json", active_hours="08:00-20:00", daily_request_cap=100
    )
    ok = scheduler.allows(_ts(10), requested=10)
    assert ok["allowed"] and ok["granted"] == 10

    scheduler.record_spend(_ts(10), 95)
    partial = scheduler.allows(_ts(10), requested=10)
    assert partial["allowed"] and partial["granted"] == 5

    scheduler.record_spend(_ts(10), 5)
    capped = scheduler.allows(_ts(10), requested=10)
    assert not capped["allowed"] and capped["reason"] == "daily_cap_reached"


def test_day_rollover_resets_spend(tmp_path: Path) -> None:
    scheduler = PoliteScheduler(tmp_path / "sched.json", daily_request_cap=50)
    scheduler.record_spend(_ts(10), 50)
    assert not scheduler.allows(_ts(23), requested=1)["allowed"]
    # next UTC day
    from datetime import datetime, timezone

    next_day = datetime(2023, 11, 15, 10, tzinfo=timezone.utc).timestamp()
    assert scheduler.allows(next_day, requested=10)["allowed"]


def test_outside_active_hours_refuses(tmp_path: Path) -> None:
    scheduler = PoliteScheduler(tmp_path / "sched.json", active_hours="08:00-20:00")
    refusal = scheduler.allows(_ts(5))
    assert not refusal["allowed"] and refusal["reason"] == "outside_active_hours"


def test_kill_switch_is_immediate_and_persistent(tmp_path: Path) -> None:
    scheduler = PoliteScheduler(tmp_path / "sched.json")
    assert not scheduler.kill_switch.engaged()
    scheduler.kill_switch.engage(reason="operator halt", now=_ts(10))
    refusal = scheduler.allows(_ts(10))
    assert not refusal["allowed"] and refusal["reason"] == "kill_switch"

    # a fresh instance (restart) sees the engaged switch before anything else
    reloaded = PoliteScheduler(tmp_path / "sched.json")
    assert reloaded.kill_switch.engaged()
    assert reloaded.allows(_ts(10))["reason"] == "kill_switch"

    reloaded.kill_switch.disengage(now=_ts(11))
    assert PoliteScheduler(tmp_path / "sched.json").allows(_ts(11))["allowed"]


def test_kill_switch_corrupt_file_starts_disengaged(tmp_path: Path) -> None:
    (tmp_path / "kill.json").write_text("{broken", encoding="utf-8")
    switch = KillSwitch(tmp_path / "kill.json")
    assert not switch.engaged()
    switch.engage(reason="x", now=1.0)
    switch.save()
    assert KillSwitch(tmp_path / "kill.json").engaged()


def test_latency_brake_pauses_and_recovers(tmp_path: Path) -> None:
    scheduler = PoliteScheduler(tmp_path / "sched.json", latency_brake_seconds=2.0)
    assert scheduler.note_latency(_ts(10), 10.0) is None  # one sample is not enough
    assert scheduler.note_latency(_ts(10), 10.0) is None
    braked = scheduler.note_latency(_ts(10), 10.0)
    assert braked is not None and braked["paused_until"] > _ts(10)
    assert not scheduler.allows(_ts(11))["allowed"]
    assert scheduler.allows(_ts(11))["reason"] == "emergency_brake"

    from datetime import datetime, timezone

    after_cooldown = datetime(2023, 11, 14, 18, tzinfo=timezone.utc).timestamp()
    assert scheduler.allows(after_cooldown)["allowed"]


def test_scheduler_persistence_roundtrip_and_corruption(tmp_path: Path) -> None:
    scheduler = PoliteScheduler(tmp_path / "sched.json", daily_request_cap=100)
    scheduler.record_spend(_ts(10), 30)
    scheduler.emergency_brake(now=_ts(10), reason="test", hours=2)
    reloaded = PoliteScheduler(tmp_path / "sched.json")
    assert reloaded._spent_today(_ts(10)) == 30
    assert reloaded.allows(_ts(10))["reason"] == "emergency_brake"

    (tmp_path / "sched.json").write_text("nope", encoding="utf-8")
    broken = PoliteScheduler(tmp_path / "sched.json")
    assert broken.allows(_ts(10))["allowed"]


def test_scheduler_status_is_bounded_and_honest(tmp_path: Path) -> None:
    scheduler = PoliteScheduler(
        tmp_path / "sched.json", active_hours="08:00-20:00", daily_request_cap=10
    )
    scheduler.record_spend(_ts(10), 4)
    status = scheduler.status(_ts(10))
    assert status["kill_switch"] is False
    assert status["within_active_hours"] is True
    assert status["spent_today"] == 4
    assert status["daily_cap"] == 10


def test_note_latency_brake_hours_configurable():
    """RT83-7: the latency brake honours an explicit brake_hours."""
    sched = PoliteScheduler(Path(tempfile.mkdtemp()) / "sched.json")
    for _ in range(3):
        result = sched.note_latency(0.0, 900.0, brake_hours=1.0)
    assert result is not None
    assert result["paused_until"] == 3600.0
