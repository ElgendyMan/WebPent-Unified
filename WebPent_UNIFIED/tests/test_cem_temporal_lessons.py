"""v83 T8 / U-CEM-8: the temporal lessons ledger."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from webpent.autonomous.cem.temporal_lessons import (
    DEFAULT_STRENGTH,
    TTL_DAYS,
    TemporalLessons,
)

NOW = datetime(2023, 11, 14, 12, tzinfo=timezone.utc).timestamp()  # month 11


def _ts(y: int, m: int, d: int) -> float:
    return datetime(y, m, d, 12, tzinfo=timezone.utc).timestamp()


def _ledger(tmp_path: Path) -> TemporalLessons:
    return TemporalLessons(tmp_path / "lessons.json")


def test_record_and_retrieve_per_target(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    out = ledger.record_lesson(
        target_id="t1", lesson="JWT rotates Mondays", vuln_class="auth", now=NOW
    )
    assert out["strength"] == DEFAULT_STRENGTH
    lessons = ledger.lessons_for("t1", now=NOW)
    assert lessons[0]["lesson"] == "JWT rotates Mondays"
    assert ledger.lessons_for("other", now=NOW) == []
    assert ledger.count() == 1


def test_duplicate_record_is_idempotent_refresh(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    ledger.record_lesson(target_id="t1", lesson="same lesson", now=NOW)
    again = ledger.record_lesson(target_id="t1", lesson="same lesson", now=NOW + 3600)
    assert ledger.count() == 1
    assert again["strength"] == DEFAULT_STRENGTH + 0.05
    assert again["last_seen"] == NOW + 3600


def test_strengthen_and_weaken_bounds(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    ledger.record_lesson(target_id="t1", lesson="L", now=NOW)
    lesson_id = ledger.lessons_for("t1", now=NOW)[0]["lesson_id"]
    assert ledger.strengthen(lesson_id, amount=0.4)
    assert ledger.strengthen(lesson_id, amount=99)  # capped at 1.0
    assert ledger.lessons_for("t1", now=NOW)[0]["strength"] == 1.0
    assert ledger.weaken(lesson_id, amount=0.85)
    assert ledger.lessons_for("t1", now=NOW)[0]["strength"] == __import__("pytest").approx(0.15)
    assert not ledger.strengthen("ghost")


def test_weak_lessons_retire_on_reap(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    ledger.record_lesson(target_id="t1", lesson="weak one", now=NOW)
    lesson_id = ledger.lessons_for("t1", now=NOW)[0]["lesson_id"]
    ledger.weaken(lesson_id, amount=0.25)  # 0.5 - 0.25 = 0.25 < 0.3
    retired = ledger.reap(now=NOW + 60)
    assert retired == [lesson_id]
    assert ledger.count() == 0


def test_ttl_expiry_after_90_days(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    ledger.record_lesson(target_id="t1", lesson="old lesson", now=NOW)
    alive = ledger.reap(now=NOW + (TTL_DAYS - 1) * 86400)
    assert alive == []
    gone = ledger.reap(now=NOW + (TTL_DAYS + 1) * 86400)
    assert len(gone) == 1
    assert ledger.count() == 0


def test_seasonal_boost_and_watchlist(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    ledger.record_lesson(target_id="t1", lesson="year-end freeze", month_hint=11, now=NOW)
    ledger.record_lesson(target_id="t2", lesson="summer lull", month_hint=6, now=NOW)
    lessons = ledger.lessons_for("t1", now=NOW)
    assert lessons[0]["seasonal"] is True
    assert lessons[0]["effective_strength"] == DEFAULT_STRENGTH + 0.2
    other = ledger.lessons_for("t2", now=NOW)
    assert other[0]["seasonal"] is False
    assert other[0]["effective_strength"] == DEFAULT_STRENGTH
    assert ledger.seasonal_watchlist(now=NOW) == ["t1"]


def test_ledger_bounded_at_max(tmp_path: Path) -> None:
    from webpent.autonomous.cem.temporal_lessons import MAX_LESSONS

    ledger = _ledger(tmp_path)
    for i in range(MAX_LESSONS + 10):
        ledger.record_lesson(target_id=f"t{i}", lesson=f"lesson {i}", now=NOW + i)
    assert ledger.count() == MAX_LESSONS


def test_garbage_lessons_never_stored(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    assert ledger.record_lesson(target_id="", lesson="x", now=NOW) == {}
    assert ledger.record_lesson(target_id="t1", lesson="", now=NOW) == {}
    record = ledger.record_lesson(target_id="t1", lesson="ok", month_hint=99, now=NOW)
    assert record["month_hint"] is None
    assert ledger.count() == 1


def test_roundtrip_and_corruption(tmp_path: Path) -> None:
    path = tmp_path / "lessons.json"
    ledger = TemporalLessons(path)
    ledger.record_lesson(target_id="t1", lesson="persisted", now=NOW)
    assert TemporalLessons(path).count() == 1

    path.write_text("junk", encoding="utf-8")
    assert TemporalLessons(path).count() == 0


def test_reap_spares_weak_lesson_in_its_seasonal_month(tmp_path):
    """RT83-5: a seasonally-live weak lesson survives threshold retirement in-season."""
    tl = TemporalLessons(tmp_path / "lessons.json")
    tl.record_lesson(target_id="t.example", lesson="JWT rotates Mondays",
                     month_hint=10, now=_ts(2023, 10, 1))
    lesson_id = next(iter(tl._lessons))
    tl.weaken(lesson_id, amount=0.5)  # strength 0.0 < RETIRE_BELOW
    retired = tl.reap(now=_ts(2023, 10, 15))  # October = the hinted month
    assert retired == []
    assert tl.count() == 1


def test_reap_still_retires_weak_lesson_out_of_season(tmp_path):
    tl = TemporalLessons(tmp_path / "lessons.json")
    tl.record_lesson(target_id="t.example", lesson="JWT rotates Mondays",
                     month_hint=5, now=0.0)
    lesson_id = next(iter(tl._lessons))
    tl.weaken(lesson_id, amount=0.5)
    retired = tl.reap(now=_ts(2023, 10, 15))  # May is long gone
    assert retired == [lesson_id]


def test_reap_ttl_still_applies_to_seasonal_lessons(tmp_path):
    """TTL expiry is absolute: even an in-season lesson dies at TTL."""
    tl = TemporalLessons(tmp_path / "lessons.json")
    tl.record_lesson(target_id="t.example", lesson="Seasonal lesson",
                     month_hint=10, now=0.0)
    retired = tl.reap(now=_ts(2023, 10, 15))  # in-season but past TTL
    assert len(retired) == 1


def test_seasonal_watchlist_uses_effective_strength(tmp_path):
    """A weak-but-seasonal lesson is lifted onto the watchlist by its boost."""
    tl = TemporalLessons(tmp_path / "lessons.json")
    tl.record_lesson(target_id="t.example", lesson="Deploy windows shift",
                     month_hint=10, now=0.0)
    lesson_id = next(iter(tl._lessons))
    tl.weaken(lesson_id, amount=0.3)  # raw 0.2 < RETIRE_BELOW; +0.2 seasonal = 0.4
    assert tl.seasonal_watchlist(now=_ts(2023, 10, 15)) == ["t.example"]


def test_lessons_for_hides_ttl_expired(tmp_path):
    """lessons_for never lists a lesson past its TTL, even before a reap."""
    tl = TemporalLessons(tmp_path / "lessons.json")
    tl.record_lesson(target_id="t.example", lesson="Old lesson", now=0.0)
    entries = tl.lessons_for("t.example", now=_ts(2024, 6, 1))
    assert entries == []
