"""CEM Longitudinal Memory — the temporal lessons ledger (v83, U-CEM-8).

Lessons ("on this target, JWT secrets rotate on Mondays") live for a
bounded time and carry a strength: confirmation strengthens, refutation
weakens, and a lesson that decays below the retirement threshold leaves
the ledger. Lessons can carry a seasonal hint (a month) so that when the
same season returns, the lesson is boosted and the operator sees an
intensified-monitoring suggestion. All time is injected; the ledger is
advisory ranking context only — it never promotes or suppresses evidence.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from typing import Any

from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

TTL_DAYS = 90.0
RETIRE_BELOW = 0.3
DEFAULT_STRENGTH = 0.5
SEASONAL_BOOST = 0.2
MAX_LESSONS = 128
MAX_STRENGTH = 1.0
MAX_TEXT = 200


def _month_of(now: float) -> int:
    return datetime.fromtimestamp(float(now), tz=timezone.utc).month


def _age_days(now: float, born: float) -> float:
    return max(0.0, (float(now) - float(born)) / 86400.0)


class TemporalLessons:
    """Bounded, decaying, season-aware lesson ledger. Advisory only."""

    def __init__(self, persist_path: Any) -> None:
        self._path = persist_path
        self._lessons: dict[str, dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError, AttributeError):
            self._lessons = {}
            return
        if not isinstance(raw, dict):
            self._lessons = {}
            return
        kept: dict[str, dict[str, Any]] = {}
        for lesson_id, record in list(raw.items())[:MAX_LESSONS]:
            if isinstance(lesson_id, str) and isinstance(record, dict):
                kept[lesson_id[:120]] = record
        self._lessons = kept

    def save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=str(self._path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(self._lessons, handle, indent=2, ensure_ascii=False)
                os.replace(tmp_name, self._path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
                raise
        except (OSError, AttributeError) as exc:
            _LOG.warning("lessons save failed (memory stays in-process): %s", exc)

    def record_lesson(
        self,
        *,
        target_id: str,
        lesson: str,
        vuln_class: str = "",
        month_hint: int | None = None,
        now: float,
    ) -> dict[str, Any]:
        """Add (or idempotently refresh) one lesson; strength 0.5 at birth."""
        target_id = redact(str(target_id or ""))[:120]
        text = redact(str(lesson or ""))[:MAX_TEXT]
        if not target_id or not text:
            return {}
        lesson_id = f"{target_id}:{text[:80]}"
        existing = self._lessons.get(lesson_id)
        if existing is not None:
            existing["last_seen"] = float(now)
            existing["strength"] = min(
                MAX_STRENGTH, float(existing.get("strength") or DEFAULT_STRENGTH) + 0.05
            )
            self.save()
            return dict(existing)
        record = {
            "target_id": target_id,
            "lesson": text,
            "vuln_class": redact(str(vuln_class or ""))[:80],
            "month_hint": int(month_hint) if isinstance(month_hint, int)
            and 1 <= month_hint <= 12 else None,
            "strength": DEFAULT_STRENGTH,
            "born": float(now),
            "last_seen": float(now),
        }
        self._lessons[lesson_id] = record
        if len(self._lessons) > MAX_LESSONS:
            oldest = min(self._lessons, key=lambda k: self._lessons[k].get("last_seen", 0))
            self._lessons.pop(oldest)
        self.save()
        return dict(record)

    def strengthen(self, lesson_id: str, *, amount: float = 0.1) -> bool:
        """Confirmation: strength up, capped at 1.0."""
        record = self._lessons.get(str(lesson_id)[:120])
        if record is None:
            return False
        record["strength"] = min(
            MAX_STRENGTH, float(record.get("strength") or 0) + max(0.0, amount)
        )
        self.save()
        return True

    def weaken(self, lesson_id: str, *, amount: float = 0.2) -> bool:
        """Refutation: strength down; the next reap retires it if low."""
        record = self._lessons.get(str(lesson_id)[:120])
        if record is None:
            return False
        record["strength"] = max(0.0, float(record.get("strength") or 0) - max(0.0, amount))
        self.save()
        return True

    def reap(self, *, now: float) -> list[str]:
        """Drop TTL-expired and sub-threshold lessons; returns their ids.

        A lesson in its hinted month is shielded from threshold retirement
        (the seasonal boost is exactly why it deserves the wait); TTL expiry
        is absolute and retires even a seasonal lesson.
        """
        now = float(now)
        retired: list[str] = []
        for lesson_id, record in list(self._lessons.items()):
            expired = _age_days(now, record.get("born", now)) > TTL_DAYS
            in_season = (
                isinstance(record.get("month_hint"), int)
                and record["month_hint"] == _month_of(now)
            )
            weak = float(record.get("strength") or 0) < RETIRE_BELOW
            if expired or (weak and not in_season):
                retired.append(lesson_id)
                self._lessons.pop(lesson_id)
        if retired:
            self.save()
        return retired

    def effective_strength(self, record: dict[str, Any], *, now: float) -> float:
        """Strength with the seasonal boost applied in the hinted month."""
        strength = max(0.0, min(MAX_STRENGTH, float(record.get("strength") or 0)))
        hint = record.get("month_hint")
        if isinstance(hint, int) and hint == _month_of(now):
            return min(MAX_STRENGTH, strength + SEASONAL_BOOST)
        return strength

    def lessons_for(self, target_id: str, *, now: float) -> list[dict[str, Any]]:
        """Advisory lessons for a target, strongest first, seasonal marked."""
        target_id = redact(str(target_id or ""))[:120]
        now = float(now)
        entries: list[dict[str, Any]] = []
        for lesson_id, record in self._lessons.items():
            if record.get("target_id") != target_id:
                continue
            if _age_days(now, record.get("born", now)) > TTL_DAYS:
                continue  # a TTL-expired lesson is dead even before a reap
            entry = dict(record)
            entry["lesson_id"] = lesson_id[:120]
            entry["effective_strength"] = self.effective_strength(record, now=now)
            entry["seasonal"] = (
                isinstance(record.get("month_hint"), int)
                and record["month_hint"] == _month_of(now)
            )
            entry["age_days"] = round(_age_days(now, record.get("born", now)), 1)
            entries.append(entry)
        entries.sort(key=lambda e: e["effective_strength"], reverse=True)
        return entries[:MAX_LESSONS]

    def seasonal_watchlist(self, *, now: float) -> list[str]:
        """Targets whose seasonal lessons are live this month: watch closer."""
        now = float(now)
        targets = {
            record.get("target_id")
            for record in self._lessons.values()
            if isinstance(record.get("month_hint"), int)
            and record["month_hint"] == _month_of(now)
            and self.effective_strength(record, now=now) >= RETIRE_BELOW
        }
        return sorted(str(t) for t in targets if t)[:MAX_LESSONS]

    def count(self) -> int:
        return len(self._lessons)


__all__ = [
    "DEFAULT_STRENGTH",
    "MAX_LESSONS",
    "RETIRE_BELOW",
    "SEASONAL_BOOST",
    "TTL_DAYS",
    "TemporalLessons",
]
