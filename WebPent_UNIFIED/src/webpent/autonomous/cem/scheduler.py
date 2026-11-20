"""CEM Watchtower — the polite scheduler (v83, U-CEM-4).

The only pacing authority in CEM. It decides, for a proposed cycle at an
injected ``now``, whether the engagement's politeness contract allows
spending requests: active hours (UTC, wrap-around midnight supported), a
hard daily request cap with day rollover, a persistent kill switch that
takes effect in the same cycle it is engaged, and an emergency brake that
pauses the engagement when observed latency turns hostile.

Everything is advisory-of-execution in the CEM sense: the scheduler never
sends anything itself. It hands out or refuses a budget, and the cycle
respects the refusal. Time is injected; persistence is atomic JSON that
degrades to defaults on corruption.
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

DEFAULT_ACTIVE_HOURS = "08:00-20:00"
DEFAULT_DAILY_REQUEST_CAP = 2000
DEFAULT_MAX_REQUESTS_PER_CYCLE = 200
DEFAULT_LATENCY_BRAKE_SECONDS = 5.0
DEFAULT_BRAKE_COOLDOWN_HOURS = 6.0
MAX_LATENCY_SAMPLES = 32


def parse_active_hours(spec: Any) -> tuple[int, int]:
    """Parse "HH:MM-HH:MM" into (start, end) hours; wrap past midnight ok.

    ``"22:00-06:00"`` means active from 22:00 through 06:00 (wrapping).
    Garbage degrades to the default window. Only whole hours are kept.
    """
    default = (8, 20)
    if not isinstance(spec, str) or "-" not in spec:
        return default
    try:
        start_raw, end_raw = spec.split("-", 1)
        start = int(start_raw.strip().split(":")[0]) % 24
        end = int(end_raw.strip().split(":")[0]) % 24
    except (ValueError, IndexError):
        return default
    return (start, end)


def is_active_hour(now: float, active_hours: tuple[int, int]) -> bool:
    """Is the injected UTC time inside the active window?"""
    hour = datetime.fromtimestamp(float(now), tz=timezone.utc).hour
    start, end = active_hours
    if start == end:
        return True  # degenerate spec means "always"
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end  # wrap-around window


def _day_key(now: float) -> str:
    return datetime.fromtimestamp(float(now), tz=timezone.utc).strftime("%Y-%m-%d")


class KillSwitch:
    """Persistent, immediately-effective engagement stop.

    Engaged state survives restarts (atomic JSON) and is checked before
    every other permission in the scheduler. Nothing in CEM overrides it.
    """

    def __init__(self, persist_path: Any) -> None:
        self._path = persist_path
        self.state: dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self.state = {}
            return
        except (OSError, ValueError):
            _LOG.warning("kill switch file unreadable; starting disengaged: %s", self._path)
            self.state = {}
            return
        self.state = raw if isinstance(raw, dict) else {}

    def save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=str(self._path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(self.state, handle, indent=2)
                os.replace(tmp_name, self._path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
                raise
        except OSError as exc:
            _LOG.warning("kill switch save failed: %s", exc)

    def engage(self, *, reason: str, now: float) -> dict[str, Any]:
        self.state = {
            "engaged": True,
            "reason": redact(reason)[:200],
            "engaged_at": float(now),
        }
        self.save()
        return dict(self.state)

    def disengage(self, *, now: float) -> dict[str, Any]:
        self.state = {"engaged": False, "disengaged_at": float(now)}
        self.save()
        return dict(self.state)

    def engaged(self) -> bool:
        return bool(self.state.get("engaged"))

    def reason(self) -> str:
        return str(self.state.get("reason") or "")


class PoliteScheduler:
    """Budget authority: active hours, daily cap, brakes. Never a sender."""

    def __init__(
        self,
        persist_path: Any,
        *,
        active_hours: str = DEFAULT_ACTIVE_HOURS,
        daily_request_cap: int = DEFAULT_DAILY_REQUEST_CAP,
        max_requests_per_cycle: int = DEFAULT_MAX_REQUESTS_PER_CYCLE,
        latency_brake_seconds: float = DEFAULT_LATENCY_BRAKE_SECONDS,
    ) -> None:
        self._path = persist_path
        self.active_hours = parse_active_hours(active_hours)
        self.daily_request_cap = max(1, min(int(daily_request_cap), 1_000_000))
        self.max_requests_per_cycle = max(
            1, min(int(max_requests_per_cycle), self.daily_request_cap)
        )
        self.latency_brake_seconds = max(0.1, float(latency_brake_seconds))
        self._spend: dict[str, Any] = {}
        self._paused_until: float = 0.0
        self._pause_reason: str = ""
        self._latency_samples: list[float] = []
        self.kill_switch = KillSwitch(
            persist_path.parent / (persist_path.stem + "_kill.json")
            if hasattr(persist_path, "parent")
            else None
        )
        self.load()

    def load(self) -> None:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError, AttributeError):
            return
        if not isinstance(raw, dict):
            return
        spend = raw.get("spend")
        self._spend = spend if isinstance(spend, dict) else {}
        self._paused_until = float(raw.get("paused_until") or 0.0)
        self._pause_reason = str(raw.get("pause_reason") or "")

    def save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "spend": self._spend,
                "paused_until": self._paused_until,
                "pause_reason": self._pause_reason,
            }
            fd, tmp_name = tempfile.mkstemp(dir=str(self._path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2)
                os.replace(tmp_name, self._path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
                raise
        except (OSError, AttributeError) as exc:
            _LOG.warning("scheduler save failed (memory stays in-process): %s", exc)

    def allows(self, now: float, *, requested: int | None = None) -> dict[str, Any]:
        """May the cycle spend requests at this injected time?

        Checked in strict order: kill switch, emergency pause, active
        hours, daily cap. The first refusal wins and is explained.
        """
        now = float(now)
        wanted = min(
            max(1, int(requested or self.max_requests_per_cycle)),
            self.max_requests_per_cycle,
        )
        if self.kill_switch.engaged():
            return self._refusal(now, wanted, "kill_switch", self.kill_switch.reason())
        if self._paused_until > now:
            return self._refusal(now, wanted, "emergency_brake", self._pause_reason)
        if not is_active_hour(now, self.active_hours):
            window = f"active={self.active_hours[0]}:00-{self.active_hours[1]}:00 UTC"
            return self._refusal(now, wanted, "outside_active_hours", window)
        spent = self._spent_today(now)
        remaining = max(0, self.daily_request_cap - spent)
        if remaining <= 0:
            return self._refusal(now, wanted, "daily_cap_reached", f"cap={self.daily_request_cap}")
        granted = min(wanted, remaining)
        return {
            "allowed": True,
            "granted": granted,
            "reason": "ok",
            "spent_today": spent,
            "remaining_today": remaining - granted,
            "daily_cap": self.daily_request_cap,
        }

    def record_spend(self, now: float, requests: int) -> int:
        """Record actual spend; rolls the day key automatically."""
        day = _day_key(now)
        if self._spend.get("day") != day:
            self._spend = {"day": day, "requests": 0}
        self._spend["requests"] = int(self._spend.get("requests", 0)) + max(0, int(requests))
        self.save()
        return int(self._spend["requests"])

    def _spent_today(self, now: float) -> int:
        if self._spend.get("day") != _day_key(now):
            return 0
        return int(self._spend.get("requests", 0))

    def note_latency(
        self, now: float, seconds: float, *, brake_hours: float = DEFAULT_BRAKE_COOLDOWN_HOURS
    ) -> dict[str, Any] | None:
        """Feed one observed latency; brake when the target turns hostile.

        Keeps a small rolling window; when the mean crosses the threshold
        the engagement pauses for a cooldown (``brake_hours``, same default
        as :meth:`emergency_brake`). Pure w.r.t. injected time.
        """
        self._latency_samples.append(max(0.0, float(seconds)))
        self._latency_samples = self._latency_samples[-MAX_LATENCY_SAMPLES:]
        mean = sum(self._latency_samples) / len(self._latency_samples)
        if mean < self.latency_brake_seconds or len(self._latency_samples) < 3:
            return None
        self._paused_until = float(now) + max(0.0, brake_hours) * 3600.0
        self._pause_reason = f"latency mean {mean:.1f}s over threshold"
        self._latency_samples = []
        self.save()
        return {"paused_until": self._paused_until, "reason": self._pause_reason}

    def emergency_brake(
        self, *, now: float, reason: str, hours: float = DEFAULT_BRAKE_COOLDOWN_HOURS
    ) -> dict[str, Any]:
        self._paused_until = float(now) + max(0.0, hours) * 3600.0
        self._pause_reason = redact(reason)[:200]
        self.save()
        return {"paused_until": self._paused_until, "reason": self._pause_reason}

    def status(self, now: float) -> dict[str, Any]:
        now = float(now)
        return {
            "kill_switch": self.kill_switch.engaged(),
            "kill_reason": self.kill_switch.reason(),
            "paused": self._paused_until > now,
            "paused_until": self._paused_until,
            "pause_reason": self._pause_reason if self._paused_until > now else "",
            "active_hours": f"{self.active_hours[0]:02d}:00-{self.active_hours[1]:02d}:00 UTC",
            "within_active_hours": is_active_hour(now, self.active_hours),
            "spent_today": self._spent_today(now),
            "daily_cap": self.daily_request_cap,
            "max_per_cycle": self.max_requests_per_cycle,
        }

    @staticmethod
    def _refusal(now: float, wanted: int, reason: str, detail: str) -> dict[str, Any]:
        return {
            "allowed": False,
            "granted": 0,
            "reason": reason,
            "detail": detail,
            "requested": wanted,
            "at": now,
        }


__all__ = [
    "DEFAULT_ACTIVE_HOURS",
    "DEFAULT_DAILY_REQUEST_CAP",
    "DEFAULT_LATENCY_BRAKE_SECONDS",
    "KillSwitch",
    "PoliteScheduler",
    "is_active_hour",
    "parse_active_hours",
]
