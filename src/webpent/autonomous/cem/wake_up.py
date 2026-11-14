"""CEM Reactor — the wake-up protocol (v83, U-CEM-7).

A CRITICAL change on a dormant target is worth a full campaign, not a
mini one: the protocol wakes the target with a full campaign budget,
safely clipped to what actually remains of the day (never negative, never
over the remaining), runs one bounded wake, and sends the target back to
dormancy. A per-target cooldown keeps a flapping target from being woken
in a loop. Advisory end to end: the scheduler still gates every request.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from typing import Any

from webpent.autonomous.cem.diff_engine import is_wake_up
from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

DEFAULT_COOLDOWN_HOURS = 24.0
MAX_WAKE_HISTORY = 32


class WakeUpProtocol:
    """Full-campaign wake on critical changes, then back to dormancy."""

    def __init__(
        self,
        persist_path: Any,
        *,
        daily_budget: int = 2000,
        cooldown_hours: float = DEFAULT_COOLDOWN_HOURS,
    ) -> None:
        self._path = persist_path
        self.daily_budget = max(1, int(daily_budget))
        self.cooldown_hours = max(0.0, float(cooldown_hours))
        self._wakes: list[dict[str, Any]] = []
        self.load()

    def load(self) -> None:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError, AttributeError):
            self._wakes = []
            return
        self._wakes = [w for w in raw if isinstance(w, dict)] if isinstance(raw, list) else []
        self._wakes = self._wakes[-MAX_WAKE_HISTORY:]

    def save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=str(self._path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(self._wakes[-MAX_WAKE_HISTORY:], handle, indent=2)
                os.replace(tmp_name, self._path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
                raise
        except (OSError, AttributeError) as exc:
            _LOG.warning("wake-up save failed (memory stays in-process): %s", exc)

    def evaluate(
        self,
        diff: dict[str, Any],
        *,
        now: float,
        remaining_budget: int,
    ) -> dict[str, Any] | None:
        """A wake decision, or None with the reason in ``refusal``."""
        now = float(now)
        if not isinstance(diff, dict) or not is_wake_up(diff):
            return None
        target_id = redact(str(diff.get("target_id") or ""))[:120]
        if not target_id:
            return None
        if self._on_cooldown(target_id, now):
            return {"refusal": "cooldown", "target_id": target_id, "advisory": True}
        remaining = max(0, int(remaining_budget))
        if remaining <= 0:
            return {"refusal": "no_remaining_budget", "target_id": target_id, "advisory": True}
        granted = min(self.daily_budget, remaining)
        return {
            "target_id": target_id,
            "kind": "wake_up",
            "budget": granted,
            "remaining_after": remaining - granted,
            "reason": redact(str(diff.get("top_signal") or ""))[:40],
            "advisory": True,
        }

    def apply(self, wake: dict[str, Any], *, now: float) -> dict[str, Any] | None:
        """Record a launched wake; returns the campaign record."""
        if not isinstance(wake, dict) or not wake.get("target_id") or wake.get("refusal"):
            return None
        record = {
            "target_id": redact(str(wake["target_id"]))[:120],
            "budget": max(0, int(wake.get("budget") or 0)),
            "launched_at": float(now),
            "cooled_until": float(now) + self.cooldown_hours * 3600.0,
            "advisory": True,
        }
        self._wakes.append(record)
        self._wakes = self._wakes[-MAX_WAKE_HISTORY:]
        self.save()
        return dict(record)

    def return_to_dormancy(self, target_id: str, *, now: float) -> bool:
        """Mark the wake closed; the cooldown keeps its protective window."""
        target_id = redact(str(target_id or ""))[:120]
        for wake in reversed(self._wakes):
            if wake.get("target_id") == target_id and not wake.get("closed"):
                wake["closed"] = True
                wake["closed_at"] = float(now)
                self.save()
                return True
        return False

    def _on_cooldown(self, target_id: str, now: float) -> bool:
        for wake in self._wakes:
            if wake.get("target_id") == target_id and float(wake.get("cooled_until") or 0) > now:
                return True
        return False

    def history(self) -> list[dict[str, Any]]:
        return [dict(w) for w in self._wakes]


__all__ = [
    "DEFAULT_COOLDOWN_HOURS",
    "MAX_WAKE_HISTORY",
    "WakeUpProtocol",
]
