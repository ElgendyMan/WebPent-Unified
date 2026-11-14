"""CEM Longitudinal Memory — the deployment rhythm detector (v83, U-CEM-9).

From a target's snapshot series (hash + injected timestamps only) the
detector builds a histogram of when the target tends to change: which
UTC hours and which weekdays see deployments. It also computes the
regression rate within a window after deploys, so the operator knows
whether "the day after a deploy" is when this target breaks. Pure
functions over injected data; nothing here observes anything itself.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

HOURS_IN_DAY = 24
DAYS_IN_WEEK = 7
DEFAULT_REGRESSION_WINDOW_HOURS = 24.0


def _utc(ts: float) -> datetime:
    return datetime.fromtimestamp(float(ts), tz=timezone.utc)


def detect_deploys(series: Any) -> list[float]:
    """Timestamps where the snapshot fingerprint changed.

    Garbage series degrades to empty. The first snapshot is not a deploy;
    only transitions count.
    """
    if not isinstance(series, (list, tuple)):
        return []
    deploys: list[float] = []
    previous_hash: str | None = None
    for entry in series[:512]:
        if not isinstance(entry, dict):
            continue
        ts = entry.get("ts")
        if not isinstance(ts, (int, float)):
            continue
        snapshot_hash = str(entry.get("hash") or "")
        if previous_hash is not None and snapshot_hash and snapshot_hash != previous_hash:
            deploys.append(float(ts))
        if snapshot_hash:
            previous_hash = snapshot_hash
    return deploys


def hour_histogram(deploys: Any) -> list[int]:
    """24 UTC-hour buckets; bounded input, garbage-safe."""
    histogram = [0] * HOURS_IN_DAY
    if not isinstance(deploys, (list, tuple)):
        return histogram
    for deploy in list(deploys)[:512]:
        try:
            histogram[_utc(deploy).hour] += 1
        except (TypeError, ValueError, OSError, OverflowError):
            continue
    return histogram


def day_histogram(deploys: Any) -> list[int]:
    """7 buckets, Monday=0 (Python weekday convention)."""
    histogram = [0] * DAYS_IN_WEEK
    if not isinstance(deploys, (list, tuple)):
        return histogram
    for deploy in list(deploys)[:512]:
        try:
            histogram[_utc(deploy).weekday()] += 1
        except (TypeError, ValueError, OSError, OverflowError):
            continue
    return histogram


def peak_hour(deploys: Any) -> int | None:
    histogram = hour_histogram(deploys)
    total = sum(histogram)
    if total == 0:
        return None
    return histogram.index(max(histogram))


def peak_day(deploys: Any) -> int | None:
    histogram = day_histogram(deploys)
    total = sum(histogram)
    if total == 0:
        return None
    return histogram.index(max(histogram))


def in_deploy_window(now: float, deploys: Any, *, tolerance_hours: int = 1) -> bool:
    """Is the injected time within +/- tolerance of the peak deploy hour?"""
    peak = peak_hour(deploys)
    if peak is None:
        return False
    hour = _utc(now).hour
    distance = min((hour - peak) % HOURS_IN_DAY, (peak - hour) % HOURS_IN_DAY)
    return distance <= max(0, int(tolerance_hours))


def regression_rate_after_deploys(
    deploys: Any,
    regression_times: Any,
    *,
    window_hours: float = DEFAULT_REGRESSION_WINDOW_HOURS,
) -> dict[str, Any]:
    """Fraction of deploys followed by a regression inside the window.

    Advisory context only: a high rate says "watch harder after deploys
    here", nothing more.
    """
    deploys_list = [float(d) for d in (deploys if isinstance(deploys, (list, tuple)) else [])][:512]
    regression_list = regression_times if isinstance(regression_times, (list, tuple)) else []
    regressions = [float(r) for r in regression_list][:512]
    window = max(0.0, float(window_hours)) * 3600.0
    if not deploys_list:
        return {
            "deploys": 0, "followed_by_regression": 0, "rate": 0.0, "window_hours": window / 3600.0,
        }
    followed = 0
    for deploy in deploys_list:
        if any(0 <= r - deploy <= window for r in regressions):
            followed += 1
    rate = followed / len(deploys_list)
    return {
        "deploys": len(deploys_list),
        "followed_by_regression": followed,
        "rate": round(rate, 3),
        "window_hours": window / 3600.0,
    }


def rhythm_report(series: Any, regression_times: Any = None) -> dict[str, Any]:
    """One bounded advisory summary of a target's deployment rhythm."""
    deploys = detect_deploys(series)
    rate = regression_rate_after_deploys(deploys, regression_times)
    peak = peak_hour(deploys)
    return {
        "deploys_observed": len(deploys),
        "hour_histogram": hour_histogram(deploys),
        "day_histogram": day_histogram(deploys),
        "peak_hour_utc": peak,
        "peak_day": peak_day(deploys),
        "regression_after_deploys": rate,
        "advisory": True,
    }


__all__ = [
    "DEFAULT_REGRESSION_WINDOW_HOURS",
    "detect_deploys",
    "hour_histogram",
    "day_histogram",
    "peak_hour",
    "peak_day",
    "in_deploy_window",
    "regression_rate_after_deploys",
    "rhythm_report",
]
