# src/webpent/shared/stealth.py
"""webpent.shared.stealth

V5 Sprint 6 — Stealth mode helpers (jitter + rate limiting).

When ``stealth_mode`` is enabled in the LangGraph state, the framework
needs to slow down its request pace to evade naive WAF / IDS rules that
flag bursty, machine-paced traffic. This module centralises:

  * :func:`apply_jitter` — synchronous random sleep used by tool wrappers
    (Nuclei, Dalfox, etc.) and the validator's OOB probes.
  * :func:`async_apply_jitter` — ``asyncio.sleep``-based variant for
    async code paths (FastAPI handlers, async graph nodes). Using
    ``time.sleep`` in an async context would block the event loop and
    stall every concurrent request — a serious regression.
  * :func:`enforce_min_interval` — per-host rate limiter that ensures
    successive requests to the same hostname are separated by at least
    ``stealth_min_request_interval`` seconds, regardless of the drawn
    jitter value.

All functions are NO-OPs when ``stealth_mode`` is False, so callers can
invoke them unconditionally without checking the flag.

Design notes:
  * The module reads ``Settings`` lazily via :func:`get_settings` so
    runtime env overrides are honoured even if the helpers are called
    before the settings singleton is fully initialised.
  * Per-host last-request timestamps are stored in a module-level dict
    keyed by hostname. This is intentionally simple — the framework runs
    one engagement per process, so cross-engagement isolation is not a
    concern. A lock guards the dict to stay safe under Celery workers.
"""

from __future__ import annotations

import asyncio
import logging
import random
import threading
import time
from urllib.parse import urlparse

from webpent.config.settings import get_settings

logger = logging.getLogger(__name__)

# Module-level per-host rate-limit registry. Keyed by hostname.
# Reads + writes are guarded by ``_rate_lock`` so concurrent Celery
# workers do not corrupt each other's timestamps.
_last_request_at: dict[str, float] = {}
_rate_lock = threading.Lock()
_telemetry_local = threading.local()


def _telemetry() -> dict[str, float]:
    state = getattr(_telemetry_local, "state", None)
    if state is None:
        state = {
            "jitter_calls": 0.0,
            "rate_limit_calls": 0.0,
            "jitter_sleep_seconds": 0.0,
            "rate_limit_sleep_seconds": 0.0,
        }
        _telemetry_local.state = state
    return state


def get_stealth_summary() -> dict[str, float | int]:
    """Return redaction-safe telemetry for the current worker thread."""
    state = _telemetry()
    jitter_sleep = state["jitter_sleep_seconds"]
    rate_sleep = state["rate_limit_sleep_seconds"]
    return {
        "jitter_calls": int(state["jitter_calls"]),
        "rate_limit_calls": int(state["rate_limit_calls"]),
        "jitter_sleep_seconds": round(jitter_sleep, 3),
        "rate_limit_sleep_seconds": round(rate_sleep, 3),
        "total_sleep_seconds": round(jitter_sleep + rate_sleep, 3),
    }


def reset_stealth_telemetry() -> None:
    """Reset current-thread telemetry; intended for scan boundaries and tests."""
    _telemetry_local.state = {
        "jitter_calls": 0.0,
        "rate_limit_calls": 0.0,
        "jitter_sleep_seconds": 0.0,
        "rate_limit_sleep_seconds": 0.0,
    }


def _draw_jitter_seconds() -> float:
    """Draw a random jitter duration from the configured range.

    Returns ``0.0`` if the range is degenerate (max <= min). The drawn
    value is clamped to ``[min, max]`` defensively even though
    ``random.uniform`` already stays within bounds — this protects
    against operator misconfiguration (min > max after env override).
    """
    settings = get_settings()
    lo = max(0.0, float(settings.stealth_jitter_min))
    hi = max(lo, float(settings.stealth_jitter_max))
    if hi <= 0.0:
        return 0.0
    return random.uniform(lo, hi)


def apply_jitter(stealth_mode: bool, *, label: str = "") -> float:
    """Synchronously sleep for a random jitter duration if stealth is on.

    Use this helper in synchronous code paths: tool wrappers
    (``run_nuclei``, ``run_dalfox``, …), the validator's OOB probe
    loop, and any other sync graph node.

    Args:
        stealth_mode: Whether stealth mode is enabled. When ``False``,
            the function returns immediately without sleeping.
        label: Optional human-readable tag included in the debug log
            line (e.g. ``"nuclei"``, ``"playwright-navigate"``) so
            operators can attribute delays in the log.

    Returns:
        The number of seconds actually slept (``0.0`` if stealth off).
    """
    if not stealth_mode:
        return 0.0
    _telemetry()["jitter_calls"] += 1.0
    delay = _draw_jitter_seconds()
    if delay <= 0.0:
        return 0.0
    logger.debug(
        "stealth jitter: sleeping %.2fs before %s", delay, label or "action"
    )
    time.sleep(delay)
    _telemetry()["jitter_sleep_seconds"] += delay
    return delay


async def async_apply_jitter(stealth_mode: bool, *, label: str = "") -> float:
    """Asynchronously sleep for a random jitter duration if stealth is on.

    Use this helper in async code paths: FastAPI handlers, async graph
    nodes, and any ``async def`` function. **Never** call
    :func:`apply_jitter` from an async context — ``time.sleep`` would
    block the event loop and stall every concurrent request.

    Args:
        stealth_mode: Whether stealth mode is enabled. When ``False``,
            the coroutine returns immediately without awaiting.
        label: Optional tag for the debug log line.

    Returns:
        The number of seconds actually awaited (``0.0`` if stealth off).
    """
    if not stealth_mode:
        return 0.0
    _telemetry()["jitter_calls"] += 1.0
    delay = _draw_jitter_seconds()
    if delay <= 0.0:
        return 0.0
    logger.debug(
        "stealth jitter: awaiting %.2fs before %s", delay, label or "action"
    )
    await asyncio.sleep(delay)
    _telemetry()["jitter_sleep_seconds"] += delay
    return delay


def enforce_min_interval(
    stealth_mode: bool,
    host: str,
    *,
    min_interval_override: float | None = None,
    jitter_max_override: float | None = None,
) -> float:
    """Ensure successive requests to ``host`` are spaced by the min interval.

    Synchronous variant. Records the current monotonic time for
    ``host`` and, if the previous request was less than
    ``stealth_min_request_interval`` seconds ago, sleeps for the
    remainder. Always updates the registry before returning.

    Args:
        stealth_mode: Whether stealth mode is enabled.
        host: Target hostname. Pass an empty string to skip (the
            caller could not parse the hostname).

    Returns:
        Seconds slept to satisfy the minimum interval (``0.0`` if none).
    """
    if not stealth_mode or not host:
        return 0.0
    _telemetry()["rate_limit_calls"] += 1.0
    settings = get_settings()
    min_interval = (
        float(min_interval_override)
        if min_interval_override is not None
        else float(settings.stealth_min_request_interval)
    )
    if min_interval <= 0.0:
        with _rate_lock:
            _last_request_at[host] = time.monotonic()
        return 0.0

    jitter_max = max(0.0, float(jitter_max_override or 0.0))
    with _rate_lock:
        last = _last_request_at.get(host)
        now = time.monotonic()
        wait = 0.0
        if last is not None:
            elapsed = now - last
            if elapsed < min_interval:
                wait = min_interval - elapsed
        jitter = random.uniform(0.0, jitter_max) if jitter_max > 0.0 else 0.0
        total_wait = wait + jitter
        _last_request_at[host] = now + total_wait

    if total_wait > 0.0:
        logger.debug(
            "stealth rate-limit: sleeping %.2fs for host %s", total_wait, host
        )
        time.sleep(total_wait)
    _telemetry()["rate_limit_sleep_seconds"] += total_wait
    return total_wait


async def async_enforce_min_interval(stealth_mode: bool, host: str) -> float:
    """Async variant of :func:`enforce_min_interval`.

    Uses ``asyncio.sleep`` so the event loop is not blocked while the
    rate-limit window elapses. The registry update is still synchronous
    (guarded by ``_rate_lock``) because the dict is shared across
    threads in the same process.
    """
    if not stealth_mode or not host:
        return 0.0
    _telemetry()["rate_limit_calls"] += 1.0
    settings = get_settings()
    min_interval = float(settings.stealth_min_request_interval)
    if min_interval <= 0.0:
        with _rate_lock:
            _last_request_at[host] = time.monotonic()
        return 0.0

    with _rate_lock:
        last = _last_request_at.get(host)
        now = time.monotonic()
        wait = 0.0
        if last is not None:
            elapsed = now - last
            if elapsed < min_interval:
                wait = min_interval - elapsed
        _last_request_at[host] = now + wait

    if wait > 0.0:
        logger.debug(
            "stealth rate-limit: awaiting %.2fs for host %s", wait, host
        )
        await asyncio.sleep(wait)
    _telemetry()["rate_limit_sleep_seconds"] += wait
    return wait


def extract_host(url: str) -> str:
    """Best-effort hostname extraction for rate-limit keying.

    Returns an empty string if the URL is malformed or has no host
    component — callers should pass the result directly to
    :func:`enforce_min_interval`, which treats empty host as a no-op.
    """
    try:
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""


def reset_rate_limits() -> None:
    """Clear the per-host rate-limit registry.

    Primarily intended for tests; production code should not call this.
    """
    with _rate_lock:
        _last_request_at.clear()
