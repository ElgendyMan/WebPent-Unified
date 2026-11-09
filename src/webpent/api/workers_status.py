# src/webpent/api/workers_status.py
"""webpent.api.workers_status

Ultimate plan 2026-10-27, proposal 9 — operational monitoring for the
Celery workers (``workers/pentest_worker.py``) that run pentest
engagements in parallel.

Self-contained router: ``app.py`` is NOT modified — the parent wires
``router`` into the FastAPI app later (``app.include_router(router)``).

Read-only by construction: nothing in this module starts, stops, or
requeues anything. Monitoring must never crash the API: every failure
path returns HTTP 200 with an HONEST body (``available: False`` plus a
reason) rather than a 5xx — an operator needs to know monitoring is
blind more than they need an error page.

Inspector injection: ``set_inspector(fn)`` installs a test/alternate
source of worker data (the callable returns the raw celery
``inspect().stats()`` / ``registered()`` shaped dict — see
:meth:`_normalise_inspector_result`). When no inspector is installed,
the route uses celery's own ``inspect()`` — but ONLY when celery is
importable AND a broker URL is explicitly configured
(``WEBPENT_REDIS_URL``); otherwise it reports ``available: False``
with reason ``"celery/broker not reachable"`` instead of pretending
(and without ever attempting a connection in the no-broker case, so
the endpoint stays fast and network-free in dev/test).

Status mapping (deterministic, documented):

  * worker present in ``stats`` WITH active tasks → ``"running"``;
  * present in ``stats`` with ZERO active tasks and NO heartbeat/clock
    key → ``"stalled"``;
  * missing from ``stats`` (e.g. only seen in ``registered``) →
    ``"failed"``.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

# F-05 (0.33.0): viewer-gate on both router routes.
from webpent.api.auth import User, require_viewer

logger = logging.getLogger(__name__)

__all__ = [
    "detect_stalled_workers",
    "get_inspector",
    "reset_inspector",
    "router",
    "set_inspector",
]

router = APIRouter(prefix="/api/v1/workers", tags=["workers"])

# Module-level inspector (injection point for tests / alternate
# backends). None -> the route falls back to celery inspect, but only
# when a broker is explicitly configured.
_INSPECTOR: Callable[[], dict[str, Any]] | None = None

# Narrow tuple for inspector/backend failures. Project governance
# forbids blanket ``except Exception``; anything outside this tuple is
# a programming error and should surface.
_INSPECTOR_FAILURE_EXCEPTIONS: tuple[type[BaseException], ...] = (
    ValueError,
    TypeError,
    RuntimeError,
    OSError,
    KeyError,
    AttributeError,
    TimeoutError,
)

_CELERY_INSPECT_TIMEOUT_S = 2.0
"""Short inspect timeout so a dead broker cannot hang the API route."""

_UNAVAILABLE_REASON = "celery/broker not reachable"

_MAX_WORKERS = 512
"""Documented cap on workers listed per response (bounding the table
and the response payload)."""


def set_inspector(inspector: Callable[[], dict[str, Any]] | None) -> None:
    """Install (or clear) the injected worker-data source.

    The inspector callable takes no arguments and returns the raw
    celery-shaped dict — either the wrapped form
    ``{"stats": {name: {...}}, "registered": {name: [...]}}`` or a
    bare stats-shaped mapping ``{name: {...}}`` (see
    :meth:`_normalise_inspector_result` for the exact contract).
    Passing ``None`` restores the default celery-inspect path.
    """
    global _INSPECTOR
    _INSPECTOR = inspector


def get_inspector() -> Callable[[], dict[str, Any]] | None:
    """Return the currently installed inspector (test visibility)."""
    return _INSPECTOR


def reset_inspector() -> None:
    """Clear the inspector (alias of ``set_inspector(None)``)."""
    set_inspector(None)


def _configured_broker_url() -> str:
    """Return the explicitly configured broker URL, or "".

    Only ``WEBPENT_REDIS_URL`` (the same variable
    ``workers/pentest_worker.py`` reads) counts as "configured": a
    broker the operator did not explicitly point at must not trigger a
    connection attempt from a monitoring route.
    """
    return os.environ.get("WEBPENT_REDIS_URL", "").strip()


def _celery_inspect_result() -> dict[str, Any]:
    """Collect the raw celery inspect view (never called without a broker).

    Builds a throwaway lightweight Celery app bound to the configured
    broker — deliberately NOT importing ``workers/pentest_worker.py``,
    whose import pulls the whole LangGraph builder and provider stack
    (far too heavy for a monitoring route).
    """
    from celery import Celery  # lazy: only imported when a broker exists.

    broker = _configured_broker_url()
    app = Celery("webpent-workers-status", broker=broker, backend=broker)
    app.conf.broker_connection_retry = False
    inspect = app.control.inspect(timeout=_CELERY_INSPECT_TIMEOUT_S)
    stats = inspect.stats() or {}
    registered = inspect.registered() or {}
    return {"stats": stats, "registered": registered}


def _active_count(entry: Any) -> int:
    """Count active tasks in one raw celery stats entry (bounded, forgiving)."""
    if not isinstance(entry, dict):
        return 0
    for key in ("active_engagements", "active_tasks", "active"):
        value = entry.get(key)
        if isinstance(value, (list, tuple)):
            return len(value)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return max(0, int(value))
    return 0


def _has_heartbeat(entry: Any) -> bool:
    """Whether a raw stats entry carries a heartbeat/clock signal."""
    if not isinstance(entry, dict):
        return False
    for key in ("heartbeat", "clock", "last_heartbeat", "heartbeats"):
        value = entry.get(key)
        if value is None or value == 0 or value is False:
            continue
        return True
    return False


def _started_seconds_ago(entry: Any, now: float) -> int | None:
    """Derive worker uptime in seconds from a raw stats entry (or None)."""
    if not isinstance(entry, dict):
        return None
    direct = entry.get("started_seconds_ago")
    if isinstance(direct, (int, float)) and not isinstance(direct, bool):
        return max(0, int(direct))
    started_at = entry.get("started_at")
    if isinstance(started_at, (int, float)) and not isinstance(started_at, bool):
        return max(0, int(now - float(started_at)))
    return None


def _normalise_inspector_result(raw: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Normalise an inspector result into ``(stats, registered)`` maps.

    Accepted shapes (both documented):

      * wrapped: ``{"stats": {name: entry}, "registered": {name: [...]}}``
        (the shape ``celery.control.inspect().stats()`` /
        ``.registered()`` produce, and the shape the built-in celery
        path returns);
      * bare stats-shaped mapping ``{name: entry}`` (a single-call
        inspector that only fetched stats).

    Non-dict values degrade to empty maps (honest emptiness, no crash).
    """
    if not isinstance(raw, dict):
        return {}, {}
    if "stats" in raw or "registered" in raw:
        stats = raw.get("stats")
        registered = raw.get("registered")
        return (
            stats if isinstance(stats, dict) else {},
            registered if isinstance(registered, dict) else {},
        )
    return raw, {}


def _map_workers(raw: Any) -> list[dict[str, Any]]:
    """Map a raw inspector result to the response worker entries.

    Mapping rules (see module docstring): active tasks → "running";
    zero active AND no heartbeat key → "stalled"; missing from stats
    → "failed". A name present in ``stats`` whose entry is not a dict
    (unparseable) is treated as an empty entry → "stalled" (present
    but showing no evidence of life — honest, never a crash). Output
    is bounded to ``_MAX_WORKERS`` entries.
    """
    stats, registered = _normalise_inspector_result(raw)
    now = time.time()
    names: list[str] = []
    for source in (stats, registered):
        for name in source.keys() if isinstance(source, dict) else ():
            if isinstance(name, str) and name not in names:
                names.append(name)
    workers: list[dict[str, Any]] = []
    for name in names[:_MAX_WORKERS]:
        if name not in stats:
            # Known (registered) but not reporting stats → failed.
            workers.append(
                {
                    "name": name,
                    "status": "failed",
                    "active_engagements": 0,
                    "started_seconds_ago": None,
                }
            )
            continue
        entry = stats.get(name)
        if not isinstance(entry, dict):
            entry = {}
        active = _active_count(entry)
        if active > 0 or _has_heartbeat(entry):
            status = "running"
        else:
            status = "stalled"
        workers.append(
            {
                "name": name,
                "status": status,
                "active_engagements": active,
                "started_seconds_ago": _started_seconds_ago(entry, now),
            }
        )
    return workers


def detect_stalled_workers(
    workers: list[dict[str, Any]],
    *,
    stalled_after_s: int = 900,
) -> list[str]:
    """Pure helper: names of workers that look stalled (alert path).

    A worker is reported stalled when ANY of:

      1. ``status == "stalled"`` — the status mapping already saw zero
         active engagements and no heartbeat/clock signal (alertable
         immediately: the inspector had no evidence of life);
      2. an explicit ``stalled_for_s`` field exceeds ``stalled_after_s``
         (when a producer can measure how long the stall has lasted);
      3. ``status == "running"`` with ZERO active engagements and an
         uptime (``started_seconds_ago``) beyond ``stalled_after_s`` —
         a conservative advisory proxy: a worker that has been up that
         long with nothing to do *may* have been idle the whole time.
         This can flag a healthy-but-idle worker; the alert is a
         WARNING for a human to check, never an enforcement action
         (documented honestly as a proxy).

    Args:
        workers: Worker entries shaped like the /status response
            (``{"name", "status", "active_engagements",
            "started_seconds_ago", ...}``). Malformed entries are
            skipped, never raised on.
        stalled_after_s: Stall threshold in seconds (default 900).

    Returns:
        The stalled worker names (order preserved, deduplicated).
    """
    stalled: list[str] = []
    for worker in workers or []:
        if not isinstance(worker, dict):
            continue
        name = worker.get("name")
        if not isinstance(name, str) or not name or name in stalled:
            continue
        status = worker.get("status")
        if status == "stalled":
            stalled.append(name)
            continue
        stalled_for = worker.get("stalled_for_s")
        if (
            isinstance(stalled_for, (int, float))
            and not isinstance(stalled_for, bool)
            and stalled_for > stalled_after_s
        ):
            stalled.append(name)
            continue
        active = worker.get("active_engagements", 0)
        uptime = worker.get("started_seconds_ago")
        if (
            status == "running"
            and not active
            and isinstance(uptime, (int, float))
            and not isinstance(uptime, bool)
            and uptime > stalled_after_s
        ):
            stalled.append(name)
    return stalled


def _unavailable_payload(reason: str, checked_at: str) -> dict[str, Any]:
    """Honest unavailable body (HTTP 200 — monitoring never crashes)."""
    return {
        "available": False,
        "workers": [],
        "checked_at": checked_at,
        "degraded_reason": reason,
        "reason": reason,
    }


def _endpoint_enabled() -> bool:
    """UM-DR-25: the operator visibility gate (fail-closed default off)."""
    from webpent.config.settings import get_settings

    return bool(getattr(get_settings(), "enable_worker_status_endpoint", False))


@router.get("/status")
def workers_status(
    user: User = Depends(require_viewer),  # F-05 (0.33.0): was anonymous
) -> dict[str, Any]:
    """Live worker status (read-only, never raises, always HTTP 200).

    F-05 (0.33.0): this route used to be registered WITHOUT an auth
    dependency — with ``auth_enabled=True`` an anonymous caller could
    enumerate Celery worker names, active-engagement counts and uptimes.
    It now requires viewer access (no-op when auth is disabled).

    UM-DR-25 (red-team window 2026-11-06): the operator visibility
    gate — ``enable_worker_status_endpoint`` (default False) hides the
    route family entirely (404) for operators who do not want worker
    names/counts exposed at all. Viewer auth AND the flag must both
    pass; fail-closed on either.

    Response shape::

        {
            "available": bool,
            "workers": [
                {
                    "name": str,
                    "status": "running" | "stalled" | "failed",
                    "active_engagements": int,
                    "started_seconds_ago": int | None,
                },
                ...
            ],
            "checked_at": iso-8601 UTC,
            "degraded_reason": str | None,
            "reason": str | None,  # same as degraded_reason when unavailable
        }
    """
    if not _endpoint_enabled():
        raise HTTPException(status_code=404, detail="worker_status_endpoint_disabled")
    checked_at = datetime.now(timezone.utc).isoformat()
    inspector = _INSPECTOR
    if inspector is not None:
        try:
            raw = inspector()
        except _INSPECTOR_FAILURE_EXCEPTIONS as exc:
            logger.warning("workers/status: injected inspector failed: %s", exc)
            return _unavailable_payload(
                f"inspector failed: {type(exc).__name__}: {exc}"[:200], checked_at
            )
        return {
            "available": True,
            "workers": _map_workers(raw),
            "checked_at": checked_at,
            "degraded_reason": None,
            "reason": None,
        }

    # Default path: celery inspect, only when explicitly configured.
    if not _configured_broker_url():
        return _unavailable_payload(_UNAVAILABLE_REASON, checked_at)
    try:
        raw = _celery_inspect_result()
    except ImportError:
        return _unavailable_payload(_UNAVAILABLE_REASON, checked_at)
    except _INSPECTOR_FAILURE_EXCEPTIONS as exc:
        logger.warning("workers/status: celery inspect failed: %s", exc)
        return _unavailable_payload(
            f"celery inspect failed: {type(exc).__name__}: {exc}"[:200], checked_at
        )
    if not isinstance(raw.get("stats"), dict) or not raw.get("stats"):
        # inspect().stats() returned nothing reachable — honest unavailable.
        return _unavailable_payload(_UNAVAILABLE_REASON, checked_at)
    return {
        "available": True,
        "workers": _map_workers(raw),
        "checked_at": checked_at,
        "degraded_reason": None,
        "reason": None,
    }


@router.get("/health")
def workers_health(
    user: User = Depends(require_viewer),  # F-05 (0.33.0): was anonymous
) -> dict[str, str]:
    """Liveness for the router itself (not the workers).

    Kept behind viewer access too (F-05): the container/Docker HEALTHCHECK
    probes the root ``/health`` (server.py), not this router-level route,
    so nothing operational breaks. UM-DR-25: also behind the operator
    visibility flag (404 when off) for the same reason — the container
    probe never touches this route.
    """
    if not _endpoint_enabled():
        raise HTTPException(status_code=404, detail="worker_status_endpoint_disabled")
    return {"status": "ok"}
