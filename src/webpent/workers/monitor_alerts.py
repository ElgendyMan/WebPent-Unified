# src/webpent/workers/monitor_alerts.py
"""webpent.workers.monitor_alerts

Ultimate plan 2026-10-27, proposal 9 (Phase 3) — stalled-worker alerts.

Takes a ``/api/v1/workers/status`` response dict (produced by
``api/workers_status.py``), determines which workers look stalled via
the shared :func:`webpent.api.workers_status.detect_stalled_workers`
heuristic, and logs one WARNING per stalled worker. Pure and offline:
no network, no celery, no state — the caller decides when and how
often to poll (the plan's "simple alerts" phase deliberately keeps
this a log line for humans, not an enforcement action).
"""

from __future__ import annotations

import logging
from typing import Any

from webpent.api.workers_status import detect_stalled_workers

logger = logging.getLogger(__name__)

__all__ = ["check_stalled_and_alert"]

_ALERT_LINE_MAX_CHARS = 300
"""Alert lines are truncated (bounded everywhere — a worker name or
error text must never flood the log with unbounded content)."""


def check_stalled_and_alert(
    workers_status: dict[str, Any],
    *,
    log_fn: Any = None,
    stalled_after_s: int = 900,
) -> list[str]:
    """Detect stalled workers in a status payload and log a warning each.

    Args:
        workers_status: A ``/api/v1/workers/status`` response dict
            (``{"available": bool, "workers": [...]}``). When the
            payload says monitoring is unavailable or carries no
            worker list, the honest result is "no alerts" (empty
            list) — an alert cannot be more truthful than the data it
            is based on. Malformed payloads degrade the same way,
            never raise.
        log_fn: Optional injected log sink called once per alert line
            (``log_fn(line)``); defaults to
            ``logging.getLogger(__name__).warning``.
        stalled_after_s: Stall threshold in seconds forwarded to
            :func:`detect_stalled_workers` (default 900).

    Returns:
        The alert lines that were emitted (one per stalled worker),
        e.g. ``["worker 'celery@host1' stalled ..."]``.
    """
    if not isinstance(workers_status, dict):
        return []
    workers = workers_status.get("workers")
    if not isinstance(workers, list):
        return []

    stalled_names = detect_stalled_workers(
        [w for w in workers if isinstance(w, dict)],
        stalled_after_s=stalled_after_s,
    )

    alert_lines: list[str] = []
    for name in stalled_names:
        line = (
            f"worker '{name}' stalled (no active engagements and no "
            f"heartbeat for over {stalled_after_s}s) — check the "
            f"engagement it was running"
        )[:_ALERT_LINE_MAX_CHARS]
        alert_lines.append(line)
        if log_fn is not None:
            log_fn(line)
        else:
            logger.warning("%s", line)
    return alert_lines
