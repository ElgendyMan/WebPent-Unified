# src/webpent/autonomous/cem/notification_bridge.py
"""CEM watch changes -> the user-chosen notification channel (0.26.0).

Track 11.1 residual wiring: the audit found the CEM watchtower fully
built (cycle, diff, digest, reactor) but its alerts "lived and died in
digest files" — ``vip/notifications`` channels (user-chosen webhook /
local JSONL inbox) were never fed by asset monitoring, so an operator
who configured a channel still had to open the daily digest to learn a
CRITICAL change happened.

This bridge is the one-way hop:

* input: one CEM cycle report (its ``changes`` entries carry a
  ``classification`` of noise/signal-low/signal-high/critical),
* filter: only ``critical`` and ``signal-high`` changes become alerts
  (noise stays in the digest; the channel is for the operator's
  attention, not a firehose),
* redaction: every string passes ``hunt_contracts.redact`` (the same
  function the CEM digest uses) before it leaves the process,
* dispatch: ``ConfirmationNotifier.notify_operational_alert`` — the
  same bounded queue, idempotency registry, severity threshold, and
  disabled-by-default posture as finding confirmations. Nothing here is
  enabled unless the operator configured a channel.

Advisory only: the bridge never mutates CEM state, never starts a
campaign, and every failure degrades to ``False`` + a log line.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from webpent.autonomous.hunt_contracts import redact
from webpent.vip.notifications import ConfirmationNotifier

logger = logging.getLogger(__name__)

__all__ = ["notify_cem_changes", "ALERT_CLASSIFICATIONS"]

#: Change classifications worth an operator ping (digest stays the
#: complete record; the channel is the highlight reel).
ALERT_CLASSIFICATIONS = frozenset({"critical", "signal-high"})

_SUMMARY_MAX = 200


def _change_summary(change: dict[str, Any]) -> str:
    """One bounded redacted line for the alert summary."""
    kind = str(change.get("kind") or "change")
    host = str(change.get("host") or change.get("target_id") or "unknown-host")
    note = str(change.get("note") or change.get("detail") or "")
    line = f"CEM {kind} on {host}"
    if note:
        line += f" — {note}"
    return redact(line)[:_SUMMARY_MAX]


def notify_cem_changes(
    report: dict[str, Any],
    notifier: ConfirmationNotifier,
) -> int:
    """Push alert-worthy CEM changes to the channel; return count enqueued.

    ``report`` is a ``run_cem_cycle`` result (or any dict with a
    ``changes`` list of mapping entries). Malformed shapes contribute
    zero alerts — a digest-format drift must never raise here.
    """
    if not isinstance(report, dict) or not notifier.enabled:
        return 0
    changes = report.get("changes")
    if not isinstance(changes, list):
        return 0
    enqueued = 0
    for change in changes[:50]:  # bounded: a channel is not a digest
        if not isinstance(change, dict):
            continue
        classification = str(change.get("classification") or "").strip().lower()
        if classification not in ALERT_CLASSIFICATIONS:
            continue
        summary = _change_summary(change)
        dedupe_key = hashlib.sha256(
            f"{classification}:{summary}".encode()
        ).hexdigest()
        ok = notifier.notify_operational_alert(
            event="cem_change_alert",
            severity="critical" if classification == "critical" else "high",
            summary=summary,
            redact_fn=redact,
            extra={
                "classification": classification,
                "host": str(change.get("host") or change.get("target_id") or ""),
                "kind": str(change.get("kind") or ""),
            },
            dedupe_key=dedupe_key,
        )
        if ok:
            enqueued += 1
    if enqueued:
        logger.info("cem notification bridge: enqueued %d alert(s)", enqueued)
    return enqueued
