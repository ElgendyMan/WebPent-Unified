# src/webpent/safety/status_snapshot.py
"""Combined read-only status view for the worker dashboard
(2026-10-25 Proposal 10). Assembles kill-switch state, request-ledger
stats, and LLM spend counters in ONE flag-gated call, so the worker
status handler stays a few lines. Never raises.
"""
from __future__ import annotations

from typing import Any

__all__ = ["safety_snapshot"]


def safety_snapshot() -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        from webpent.safety import kill_switch

        # Read-only snapshot: starting the Redis subscriber thread was a
        # hidden side effect on a pure status path (the v3.0 defect) —
        # the subscriber is started by the agency/engage path instead.
        out["kill_switch"] = kill_switch.status()
    except Exception:  # noqa: BLE001
        out["kill_switch"] = {"error": "unavailable"}
    try:
        from webpent.safety import request_ledger

        out["request_ledger"] = request_ledger.ledger_stats()
    except Exception:  # noqa: BLE001
        out["request_ledger"] = {"error": "unavailable"}
    try:
        from webpent.safety import spend_governor

        out["llm_spend"] = spend_governor.spend_snapshot()
    except Exception:  # noqa: BLE001
        out["llm_spend"] = {"error": "unavailable"}
    try:
        # PROPOSALS_ULTIMATE_V2 §10: the last target-selection
        # recommendation, always with its reason (full transparency to
        # the operator; the selector recommends only — the scope
        # enforcer stays the final judge). Absent when no selection
        # has run or the selector flag is off.
        from webpent.targeting.selector import last_selection

        record = last_selection()
        out["target_selector"] = (
            record.snapshot_entry() if record is not None else None
        )
    except Exception:  # noqa: BLE001
        out["target_selector"] = {"error": "unavailable"}
    return out
