"""webpent.production.campaign_lifecycle — M3 UM-DR-17: worker-level
campaign-resume wiring (production wiring of ``resume/``).

M1a deferral note (M1_PHASE_REPORT): "OAST/``enable_campaign_resume``
production-graph wiring → M3 — flags now exist fail-closed". The resume
package (``resume/campaign_checkpoints.py``: crash/timeout markers, the
bounded probe-execution ledger, bounded requeue backoff) shipped with
ZERO production consumers — the worker never marked interrupted
engagements and never consulted the resume budget.

This module is the worker-level context the deferral asked for (NEW
file, outside the frozen gate; the worker gains flag-gated calls):

* ``mark_campaign_interrupted`` — the worker's crash/soft-timeout/
  recursion-limit handlers call this (flag-gated): marker + state
  fingerprint, so a redelivered task CAN auto-continue.
* ``campaign_resume_decision`` — the redelivery-side gate: fresh marker
  + retry budget ⇒ continue the existing graph thread (the checkpointer
  already holds the state); anything else ⇒ the operator-restart
  contract stays untouched.
* ``record_probe_executed`` / ``probe_already_executed`` — the
  probe-execution ledger guards, so a resumed campaign never re-fires
  an already-executed probe.

Every entry point is inert unless ``enable_campaign_resume`` is on —
the flag's fail-closed contract (interrupted campaigns stay strictly
operator-restarted by default) is preserved exactly.
"""

from __future__ import annotations

import logging
from typing import Any

from webpent.config.settings import get_settings

logger = logging.getLogger(__name__)


def _resume_enabled(settings: Any = None) -> bool:
    try:
        resolved = settings or get_settings()
        return bool(getattr(resolved, "enable_campaign_resume", False))
    except Exception:  # pragma: no cover - defensive
        return False


def mark_campaign_interrupted(
    *,
    engagement_id: str,
    reason: str,
    node: str | None = None,
    state_values: Any = None,
    settings: Any = None,
) -> bool:
    """Flag-gated wrapper over ``resume.mark_interrupted``.

    Computes the state fingerprint from the graph's values when
    available. Returns False (and writes nothing) when the flag is off.
    """
    if not _resume_enabled(settings) or not str(engagement_id).strip():
        return False
    try:
        from webpent.resume.campaign_checkpoints import mark_interrupted, state_fingerprint

        state_hash = ""
        if state_values is not None:
            try:
                state_hash = state_fingerprint(state_values)
            except Exception:  # noqa: BLE001 — fingerprint is best-effort
                state_hash = ""
        marked = mark_interrupted(
            str(engagement_id),
            reason=str(reason)[:120],
            node=str(node)[:120] if node else None,
            state_hash=state_hash,
        )
        if marked:
            logger.info(
                "campaign-resume: marked engagement=%s interrupted (reason=%s, node=%s)",
                engagement_id,
                reason,
                node,
            )
        return marked
    except Exception as exc:  # noqa: BLE001 — marker is advisory
        logger.warning(
            "campaign-resume: marker write failed for %s: %s",
            engagement_id,
            type(exc).__name__,
        )
        return False


def campaign_resume_decision(
    *,
    engagement_id: str,
    retries: int,
    settings: Any = None,
) -> dict[str, Any]:
    """The redelivery-side gate (flag-gated).

    Returns ``{"auto_resume": bool, "reason": str}`` — never raises. The
    caller continues the existing checkpointed graph ONLY on
    auto_resume=True; every other path keeps the operator-restart
    contract.
    """
    if not _resume_enabled(settings):
        return {"auto_resume": False, "reason": "campaign_resume_disabled"}
    try:
        from webpent.resume.campaign_checkpoints import should_auto_resume

        allowed = should_auto_resume(str(engagement_id), int(retries))
        return {
            "auto_resume": bool(allowed),
            "reason": "marker_present_budget_remaining" if allowed else "no_marker_or_budget_exhausted",
        }
    except Exception as exc:  # noqa: BLE001 — gate is fail-closed
        logger.warning(
            "campaign-resume: decision failed for %s: %s",
            engagement_id,
            type(exc).__name__,
        )
        return {"auto_resume": False, "reason": "decision_error"}


def campaign_backoff_seconds(retries: int, settings: Any = None) -> float:
    """Flag-aware bounded backoff for requeue (0 = do not requeue)."""
    if not _resume_enabled(settings):
        return 0.0
    try:
        from webpent.resume.campaign_checkpoints import backoff_seconds

        return float(backoff_seconds(max(0, int(retries))))
    except Exception:  # pragma: no cover - defensive
        return 0.0


def record_probe_executed(
    *,
    engagement_id: str,
    probe_id: str,
    settings: Any = None,
) -> bool:
    """Record one probe execution in the bounded ledger (flag-gated)."""
    if not _resume_enabled(settings):
        return False
    try:
        from webpent.resume.campaign_checkpoints import ProbeLedger

        return ProbeLedger().mark(str(engagement_id), str(probe_id))
    except Exception as exc:  # noqa: BLE001 — ledger is advisory
        logger.debug(
            "campaign-resume: probe ledger write failed: %s", type(exc).__name__
        )
        return False


def probe_already_executed(
    *,
    engagement_id: str,
    probe_id: str,
    settings: Any = None,
) -> bool:
    """Has this probe already fired for this engagement? (flag-gated,
    False when off — a disabled ledger never suppresses a probe)."""
    if not _resume_enabled(settings):
        return False
    try:
        from webpent.resume.campaign_checkpoints import ProbeLedger

        return ProbeLedger().was_executed(str(engagement_id), str(probe_id))
    except Exception as exc:  # noqa: BLE001 — ledger is advisory
        logger.debug(
            "campaign-resume: probe ledger read failed: %s", type(exc).__name__
        )
        return False


def clear_campaign_interrupt(engagement_id: str, settings: Any = None) -> None:
    """Clear the marker after a terminal (non-resumable) exit (flag-gated)."""
    if not _resume_enabled(settings):
        return
    try:
        from webpent.resume.campaign_checkpoints import clear_interrupt

        clear_interrupt(str(engagement_id))
    except Exception as exc:  # noqa: BLE001 — advisory
        logger.debug(
            "campaign-resume: marker clear failed: %s", type(exc).__name__
        )


__all__ = [
    "campaign_backoff_seconds",
    "campaign_resume_decision",
    "clear_campaign_interrupt",
    "mark_campaign_interrupted",
    "probe_already_executed",
    "record_probe_executed",
]
