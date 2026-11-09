# src/webpent/safety/agency.py
"""2026-10-25 Proposal 10 (safety governor v2) — agency-respect double gate.

robots.txt compliance is the DEFAULT posture of the autonomous crawler
(``CrawlConfig.respect_robots = True``). The one code path that lifts it
(``respect_robots=False``) is an exceptional override, and per the
proposal it must sit behind a double gate:

  1. the settings flag ``enable_robots_override`` (default OFF — with
     the flag off, the legacy posture is unchanged: the crawler config
     alone decides, exactly as before this proposal), and
  2. an explicit per-engagement allowlist in the environment
     (``WEBPENT_ROBOTS_OVERRIDE_ENGAGEMENTS``, comma-separated ids) —
     so an override is always attributable to a named engagement that
     an operator deliberately listed.

Fail-closed by contract: every lookup error resolves to "override not
authorized" and the crawler falls through to the normal robots
evaluation.
"""
from __future__ import annotations

import os
from typing import Any

_OVERRIDE_ENV = "WEBPENT_ROBOTS_OVERRIDE_ENGAGEMENTS"


def _allowlisted_engagements() -> frozenset[str]:
    """Parse the explicit override allowlist from the environment."""
    raw = os.environ.get(_OVERRIDE_ENV, "")
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def robots_override_allowed(engagement_id: str | None = None) -> bool:
    """True only when BOTH gates authorize a robots.txt lift.

    Pure and fail-closed: any settings/context error resolves to False,
    so the exceptional path can only open through explicit configuration.
    """
    if engagement_id is None:
        engagement_id = _active_engagement_id()
    if not engagement_id or engagement_id == "unassigned":
        return False
    try:
        from webpent.config.settings import get_settings

        if not get_settings().enable_robots_override:
            return False
    except Exception:  # noqa: BLE001 — fail closed on any settings error
        return False
    return engagement_id in _allowlisted_engagements()


def _active_engagement_id() -> str:
    """The engagement bound to the active target workspace ('' when none).

    UM-DR-26 wiring fix: this alias previously imported a name
    (``active_engagement_id``) that ``target_workspace_context`` never
    exported, so the no-argument call path crashed with ImportError and the
    fail-closed wrappers masked it as an unauthorized decision.  The
    engagement now derives from the M1b active-workspace identity axis.
    """
    try:
        from webpent.shared.target_workspace_context import get_active_target_workspace

        workspace = get_active_target_workspace()
        engagement = getattr(workspace, "engagement_id", None) if workspace is not None else None
        return str(engagement or "")
    except Exception:  # noqa: BLE001 — fail closed toward robots respect
        return ""


def robots_lift_authorized(engagement_id: str | None = None) -> bool:
    """Crawler-facing decision for a ``respect_robots=False`` config.

    Flag OFF (default): the legacy posture is preserved unchanged — the
    crawler config alone decides, so the lift proceeds exactly as it did
    before this proposal. Flag ON: the double gate must pass, otherwise
    the crawler stays robots-respecting despite its config.
    """
    try:
        from webpent.config.settings import get_settings

        if not get_settings().enable_robots_override:
            return True  # flag off: legacy behaviour, config decides
    except Exception:  # noqa: BLE001 — fail closed toward robots respect
        return False
    return robots_override_allowed(engagement_id)
