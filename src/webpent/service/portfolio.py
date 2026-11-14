# src/webpent/service/portfolio.py
"""webpent.service.portfolio

Ultimate plan 2026-10-27, proposal 6 — portfolio dashboard and
priority-aware campaign queue ordering.

``service/facade.py``'s ``MultiCampaignService.dashboard()`` reports on
ONE campaign. This module (proposal 6, Phases 3-4) aggregates many
campaigns into a portfolio view and orders the pending campaign queue
by a deterministic priority score. It is a NEW module — ``facade.py``
is untouched; the parent wires ``facade_snapshot_fn`` to the real
facade's ``dashboard``/``snapshot`` later (dependency injection keeps
this module pure, offline, and unit-testable without SQLite stores).

Honesty rules that shape this module:

  * Every input is injected (snapshot function, lessons lookup, stats
    dicts). No service objects are constructed here, nothing opens a
    database, nothing makes network calls.
  * Lessons are ADVISORY ONLY: they adjust the queue priority score,
    never a finding verdict, a scope decision, or a budget release.
  * A failing per-campaign snapshot yields an honest
    ``status="snapshot_error"`` entry with zeroed counters instead of
    crashing the whole dashboard (narrow catch — see
    ``_SNAPSHOT_FAILURE_EXCEPTIONS``).
  * Severity ranking mirrors ``models.findings.Severity`` (info < low
    < medium < high < critical); unknown severity labels cannot be
    ranked and are ignored (an unrankable value must not silently win
    the "highest severity" slot).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "MAX_CAMPAIGNS",
    "SEVERITY_RANK",
    "compute_campaign_priority",
    "order_campaign_queue",
    "portfolio_dashboard",
]

MAX_CAMPAIGNS = 256
"""Upper bound on campaigns processed per dashboard/queue call
(documented cap — a dashboard aggregating unbounded ids would be an
accidental DoS on the API layer; excess ids are truncated)."""

SEVERITY_RANK: dict[str, int] = {
    # Mirrors models.findings.Severity (low -> critical). "info" ranks
    # lowest; unlisted labels are unrankable and ignored.
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Narrow tuple of exception types an injected snapshot/lookup callable
# can realistically raise (service store lookups raise KeyError on
# unknown ids; sqlite I/O raises OSError; encoding/data bugs surface as
# ValueError/TypeError/RuntimeError). Blanket ``except Exception`` is
# forbidden by project governance — exotic types propagate and stay
# visible.
_SNAPSHOT_FAILURE_EXCEPTIONS: tuple[type[BaseException], ...] = (
    KeyError,
    ValueError,
    TypeError,
    RuntimeError,
    OSError,
)


def _empty_snapshot(campaign_id: str) -> dict[str, Any]:
    """The honest zero snapshot used when no facade function is wired."""
    return {
        "campaign_id": campaign_id,
        "status": "unknown",
        "findings_confirmed": 0,
        "cost_usd": 0.0,
        "started_at": None,
        "current_phase": None,
        "highest_severity": None,
    }


def _to_float(value: Any, default: float = 0.0) -> float:
    """Best-effort numeric coercion for snapshot counters."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_int(value: Any, default: int = 0) -> int:
    """Best-effort integer coercion for snapshot counters."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def portfolio_dashboard(
    campaign_ids: list[str],
    *,
    facade_snapshot_fn: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Aggregate per-campaign snapshots into one portfolio dashboard.

    Proposal 6, Phase 3. Each campaign contributes a snapshot shaped::

        {
            "campaign_id": str,
            "status": str,
            "findings_confirmed": int,
            "cost_usd": float,
            "started_at": str | None,
            "current_phase": str | None,
            # optional, used for the severity aggregate:
            "highest_severity" / "highest_severity_open": str | None,
        }

    Returns::

        {
            "campaigns": [snapshot, ...],  # sorted: findings desc, cost asc
            "totals": {
                "campaigns": int,
                "findings_confirmed": int,
                "cost_usd": float,
            },
            "highest_severity_open": str | None,  # max rank or None
            "generated_at": iso-8601 UTC timestamp,
        }

    Args:
        campaign_ids: Campaign ids to aggregate. Bounded to
            ``MAX_CAMPAIGNS`` (256) — excess ids are truncated.
        facade_snapshot_fn: Injected per-campaign snapshot provider
            (the parent wires this to the real MultiCampaignService).
            When ``None``, a stub returns honest zero snapshots with
            ``status="unknown"`` — the dashboard renders, it does not
            lie. If the function raises for one campaign, that
            campaign gets a ``status="snapshot_error"`` entry with
            zeroed counters and the error text; the rest of the
            dashboard is unaffected (fail-closed per campaign, not
            per dashboard).

    Returns:
        The aggregated portfolio dashboard dict described above.
    """
    bounded_ids = [str(cid) for cid in list(campaign_ids or [])][:MAX_CAMPAIGNS]
    snapshot_fn = facade_snapshot_fn or _empty_snapshot

    campaigns: list[dict[str, Any]] = []
    for campaign_id in bounded_ids:
        try:
            snapshot = dict(snapshot_fn(campaign_id) or {})
        except _SNAPSHOT_FAILURE_EXCEPTIONS as exc:
            snapshot = dict(_empty_snapshot(campaign_id))
            snapshot["status"] = "snapshot_error"
            snapshot["error"] = f"{type(exc).__name__}: {exc}"[:200]
        snapshot["campaign_id"] = campaign_id
        campaigns.append(snapshot)

    campaigns.sort(
        key=lambda item: (
            -_to_int(item.get("findings_confirmed")),
            _to_float(item.get("cost_usd")),
        )
    )

    highest_severity: str | None = None
    highest_rank = -1
    for snapshot in campaigns:
        # Prefer "highest_severity_open" when it carries a rankable
        # label; otherwise consider "highest_severity". Unrankable
        # labels (not in SEVERITY_RANK) never win the aggregate slot.
        for severity_key in ("highest_severity_open", "highest_severity"):
            label = str(snapshot.get(severity_key) or "").strip().lower()
            if not label:
                continue
            rank = SEVERITY_RANK.get(label, -1)
            if rank >= 0 and rank > highest_rank:
                highest_rank = rank
                highest_severity = label

    return {
        "campaigns": campaigns,
        "totals": {
            "campaigns": len(campaigns),
            "findings_confirmed": sum(
                _to_int(item.get("findings_confirmed")) for item in campaigns
            ),
            "cost_usd": round(
                sum(_to_float(item.get("cost_usd")) for item in campaigns), 4
            ),
        },
        "highest_severity_open": highest_severity,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def compute_campaign_priority(
    campaign_id: str,
    lessons_lookup: Callable[[str], list[dict[str, Any]]] | None = None,
    *,
    stats: dict[str, Any] | None = None,
) -> float:
    """Deterministic priority score in [0.0, 1.0] for queue ordering.

    Proposal 6, Phase 4 (priority-aware scheduling). Components
    (weights fixed and documented — no LLM input anywhere):

      * 0.5 base — every campaign deserves a baseline slot;
      * +0.2 when ``lessons_lookup(campaign_id)`` yields applicable
        lessons (non-empty list). Lessons are ADVISORY ONLY: they bias
        queue order so a campaign whose target resembles past
        engagements runs earlier; they never change verdicts, scopes,
        or budgets. A failing lookup counts as "no lessons" (narrow
        catch — the queue must always be orderable).
      * +0.2 * normalized confirmed-findings rate —
        ``findings_confirmed / max(findings_total, 1)`` from ``stats``
        (missing stats → 0.0). Campaigns that convert work into
        confirmed findings keep their compute.
      * +0.1 when ``stats["stalled"]`` is truthy — nudge stalled
        campaigns up so a human sees them near the top of the queue.

    Args:
        campaign_id: The campaign being scored.
        lessons_lookup: Injected advisory-lessons provider (the parent
            wires it to ``memory/lessons.py``). ``None`` → no lessons
            bonus.
        stats: Optional per-campaign stats dict with keys
            ``findings_confirmed`` (int), ``findings_total`` (int),
            ``stalled`` (bool) — all optional.

    Returns:
        The priority score clamped to [0.0, 1.0].
    """
    score = 0.5
    if lessons_lookup is not None:
        try:
            lessons = lessons_lookup(campaign_id)
        except _SNAPSHOT_FAILURE_EXCEPTIONS:
            lessons = []
        if isinstance(lessons, (list, tuple)) and len(lessons) > 0:
            score += 0.2

    stats_dict = stats if isinstance(stats, dict) else {}
    confirmed = max(0, _to_int(stats_dict.get("findings_confirmed")))
    total = max(0, _to_int(stats_dict.get("findings_total")))
    rate = (confirmed / total) if total > 0 else 0.0
    score += 0.2 * min(1.0, max(0.0, rate))

    if stats_dict.get("stalled"):
        score += 0.1

    return round(min(1.0, max(0.0, score)), 4)


def order_campaign_queue(
    campaign_ids: list[str],
    *,
    stats_by_campaign: dict[str, dict[str, Any]],
    lessons_lookup: Callable[[str], list[dict[str, Any]]] | None = None,
) -> list[tuple[str, float]]:
    """Order campaigns by :func:`compute_campaign_priority` (descending).

    Proposal 6, Phase 4. Ties keep input order (stable sort). Bounded
    to ``MAX_CAMPAIGNS`` (256) ids, mirroring the dashboard cap.

    Args:
        campaign_ids: Campaign ids to order.
        stats_by_campaign: Per-campaign stats dicts (see
            :func:`compute_campaign_priority`); campaigns without an
            entry are scored with empty stats.
        lessons_lookup: Optional injected lessons provider (advisory
            only — see :func:`compute_campaign_priority`).

    Returns:
        ``[(campaign_id, priority), ...]`` sorted by priority
        descending.
    """
    bounded_ids = [str(cid) for cid in list(campaign_ids or [])][:MAX_CAMPAIGNS]
    stats_map = stats_by_campaign if isinstance(stats_by_campaign, dict) else {}
    scored = [
        (
            campaign_id,
            compute_campaign_priority(
                campaign_id,
                lessons_lookup,
                stats=stats_map.get(campaign_id) or {},
            ),
        )
        for campaign_id in bounded_ids
    ]
    scored.sort(key=lambda pair: -pair[1])
    return scored
