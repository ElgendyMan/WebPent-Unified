"""Economist — the executive dashboard (NC-ECON-1, U-ECON-12).

The operator's single daily view, assembled from the other Economist
modules — all local, all advisory (L-1, L-2: nothing is fetched, nothing
is reported, nothing mutates a live system):

    * portfolio counts by state (ACTIVE / WATCHING / DORMANT / ARCHIVED)
    * top 5 opportunities ranked by estimated EV
    * bottom 5 targets wasting resources (lowest EV/hour, active only)
    * pipeline: findings currently in processing (injected by the caller)
    * earnings projection from the daily-plan hour split
    * alerts (empty on a clean state)

Everything is deterministic for identical inputs (L-3) and every record
carries the full transparency envelope {value, components, rationale,
confidence, timestamp} (L-4). The CLI in ``webpent/cli/econ.py`` renders
this as markdown or JSON and appends every invocation to
``download/econ/audit.jsonl``.
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.econ.portfolio import (
    ACTIVE,
    ARCHIVED,
    DORMANT,
    MIN_TARGETS,
    PLAN_HOURS,
    WATCHING,
    Portfolio,
    PortfolioManager,
)

_LOG = logging.getLogger(__name__)

WEEKS_PER_MONTH = 52.0 / 12.0
TOP_OPPORTUNITIES = 5
BOTTOM_TARGETS = 5
MAX_PIPELINE = 20

RESOURCE_STATES = (ACTIVE, WATCHING)  # states that actually consume hours

def _md_cell(text: Any) -> str:
    """One markdown cell, structurally inert (RT-11).

    Line breaks are folded to spaces (a raw newline would forge new rows
    or bullets) and pipes are replaced with a broken-bar lookalike (a raw
    pipe would split table cells).
    """
    raw = "" if text is None else str(text)
    return " ".join(raw.splitlines()).replace("|", "\u00a6")


def load_portfolio_failsoft(path: Any) -> Portfolio:
    """Load portfolio.yaml; missing/corrupt -> empty portfolio (fail-soft)."""
    if path is None:
        return Portfolio()
    return PortfolioManager().load(Path(str(path)))


@dataclass
class DashboardAlert:
    """One operator alert, advisory only (L-4)."""

    level: str  # "info" | "warn"
    message: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "advisory": True,
        }


@dataclass
class DailyDigest:
    """The full daily picture (L-4): everything needed, nothing fetched."""

    generated_at: datetime
    portfolio_counts: dict[str, int] = field(default_factory=dict)
    top_opportunities: list[dict[str, Any]] = field(default_factory=list)
    bottom_targets: list[dict[str, Any]] = field(default_factory=list)
    pipeline: list[dict[str, Any]] = field(default_factory=list)
    earnings_projection: dict[str, Any] = field(default_factory=dict)
    alerts: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "portfolio_counts": dict(self.portfolio_counts),
            "top_opportunities": list(self.top_opportunities),
            "bottom_targets": list(self.bottom_targets),
            "pipeline": list(self.pipeline),
            "earnings_projection": dict(self.earnings_projection),
            "alerts": list(self.alerts),
            "advisory": True,
        }


class Dashboard:
    """Assembles the daily digest from the Economist's local modules."""

    def __init__(
        self,
        *,
        portfolio_path: Any = None,
        now: datetime | None = None,
    ) -> None:
        self.portfolio_path = portfolio_path
        self._now = now or datetime.now(timezone.utc)
        if self._now.tzinfo is None:
            self._now = self._now.replace(tzinfo=timezone.utc)

    # ------------------------------------------------------------ projection
    def earnings_projection(self, portfolio: Portfolio, hours_per_week: float) -> dict[str, Any]:
        """Project weekly/monthly EV from the plan's hour split (deterministic).

        Hours are split by state (60/30/10, PLAN_HOURS) and spread evenly
        across that state's targets; each target's EV/hour converts its
        slice into USD. Zero-EV targets project zero — the number is only
        as honest as the EV/hour estimates behind it.
        """
        hours_per_week = max(0.0, float(hours_per_week))
        weekly = 0.0
        per_state_hours: dict[str, float] = {}
        for state in (ACTIVE, WATCHING, DORMANT):
            share = PLAN_HOURS.get(state, 0.0)
            state_hours = hours_per_week * share
            per_state_hours[state] = state_hours
            targets = portfolio.by_state(state)
            if not targets or state_hours <= 0:
                continue
            per_target = state_hours / len(targets)
            for pt in targets:
                weekly += per_target * max(0.0, float(pt.ev_per_hour))
        blended = weekly / hours_per_week if hours_per_week > 0 else 0.0
        return {
            "hours_per_week": round(hours_per_week, 4),
            "hours_by_state": {k: round(v, 4) for k, v in per_state_hours.items()},
            "blended_ev_per_hour_usd": round(blended, 4),
            "projected_weekly_usd": round(weekly, 2),
            "projected_monthly_usd": round(weekly * WEEKS_PER_MONTH, 2),
            "basis": "plan hour split x per-target EV/hour (advisory estimate)",
            "timestamp": self._now.isoformat(),
            "advisory": True,
        }

    # ---------------------------------------------------------------- alerts
    def _alerts(self, portfolio: Portfolio) -> list[DashboardAlert]:
        alerts: list[DashboardAlert] = []
        burning = [
            pt.target.target_id
            for pt in portfolio.by_state(ACTIVE)
            if float(pt.ev_per_hour) <= 0.0
        ]
        if burning:
            alerts.append(
                DashboardAlert(
                    "warn",
                    f"{len(burning)} ACTIVE target(s) burning hours with zero "
                    f"EV/hour: {', '.join(burning[:5])}",
                    timestamp=self._now,
                )
            )
        if len(portfolio.targets) < MIN_TARGETS:
            alerts.append(
                DashboardAlert(
                    "info",
                    f"portfolio has {len(portfolio.targets)} target(s), below the "
                    f"minimum diversity of {MIN_TARGETS}",
                    timestamp=self._now,
                )
            )
        return alerts

    # ---------------------------------------------------------------- digest
    def build_digest(
        self,
        *,
        hours_per_week: float = 40.0,
        pipeline: list[dict[str, Any]] | None = None,
        spots: list[Any] | None = None,
    ) -> DailyDigest:
        """Build one DailyDigest.

        ``pipeline`` is the operator's in-processing findings (injected,
        never fetched); ``spots`` is an optional ranked list of blind
        spots / opportunities carrying ``estimated_ev`` (U-ECON-9 output).
        """
        portfolio = load_portfolio_failsoft(self.portfolio_path)
        counts = {state: len(portfolio.by_state(state)) for state in
                  (ACTIVE, WATCHING, DORMANT, ARCHIVED)}

        ranked: list[tuple[float, int, str, dict[str, Any]]] = []
        for i, spot in enumerate(list(spots or [])[:256]):
            with contextlib.suppress(Exception):
                d = spot.as_dict() if hasattr(spot, "as_dict") else dict(spot)
                ranked.append((float(d.get("estimated_ev") or 0.0), i,
                               str(d.get("identifier") or ""), d))
        ranked.sort(key=lambda t: (-t[0], t[1], t[2]))
        top = [d for _, _, _, d in ranked[:TOP_OPPORTUNITIES]]

        wasting = sorted(
            (pt for pt in portfolio.targets.values() if pt.state in RESOURCE_STATES),
            key=lambda pt: (float(pt.ev_per_hour), pt.target.target_id),
        )[:BOTTOM_TARGETS]
        bottom = [
            {
                "target_id": pt.target.target_id,
                "state": pt.state,
                "ev_per_hour": round(float(pt.ev_per_hour), 4),
                "total_findings": int(pt.total_findings),
                "total_payout_usd": round(float(pt.total_payout_usd), 2),
            }
            for pt in wasting
        ]

        alerts = [a.as_dict() for a in self._alerts(portfolio)]
        clean_pipeline = [
            dict(item) for item in list(pipeline or [])[:MAX_PIPELINE]
            if isinstance(item, dict)
        ]
        return DailyDigest(
            generated_at=self._now,
            portfolio_counts=counts,
            top_opportunities=top,
            bottom_targets=bottom,
            pipeline=clean_pipeline,
            earnings_projection=self.earnings_projection(portfolio, hours_per_week),
            alerts=alerts,
        )

    # -------------------------------------------------------------- markdown
    def as_markdown(self, digest: DailyDigest) -> str:
        """Render the digest as a markdown daily briefing."""
        d = digest.as_dict()
        lines = ["# Economist Daily Digest", ""]
        ts = d["generated_at"]
        lines += [f"Generated: {ts}", ""]
        lines += ["## Portfolio", ""]
        for state, count in d["portfolio_counts"].items():
            lines.append(f"- {state}: {count}")
        lines.append("")
        lines += ["## Top opportunities (by estimated EV)", ""]
        if d["top_opportunities"]:
            for opp in d["top_opportunities"]:
                ev = opp.get("estimated_ev", 0.0)
                lines.append(
                    f"- {opp.get('kind', '?')} `{_md_cell(opp.get('identifier', '?'))}` "
                    f"EV ~{ev:.0f}USD (confidence {opp.get('confidence', 0):.2f})"
                )
        else:
            lines.append("- none recorded")
        lines.append("")
        lines += ["## Bottom targets (wasting resources)", ""]
        if d["bottom_targets"]:
            lines.append("| target | state | EV/hour USD | findings |")
            lines.append("|---|---|---|---|")
            for t in d["bottom_targets"]:
                lines.append(
                    f"| {_md_cell(t['target_id'])} | {_md_cell(t['state'])} | "
                    f"{t['ev_per_hour']:.2f} | {t['total_findings']} |"
                )
        else:
            lines.append("- none recorded")
        lines.append("")
        lines += ["## Pipeline (findings in processing)", ""]
        if d["pipeline"]:
            for item in d["pipeline"]:
                lines.append(f"- `{_md_cell(item.get('finding_id', '?'))}` "
                             f"{_md_cell(item.get('vuln_class', '?'))} "
                             f"@ {_md_cell(item.get('program_id', '?'))}")
        else:
            lines.append("- empty")
        lines.append("")
        ep = d["earnings_projection"]
        lines += [
            "## Earnings projection",
            "",
            f"- weekly: {ep.get('projected_weekly_usd', 0.0):.2f}USD "
            f"(blended {ep.get('blended_ev_per_hour_usd', 0.0):.2f}USD/hour)",
            f"- monthly: {ep.get('projected_monthly_usd', 0.0):.2f}USD",
            "",
            "## Alerts",
            "",
        ]
        if d["alerts"]:
            for alert in d["alerts"]:
                lines.append(f"- [{alert['level']}] {_md_cell(alert['message'])}")
        else:
            lines.append("- none: clean state")
        lines.append("")
        lines.append("_Advisory only: every number here is an estimate (L-1)._")
        return "\n".join(lines)


__all__ = [
    "BOTTOM_TARGETS",
    "DailyDigest",
    "Dashboard",
    "DashboardAlert",
    "TOP_OPPORTUNITIES",
    "WEEKS_PER_MONTH",
    "load_portfolio_failsoft",
]
