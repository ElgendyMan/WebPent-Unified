"""Economist — the budget-to-ROI mapper (NC-ECON-1, U-ECON-6).

Distributes a weekly hour budget across the portfolio (L-3: deterministic).

The charter algorithm, verbatim:

    1. For each target: EV_per_hour = expected_EV / estimated_hours
    2. Sort by EV_per_hour (descending; ties broken by target_id so the
       ordering never depends on dict/set iteration)
    3. Top 20%    -> INTENSIVE  (60% of the time budget)
    4. Middle 30% -> ROUTINE   (30% of the time budget)
    5. Bottom 50% -> DORMANT   (10% of the time budget — CEM only)

Split ratios and thresholds (all in ``BUDGET_DEFAULTS``, overridable from
``config/econ/roi_params.yaml`` under ``budget:``):

    Tier       Share of targets   Share of hours
    INTENSIVE  top 20%            60%
    ROUTINE    next 30%           30%
    DORMANT    bottom 50%         10%

With few targets the share is rounded but never vanishes: one target is
INTENSIVE, two targets split INTENSIVE + ROUTINE. Within a tier the
hours divide evenly (deterministic; no randomness, no LLM).

expected_EV comes from the injected TargetScorer score scaled to USD by
``ev_scale_usd`` (score 100 ~= the reference payout). ``total_hours <=
0`` raises ValueError: allocating nothing is not a budget. Every
allocation carries a justification (DoD) and is advisory only (L-1).
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.autonomous.hunt_contracts import redact
from webpent.econ.market_kb import Target
from webpent.econ.target_scorer import PAYOUT_REFERENCE_USD, TargetScorer

_LOG = logging.getLogger(__name__)

INTENSIVE = "INTENSIVE"
ROUTINE = "ROUTINE"
DORMANT = "DORMANT"

BUDGET_DEFAULTS: dict[str, float] = {
    "intensive_share_targets": 0.20,
    "routine_share_targets": 0.30,
    "intensive_share_hours": 0.60,
    "routine_share_hours": 0.30,
    "dormant_share_hours": 0.10,
    "ev_scale_usd": PAYOUT_REFERENCE_USD,
}


def load_budget_params(path: Any) -> dict[str, float]:
    """Load the budget block of roi_params.yaml; corrupt/missing -> defaults."""
    config = dict(BUDGET_DEFAULTS)
    if path is None:
        return config
    try:
        import yaml

        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return config
    except Exception as exc:
        _LOG.warning("budget params unreadable; using defaults: %s", exc)
        return config
    if not isinstance(raw, dict):
        return config
    budget = raw.get("budget") if isinstance(raw.get("budget"), dict) else raw
    for key in list(BUDGET_DEFAULTS):
        if budget.get(key) is None:
            continue
        with contextlib.suppress(TypeError, ValueError):
            config[key] = max(0.0, float(budget[key]))
    return config


@dataclass
class BudgetContext:
    """Injected inputs for one allocation cycle; nothing is fetched (L-2)."""

    now: float

    def sanitized(self) -> BudgetContext:
        return BudgetContext(now=float(self.now))


@dataclass
class BudgetAllocation:
    """One target's slice of the weekly budget, with its reason (L-4)."""

    target_id: str
    tier: str  # INTENSIVE | ROUTINE | DORMANT
    hours_per_week: float
    ev_per_hour: float
    justification: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "tier": self.tier,
            "hours_per_week": round(self.hours_per_week, 4),
            "ev_per_hour": round(self.ev_per_hour, 4),
            "justification": self.justification,
            "timestamp": self.timestamp.isoformat(),
            "advisory": True,
        }


class BudgetMapper:
    """Deterministic time-budget allocation over the portfolio. Advisory."""

    def __init__(self, scorer: TargetScorer, *, params_path: Any = None) -> None:
        self._scorer = scorer
        self.params = load_budget_params(params_path)

    def _expected_ev(self, target: Target, ctx: BudgetContext) -> float:
        """Charter step 1's numerator, from the deterministic scorer."""
        from webpent.econ.target_scorer import ScorerContext

        score = self._scorer.score(target, ScorerContext(now=ctx.now))
        return max(0.0, score.score) * float(self.params["ev_scale_usd"]) / 100.0

    def allocate(
        self, targets: list[Target], total_hours: float, ctx: BudgetContext
    ) -> list[BudgetAllocation]:
        if total_hours is None or float(total_hours) <= 0.0:
            raise ValueError("total_hours must be > 0: allocating nothing is not a budget")
        ctx = ctx.sanitized()
        clean = [t.sanitized() for t in list(targets)[:256]]
        if not clean:
            return []
        seen_ids: set[str] = set()
        for t in clean:  # RT-06: a duplicate id would double-allocate one target silently
            if t.target_id in seen_ids:
                raise ValueError(
                    f"duplicate target_id {t.target_id!r}: each target may appear once"
                )
            seen_ids.add(t.target_id)

        expected_ev = {t.target_id: self._expected_ev(t, ctx) for t in clean}
        # charter step 1 + 2: EV_per_hour, sorted desc, ties by target_id
        ranked = sorted(
            clean,
            key=lambda t: (
                -expected_ev[t.target_id] / t.effort_estimate,
                t.target_id,
            ),
        )

        n = len(ranked)
        n_intensive = min(n, max(1, round(float(self.params["intensive_share_targets"]) * n)))
        n_routine = min(
            n - n_intensive,
            max(0, round(float(self.params["routine_share_targets"]) * n)),
        )
        tiers = (
            [INTENSIVE] * n_intensive
            + [ROUTINE] * n_routine
            + [DORMANT] * (n - n_intensive - n_routine)
        )

        hour_shares = {
            INTENSIVE: float(self.params["intensive_share_hours"]),
            ROUTINE: float(self.params["routine_share_hours"]),
            DORMANT: float(self.params["dormant_share_hours"]),
        }

        allocations: list[BudgetAllocation] = []
        ts = datetime.fromtimestamp(ctx.now, tz=timezone.utc)
        for tier in (INTENSIVE, ROUTINE, DORMANT):
            members = [t for t, tier_name in zip(ranked, tiers, strict=False) if tier_name == tier]
            if not members:
                continue
            pool = hour_shares[tier] * float(total_hours)
            per_target = pool / len(members)
            for t in members:
                evph = expected_ev[t.target_id] / t.effort_estimate
                rank_word = {"INTENSIVE": "top", "ROUTINE": "middle",
                             "DORMANT": "bottom"}[tier]
                allocations.append(
                    BudgetAllocation(
                        target_id=redact(t.target_id)[:120],
                        tier=tier,
                        hours_per_week=per_target,
                        ev_per_hour=evph,
                        justification=(
                            f"tier {tier}: EV/hour {evph:.1f}USD/h ranks "
                            f"{rank_word} of {n} targets; "
                            f"{per_target:.2f}h/week of the "
                            f"{hour_shares[tier]:.0%} {tier} pool"
                        ),
                        timestamp=ts,
                    )
                )
        # report in ranked order so output order matches the charter's sort
        by_id = {a.target_id: a for a in allocations}
        ordered = [by_id[redact(t.target_id)[:120]] for t in ranked]
        return ordered


__all__ = [
    "BUDGET_DEFAULTS",
    "BudgetAllocation",
    "BudgetContext",
    "BudgetMapper",
    "DORMANT",
    "INTENSIVE",
    "ROUTINE",
    "load_budget_params",
]
