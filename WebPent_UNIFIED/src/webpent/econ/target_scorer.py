"""Economist — the target scorer (NC-ECON-1, U-ECON-2).

The charter formula, verbatim (L-3: deterministic, no randomness, no LLM):

    TargetScore(t) = clamp(
        (payout_potential(t)
         x freshness_signal(t)
         x (1 - dup_risk(t))
         x deploy_rhythm_bonus(t))
        / (effort_estimate(t) x competition_level(t))
        , 0, 100)

Component table (each documented with its source and range):

    Component            Source                              Range
    payout_potential     market_kb (weighted avg of curves)  0-1
    freshness_signal     CEM's last change timestamp         0.3-1.0
    dup_risk             market_kb dup_rate x saturation     0-1
    deploy_rhythm_bonus  CEM's rhythm detector               1.0-1.5
    effort_estimate      hours estimate                      0.5-3.0
    competition_level    U-ECON-8 (later), default 1.0       0.5-2.0

The raw product is at most ~6, so it is scaled by 100 before clamping:
a perfect payout, perfectly fresh, zero-dup, fastest-rhythm, half-hour
target saturates; a stale, saturated, high-effort one collapses toward 0.
Tiers: S >= 80, A >= 65, B >= 50, C >= 30, else D.

Advisory only (L-1); every score carries the full component breakdown,
a one-line rationale and the (injected) timestamp (L-4). Identical
inputs produce an identical score, always.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from webpent.econ.market_kb import MarketKB, Target

#: USD denominator for payout_potential: a program whose weighted typical
#: payout reaches this amount scores payout_potential 1.0.
PAYOUT_REFERENCE_USD = 10_000.0

FRESH_DAYS = 7
STALE_DAYS = 90
FRESHNESS_FLOOR = 0.3

TIER_THRESHOLDS: tuple[tuple[str, float], ...] = (
    ("S", 80.0),
    ("A", 65.0),
    ("B", 50.0),
    ("C", 30.0),
)


def tier_for(score: float) -> str:
    for tier, floor in TIER_THRESHOLDS:
        if score >= floor:
            return tier
    return "D"


@dataclass
class TargetScore:
    """Full transparency record for one scored target (L-4)."""

    target_id: str
    score: float
    tier: str
    components: dict[str, float] = field(default_factory=dict)
    rationale: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "score": round(self.score, 2),
            "tier": self.tier,
            "components": {k: round(v, 4) for k, v in self.components.items()},
            "rationale": self.rationale,
            "timestamp": self.timestamp.isoformat(),
            "advisory": True,
        }


@dataclass
class ScorerContext:
    """Everything the scorer needs beyond the target itself, injected."""

    now: float
    competition_level: float = 1.0
    saturation: float | None = None  # 0-100; U-ECON-8 fills this later

    def sanitized(self) -> ScorerContext:
        comp = min(2.0, max(0.5, float(self.competition_level or 1.0)))
        saturation = None
        if self.saturation is not None:
            saturation = min(100.0, max(0.0, float(self.saturation)))
        return ScorerContext(float(self.now), comp, saturation)


class TargetScorer:
    """Deterministic, transparent target ranking. Advisory only."""

    def __init__(self, kb: MarketKB) -> None:
        self._kb = kb

    def score(self, target: Target, ctx: ScorerContext) -> TargetScore:
        target = target.sanitized() if isinstance(target, Target) else Target(
            str(target or ""), ""
        ).sanitized()
        ctx = ctx.sanitized()

        program_payout = 0.0
        dup_base = 0.5
        if self._kb.has_program(target.program_id):
            program = self._kb.load_program(target.program_id)
            program_payout = self._kb.weighted_typical_payout(program)
            dup_base = program.dup_rate

        payout_potential = min(1.0, max(0.0, program_payout / PAYOUT_REFERENCE_USD))

        if target.last_change_ts is None:
            freshness = FRESHNESS_FLOOR
            days_since_change: float | None = None
        else:
            days_since_change = max(0.0, (ctx.now - target.last_change_ts) / 86400.0)
            if days_since_change <= FRESH_DAYS:
                freshness = 1.0
            elif days_since_change >= STALE_DAYS:
                freshness = FRESHNESS_FLOOR
            else:
                span = STALE_DAYS - FRESH_DAYS
                freshness = 1.0 - (days_since_change - FRESH_DAYS) / span * (
                    1.0 - FRESHNESS_FLOOR
                )

        saturation_factor = (ctx.saturation / 100.0) if ctx.saturation is not None else 1.0
        dup_risk = min(1.0, max(0.0, dup_base * saturation_factor))

        numerator = payout_potential * freshness * (1.0 - dup_risk) * target.deploy_rhythm_bonus
        denominator = target.effort_estimate * ctx.competition_level
        raw = numerator / denominator if denominator > 0 else 0.0
        score = min(100.0, max(0.0, raw * 100.0))

        components = {
            "payout_potential": payout_potential,
            "freshness_signal": round(freshness, 4),
            "dup_risk": round(dup_risk, 4),
            "deploy_rhythm_bonus": target.deploy_rhythm_bonus,
            "effort_estimate": target.effort_estimate,
            "competition_level": ctx.competition_level,
        }
        rationale = (
            f"payout {payout_potential:.2f} x fresh {freshness:.2f} "
            f"x (1-dup {dup_risk:.2f}) {1.0 - dup_risk:.2f} x rhythm "
            f"{target.deploy_rhythm_bonus:.2f} / effort "
            f"{target.effort_estimate:.2f} / comp {ctx.competition_level:.2f} "
            f"= {score:.1f} ({tier_for(score)})"
        )
        return TargetScore(
            target_id=target.target_id,
            score=score,
            tier=tier_for(score),
            components=components,
            rationale=rationale,
            timestamp=datetime.fromtimestamp(ctx.now, tz=timezone.utc),
        )

    def rank(self, targets: list[Target], ctx: ScorerContext) -> list[TargetScore]:
        """Score every target; ties break deterministically by target_id."""
        scored = [self.score(t, ctx) for t in list(targets)[:256]]
        scored.sort(key=lambda s: (-s.score, s.target_id))
        return scored


__all__ = [
    "FRESHNESS_FLOOR",
    "FRESH_DAYS",
    "PAYOUT_REFERENCE_USD",
    "STALE_DAYS",
    "ScorerContext",
    "TargetScore",
    "TargetScorer",
    "tier_for",
]
