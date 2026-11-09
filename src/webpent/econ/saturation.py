"""Economist — the hunter activity estimator (NC-ECON-1, U-ECON-8).

Estimates the saturation index of one target from public data only
(L-2: everything is read from the local CompetitiveRadar DB or
injected; nothing is fetched).

The charter formula, verbatim (L-3: deterministic):

    Saturation = weighted_avg(
        0.5 x findings_rate_normalized,
        0.3 x mentions_normalized,
        0.2 x reporters_normalized
    ) x 100

Component table (source and range per component):

    Component                 Source                          Range
    findings_rate_normalized  radar findings over 30 days,    0-1
                              capped at findings_reference
    mentions_normalized       injected mentions count         0-1
                              (only if a source is available)
    reporters_normalized      injected reporter count         0-1
                              (only if the program publishes
                              it)

Missing-data policy (DoD: clear handling):

    * the findings component is the backbone: without it the report is
      ``insufficient_signal`` and carries no number;
    * mentions and reporters are optional: when absent, the remaining
      weights are renormalized over the components that exist (0.5 and
      0.3 renormalize to 0.625/0.375); the report notes which parts
      were estimated from partial weights;
    * every normalization clamps at 1.0, so the index is clamped
      0-100 by construction.

Tiers: 0-30 LOW (golden opportunity), 31-60 MEDIUM, 61-85 HIGH,
86-100 SATURATED. Advisory only (L-1); identical inputs give an
identical index, always.
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from webpent.econ.competitive import CompetitiveRadar
from webpent.econ.market_kb import Target

_LOG = logging.getLogger(__name__)

WEIGHT_FINDINGS = 0.5
WEIGHT_MENTIONS = 0.3
WEIGHT_REPORTERS = 0.2

TIER_BOUNDS: tuple[tuple[str, float], ...] = (
    ("LOW", 30.0),
    ("MEDIUM", 60.0),
    ("HIGH", 85.0),
    ("SATURATED", 100.0),
)

FINDINGS_WINDOW_DAYS = 30


def tier_for(index: float) -> str:
    for tier, ceiling in TIER_BOUNDS:
        if index <= ceiling:
            return tier
    return "SATURATED"


def load_saturation_params(path: Any) -> dict[str, float]:
    """Load the saturation block of competition_params.yaml; fail-soft."""
    config: dict[str, float] = {
        "findings_reference_per_30d": 5.0,
        "mentions_reference": 20.0,
        "reporters_reference": 10.0,
    }
    if path is None:
        return config
    try:
        import yaml

        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return config
    except Exception as exc:
        _LOG.warning("saturation params unreadable; using defaults: %s", exc)
        return config
    if not isinstance(raw, dict):
        return config
    sat = raw.get("saturation") if isinstance(raw.get("saturation"), dict) else raw
    for key in list(config):
        if sat.get(key) is None:
            continue
        with contextlib.suppress(TypeError, ValueError):
            config[key] = max(1.0, float(sat[key]))
    return config


@dataclass
class SaturationReport:
    """Full transparency record of one saturation estimate (L-4)."""

    index: float  # 0-100
    tier: str
    components: dict[str, float] = field(default_factory=dict)
    recommendation: str = ""
    confidence: float = 1.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": round(self.index, 2),
            "tier": self.tier,
            "components": {k: round(v, 4) for k, v in self.components.items()},
            "recommendation": self.recommendation,
            "confidence": round(self.confidence, 3),
            "timestamp": self.timestamp.isoformat(),
            "advisory": True,
        }


def _norm(value: float, reference: float) -> float:
    if value <= 0 or reference <= 0:
        return 0.0
    return min(1.0, value / reference)


def _float_signal(value: Any) -> float | None:
    """Coerce an optional public signal to float; None on failure.

    R2-econ-06: a PRESENT but non-numeric signal (e.g. mentions="many")
    must be treated like a missing one -- recorded in ``partial`` and
    reflected in confidence -- never silently dropped while the report
    still claims "all three public signals" (L-4).
    """
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class SaturationEstimator:
    """Deterministic saturation index from public signals. Advisory only."""

    def __init__(self, *, params_path: Any = None) -> None:
        self.params = load_saturation_params(params_path)

    def estimate(
        self,
        target: Target,
        radar: CompetitiveRadar,
        *,
        now: datetime | None = None,
        mentions: float | None = None,
        reporters: float | None = None,
    ) -> SaturationReport:
        """Estimate one target's saturation index.

        ``now`` is injected (L-4); ``mentions``/``reporters`` are the
        optional public signals the charter allows. Everything else
        comes from the radar's local DB.
        """
        target = target.sanitized() if isinstance(target, Target) else Target(
            str(target or ""), ""
        ).sanitized()
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        findings_count = len(
            radar.get_findings(target.program_id, now - timedelta(days=FINDINGS_WINDOW_DAYS))
        )
        # missing-data policy: an empty radar DB plus no optional signals
        # means "no data", not "no activity"
        if (
            findings_count == 0
            and mentions is None
            and reporters is None
            and radar.count_findings(target.program_id) == 0
        ):
            return self._insufficient(now)
        ref_findings = float(self.params["findings_reference_per_30d"])
        ref_mentions = float(self.params["mentions_reference"])
        ref_reporters = float(self.params["reporters_reference"])

        components: dict[str, float] = {
            "findings_rate_normalized": _norm(float(findings_count), ref_findings),
        }
        weights: dict[str, float] = {"findings_rate_normalized": WEIGHT_FINDINGS}
        partial: list[str] = []
        if mentions is not None:
            # R2-econ-06: corrupt signal -> partial, not a silent drop
            mentions_val = _float_signal(mentions)
            if mentions_val is None:
                partial.append("mentions")
            else:
                components["mentions_normalized"] = _norm(mentions_val, ref_mentions)
                weights["mentions_normalized"] = WEIGHT_MENTIONS
        else:
            partial.append("mentions")
        if reporters is not None:
            # R2-econ-06: corrupt signal -> partial, not a silent drop
            reporters_val = _float_signal(reporters)
            if reporters_val is None:
                partial.append("reporters")
            else:
                components["reporters_normalized"] = _norm(reporters_val, ref_reporters)
                weights["reporters_normalized"] = WEIGHT_REPORTERS
        else:
            partial.append("reporters")

        total_weight = sum(weights.values())
        if total_weight <= 0:  # pragma: no cover - findings weight is constant
            return self._insufficient(now)
        index = sum(
            components[name] * weight for name, weight in weights.items()
        ) / total_weight * 100.0
        index = min(100.0, max(0.0, index))
        tier = tier_for(index)
        confidence = 1.0 if not partial else 0.7
        rec = {
            "LOW": "golden opportunity: public activity is minimal",
            "MEDIUM": "playable: normal public competition",
            "HIGH": "crowded: prioritize uncovered classes (U-ECON-9)",
            "SATURATED": "late: the crowd got here first; avoid duplication",
        }[tier]
        note = (
            f"estimated from partial weights ({', '.join(partial)} unavailable)"
            if partial
            else "estimated from all three public signals"
        )
        return SaturationReport(
            index=index,
            tier=tier,
            components={
                **components,
                "findings_count_30d": float(findings_count),
            },
            recommendation=f"{rec}; {note}",
            confidence=confidence,
            timestamp=now,
        )

    @staticmethod
    def _insufficient(now: datetime) -> SaturationReport:
        # R2-econ-08: "no data" must not masquerade as a measured LOW
        # score; NO_DATA lets machine readers tell the two apart while
        # index/confidence stay honestly zero.
        return SaturationReport(
            index=0.0,
            tier="NO_DATA",
            components={},
            recommendation="insufficient_signal: no public findings data at all",
            confidence=0.0,
            timestamp=now,
        )


__all__ = [
    "FINDINGS_WINDOW_DAYS",
    "SaturationReport",
    "SaturationEstimator",
    "TIER_BOUNDS",
    "WEIGHT_FINDINGS",
    "WEIGHT_MENTIONS",
    "WEIGHT_REPORTERS",
    "load_saturation_params",
    "tier_for",
]
