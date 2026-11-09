"""THE PRISM — U-PRISM-8, the Anomaly Filter (v89).

Turns "anomaly detected" into "anomaly detected AND value ≥ threshold".
Curiosity is a value hunter (PRISM-L-5): every raw anomaly gets an
estimated value from prior × historical success × context match, divided
by its cost, and only clears the configured thresholds when it is worth
pursuing. The filter is advisory-only (PRISM-L-2) and fully
deterministic (PRISM-L-9): no clocks, no RNG, no network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from webpent.prism.errors import PrismLawError

DECISIONS = ("pursue", "hold", "discard")


@dataclass(frozen=True)
class RawAnomaly:
    anomaly_id: str
    anomaly_type: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FilterContext:
    target_hash: str
    target_profile: dict[str, Any] = field(default_factory=dict)
    # anomaly types that already paid off on this target
    proven_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class FilteredAnomaly:
    anomaly_id: str
    anomaly_type: str
    raw_anomaly: dict[str, Any]
    estimated_value: float
    estimated_impact: float
    combined_value: float
    decision: str
    reasoning: str
    mode: str = "advisory-only (PRISM-L-2)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id,
            "anomaly_type": self.anomaly_type,
            "estimated_value": round(self.estimated_value, 6),
            "estimated_impact": round(self.estimated_impact, 6),
            "combined_value": round(self.combined_value, 6),
            "decision": self.decision,
            "reasoning": self.reasoning,
            "mode": self.mode,
        }


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, value))


class AnomalyFilter:
    """Value-weighted anomaly filter (U-PRISM-8)."""

    def __init__(self, config_path: Path | str) -> None:
        path = Path(config_path)
        if not path.is_file():
            raise PrismLawError(
                f"curiosity params not found: {path}", law="PRISM-L-4"
            )
        config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        block = config.get("anomaly_filter")
        if not isinstance(block, dict):
            raise PrismLawError(
                "curiosity params: missing 'anomaly_filter' block",
                law="PRISM-L-4",
            )
        for key in ("pursue_threshold", "hold_threshold"):
            value = block.get(key)
            if not isinstance(value, (int, float)) or not 0.0 <= value <= 1.0:
                raise PrismLawError(
                    f"anomaly_filter: '{key}' must be in [0, 1]",
                    law="PRISM-L-1",
                )
        if block["hold_threshold"] > block["pursue_threshold"]:
            raise PrismLawError(
                "anomaly_filter: hold_threshold must be ≤ pursue_threshold",
                law="PRISM-L-1",
            )
        # R2-prism-08: validate every key consumed at decision time here,
        # instead of failing with an untyped KeyError inside filter().
        for key in ("default_prior", "default_historical", "default_impact",
                    "proven_context_match", "default_context_match"):
            value = block.get(key)
            if not isinstance(value, (int, float)) or not 0.0 <= value <= 1.0:
                raise PrismLawError(
                    f"anomaly_filter: '{key}' must be in [0, 1]",
                    law="PRISM-L-1",
                )
        for key in ("hour_cost_step", "request_cost_step"):
            value = block.get(key)
            if not isinstance(value, (int, float)) or value < 0.0:
                raise PrismLawError(
                    f"anomaly_filter: '{key}' must be a non-negative number",
                    law="PRISM-L-1",
                )
        self._config = block

    def get_decision_thresholds(self) -> dict[str, float]:
        return {
            "pursue_threshold": float(self._config["pursue_threshold"]),
            "hold_threshold": float(self._config["hold_threshold"]),
        }

    # -- value computation -------------------------------------------------------

    def _context_match(self, anomaly: RawAnomaly,
                       context: FilterContext) -> float:
        if "context_match" in anomaly.raw:
            return _clamp01(float(anomaly.raw["context_match"]))
        if anomaly.anomaly_type in context.proven_types:
            return float(self._config["proven_context_match"])
        return float(self._config["default_context_match"])

    def _cost(self, anomaly: RawAnomaly) -> float:
        requests = max(0, int(anomaly.raw.get("estimated_requests", 1)))
        hours = max(0.0, float(anomaly.raw.get("estimated_hours", 0.0)))
        # R2-prism-04: the shipped config documents request_cost_step: 0.25
        # ("each extra request beyond the first divides value") but no code
        # read it — the filter hardcoded 1.0 per extra request while the
        # value weighter used 0.25. Both layers now read the same key.
        cost = (
            1.0
            + (requests - 1) * float(self._config["request_cost_step"])
            + (hours * float(self._config["hour_cost_step"]))
        )
        return max(1.0, cost)

    def compute_value(self, anomaly: RawAnomaly, prior: float,
                      historical: float, context_match: float) -> float:
        cost = self._cost(anomaly)
        value = (prior * historical * context_match) / cost
        return _clamp01(value)

    # -- filtering -----------------------------------------------------------------

    def filter(self, anomaly: RawAnomaly, context: FilterContext,
               prior: float | None = None,
               historical: float | None = None) -> FilteredAnomaly:
        if not anomaly.anomaly_id or not anomaly.anomaly_type:
            raise PrismLawError(
                "an anomaly needs both an id and a type", law="PRISM-L-4"
            )
        used_prior = _clamp01(
            float(prior) if prior is not None
            else float(self._config["default_prior"])
        )
        used_historical = _clamp01(
            float(historical) if historical is not None
            else float(self._config["default_historical"])
        )
        match = self._context_match(anomaly, context)
        estimated_value = self.compute_value(
            anomaly, used_prior, used_historical, match
        )
        impact = _clamp01(
            float(anomaly.raw.get(
                "estimated_impact", self._config["default_impact"]
            ))
        )
        combined = _clamp01(0.6 * estimated_value + 0.4 * impact)
        thresholds = self.get_decision_thresholds()
        if combined >= thresholds["pursue_threshold"]:
            decision = "pursue"
        elif combined >= thresholds["hold_threshold"]:
            decision = "hold"
        else:
            decision = "discard"
        reasoning = (
            f"value={estimated_value:.3f} "
            f"(prior={used_prior:.3f} × historical={used_historical:.3f} "
            f"× context_match={match:.3f} ÷ cost={self._cost(anomaly):.3f}), "
            f"impact={impact:.3f}, combined={combined:.3f} → {decision} "
            f"(pursue≥{thresholds['pursue_threshold']:.2f}, "
            f"hold≥{thresholds['hold_threshold']:.2f})"
        )
        return FilteredAnomaly(
            anomaly_id=anomaly.anomaly_id,
            anomaly_type=anomaly.anomaly_type,
            raw_anomaly=dict(anomaly.raw),
            estimated_value=estimated_value,
            estimated_impact=impact,
            combined_value=combined,
            decision=decision,
            reasoning=reasoning,
        )

    def batch_filter(self, anomalies: list[RawAnomaly],
                     context: FilterContext) -> list[FilteredAnomaly]:
        return [self.filter(a, context) for a in anomalies]


__all__ = [
    "DECISIONS", "AnomalyFilter", "FilterContext", "FilteredAnomaly",
    "RawAnomaly",
]
