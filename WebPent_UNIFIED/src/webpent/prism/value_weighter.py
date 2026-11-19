"""THE PRISM — U-PRISM-9, the Value Weighter (v89).

Where the Anomaly Filter (U-PRISM-8) makes a coarse pursue/hold/discard
call, the weighter produces one precise number per signal with the full
component breakdown, a confidence interval and a readable explanation.
Seven components, each in [0, 1], combined by config weights that must
sum to exactly 1.0 (PRISM-L-5: value over volume). Advisory-only
(PRISM-L-2) and deterministic (PRISM-L-9).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from webpent.prism.errors import PrismLawError

WEIGHT_COMPONENTS = (
    "prior_probability",
    "historical_success",
    "context_match",
    "evidence_strength",
    "novelty",
    "cost_penalty",
    "risk_penalty",
)


@dataclass(frozen=True)
class Signal:
    signal_id: str
    anomaly_type: str
    evidence_strength: float
    novelty: float
    estimated_requests: int = 1
    detection_risk: float = 0.0


@dataclass(frozen=True)
class WeightingContext:
    target_hash: str
    priors: dict[str, float] = field(default_factory=dict)
    historical: dict[str, float] = field(default_factory=dict)
    proven_types: tuple[str, ...] = ()
    explicit_context_match: float | None = None


@dataclass(frozen=True)
class SignalWeight:
    signal_id: str
    weight: float
    components: dict[str, float]
    confidence_interval: tuple[float, float]
    recommendation: str
    explanation: str
    mode: str = "advisory-only (PRISM-L-2)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "weight": round(self.weight, 6),
            "components": {k: round(v, 6)
                           for k, v in sorted(self.components.items())},
            "confidence_interval": [
                round(self.confidence_interval[0], 6),
                round(self.confidence_interval[1], 6),
            ],
            "recommendation": self.recommendation,
            "explanation": self.explanation,
            "mode": self.mode,
        }


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, value))


class ValueWeighter:
    """Precise per-signal value weighting (U-PRISM-9)."""

    def __init__(self, config_path: Path | str) -> None:
        path = Path(config_path)
        if not path.is_file():
            raise PrismLawError(
                f"curiosity params not found: {path}", law="PRISM-L-4"
            )
        config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        block = config.get("value_weighter")
        if not isinstance(block, dict):
            raise PrismLawError(
                "curiosity params: missing 'value_weighter' block",
                law="PRISM-L-4",
            )
        weights = block.get("component_weights")
        if not isinstance(weights, dict) or set(weights) != set(
            WEIGHT_COMPONENTS
        ):
            raise PrismLawError(
                f"value_weighter: component_weights must define exactly "
                f"{list(WEIGHT_COMPONENTS)}",
                law="PRISM-L-1",
            )
        total = sum(float(w) for w in weights.values())
        if abs(total - 1.0) > 1e-9:
            raise PrismLawError(
                f"value_weighter: component weights must sum to 1.0, "
                f"got {total:.6f}",
                law="PRISM-L-1",
            )
        thresholds = block.get("recommendation_thresholds")
        if not isinstance(thresholds, dict) or set(thresholds) != {
            "prioritize", "keep", "backlog"
        }:
            raise PrismLawError(
                "value_weighter: recommendation_thresholds must define "
                "prioritize, keep and backlog",
                law="PRISM-L-1",
            )
        # R2-prism-08: keys consumed at decision time are validated at
        # load; thresholds must descend so labels stay meaningful.
        try:
            confidence_width = float(block.get("confidence_width"))
        except (TypeError, ValueError):
            confidence_width = -1.0
        if not 0.0 <= confidence_width <= 1.0:
            raise PrismLawError(
                "value_weighter: 'confidence_width' must be in [0, 1]",
                law="PRISM-L-1",
            )
        t_prior = float(thresholds["prioritize"])
        t_keep = float(thresholds["keep"])
        t_backlog = float(thresholds["backlog"])
        if not t_prior >= t_keep >= t_backlog:
            raise PrismLawError(
                "value_weighter: recommendation_thresholds must descend "
                "(prioritize >= keep >= backlog)",
                law="PRISM-L-1",
            )
        # R2-prism-04: request_cost_step lives in the anomaly_filter block
        # of the shipped config (single source of truth for both curiosity
        # layers); a block-local key wins, then the filter block, then 0.25.
        self._request_cost_step = 0.25
        for source in (block, config.get("anomaly_filter") or {}):
            raw = source.get("request_cost_step") if isinstance(source, dict) else None
            if raw is None:
                continue
            try:
                self._request_cost_step = float(raw)
            except (TypeError, ValueError):
                continue
            break
        self._config = block

    @property
    def component_weights(self) -> dict[str, float]:
        return {k: float(v)
                for k, v in self._config["component_weights"].items()}

    # -- weighting -----------------------------------------------------------------

    def _components(self, signal: Signal,
                    context: WeightingContext) -> dict[str, float]:
        config = self._config
        requests = max(1, int(signal.estimated_requests))
        return {
            "prior_probability": _clamp01(
                context.priors.get(
                    signal.anomaly_type, float(config.get(
                        "default_prior", 0.3))
                )
            ),
            "historical_success": _clamp01(
                context.historical.get(
                    signal.anomaly_type, float(config.get(
                        "default_historical", 0.5))
                )
            ),
            "context_match": _clamp01(
                context.explicit_context_match
                if context.explicit_context_match is not None
                else (float(config.get("proven_context_match", 0.8))
                      if signal.anomaly_type in context.proven_types
                      else float(config.get("default_context_match", 0.4)))
            ),
            "evidence_strength": _clamp01(signal.evidence_strength),
            "novelty": _clamp01(signal.novelty),
            "cost_penalty": _clamp01(1.0 / (
                1.0 + self._request_cost_step * (requests - 1)
            )),
            "risk_penalty": _clamp01(1.0 - float(signal.detection_risk)),
        }

    def weight(self, signal: Signal, context: WeightingContext) -> SignalWeight:
        if not signal.signal_id:
            raise PrismLawError(
                "a signal needs an id", law="PRISM-L-4"
            )
        components = self._components(signal, context)
        raw = sum(
            float(self._config["component_weights"][name]) * value
            for name, value in components.items()
        )
        weight = _clamp01(raw)
        half_width = float(self._config["confidence_width"]) * (
            1.0 - _clamp01(signal.evidence_strength)
        )
        interval = (
            _clamp01(weight - half_width),
            _clamp01(weight + half_width),
        )
        thresholds = self._config["recommendation_thresholds"]
        if weight >= float(thresholds["prioritize"]):
            recommendation = "prioritize"
        elif weight >= float(thresholds["keep"]):
            recommendation = "keep"
        elif weight >= float(thresholds["backlog"]):
            recommendation = "backlog"
        else:
            recommendation = "drop"
        breakdown = ", ".join(
            f"{name}={components[name]:.3f}"
            for name in WEIGHT_COMPONENTS
        )
        explanation = (
            f"signal {signal.signal_id} ({signal.anomaly_type}): "
            f"weight={weight:.3f} [{interval[0]:.3f}, {interval[1]:.3f}] "
            f"→ {recommendation}. Breakdown: {breakdown}."
        )
        return SignalWeight(
            signal_id=signal.signal_id,
            weight=weight,
            components=components,
            confidence_interval=interval,
            recommendation=recommendation,
            explanation=explanation,
        )

    def rank(self, signals: list[Signal],
             context: WeightingContext) -> list[SignalWeight]:
        ranked = [self.weight(s, context) for s in signals]
        ranked.sort(key=lambda w: (-w.weight, w.signal_id))
        return ranked

    @staticmethod
    def explain(weight: SignalWeight) -> str:
        return weight.explanation


__all__ = ["WEIGHT_COMPONENTS", "Signal", "SignalWeight", "ValueWeighter",
           "WeightingContext"]
