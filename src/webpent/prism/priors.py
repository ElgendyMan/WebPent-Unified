"""THE PRISM — U-PRISM-7, the Prior Adjuster (v89).

Applies learned patterns as priors to a baseline. The laws are
structural, not aspirational (PRISM-L-3/L-1): an adjustment below the
confidence floor is refused, the delta is hard-capped at ±adjustment_cap
(±0.20 by default), a reason is mandatory, and the pattern must match
the context it is applied to. The result carries its advisory mode
explicitly (PRISM-L-2).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from webpent.prism.errors import PrismLawError
from webpent.prism.patterns import Pattern, PatternExtractor

_TYPE_KEYS = {
    "technique_effectiveness": "technique",
    "evidence_quality": "signal_kind",
    "stack_specific": "stack",
    "family_transfer": "family",
    "target_archetype": "archetype",
}


@dataclass(frozen=True)
class PriorAdjustment:
    pattern_id: str
    pattern_type: str
    key: str
    baseline: float
    delta: float
    adjusted: float
    reason: str
    confidence: float
    mode: str = "advisory-only (PRISM-L-2)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "pattern_type": self.pattern_type,
            "key": self.key,
            "baseline": round(self.baseline, 6),
            "delta": round(self.delta, 6),
            "adjusted": round(self.adjusted, 6),
            "reason": self.reason,
            "confidence": round(self.confidence, 6),
            "mode": self.mode,
        }


class PriorAdjuster:
    """Profile-matched, capped, reasoned prior adjustment (U-PRISM-7)."""

    def __init__(self, config_path: Path | str,
                 extractor: PatternExtractor | None = None) -> None:
        path = Path(config_path)
        if not path.is_file():
            raise PrismLawError(
                f"learning params not found: {path}", law="PRISM-L-4"
            )
        self._config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        self._extractor = extractor or PatternExtractor(config_path)

    @property
    def adjustment_cap(self) -> float:
        return float(self._config["adjustment_cap"])

    def adjust(self, baseline: float, pattern: Pattern,
               context: dict[str, Any]) -> PriorAdjustment:
        if not 0.0 <= baseline <= 1.0:
            raise PrismLawError(
                f"baseline must be in [0, 1], got {baseline!r}",
                law="PRISM-L-1",
            )
        if pattern.confidence < self._extractor.confidence_floor:
            raise PrismLawError(
                f"pattern {pattern.pattern_id} confidence "
                f"{pattern.confidence:.3f} is below the floor "
                f"{self._extractor.confidence_floor}; refusing to adjust",
                law="PRISM-L-3",
            )
        if not pattern.reason:
            raise PrismLawError(
                "an adjustment without a reason is a law breach (PRISM-L-1)",
                law="PRISM-L-1",
            )
        # profile-matched: the pattern's key must match the context
        # R2-prism-06: an unknown pattern_type raises the typed law error
        # at the law boundary, not a raw KeyError.
        context_field = _TYPE_KEYS.get(pattern.pattern_type)
        if context_field is None:
            raise PrismLawError(
                f"unknown pattern_type {pattern.pattern_type!r} "
                f"(expected one of {sorted(_TYPE_KEYS)})",
                law="PRISM-L-3",
            )
        context_value = context.get(context_field)
        if context_value is None or str(context_value) != pattern.key:
            raise PrismLawError(
                f"pattern {pattern.pattern_id} ({pattern.pattern_type}="
                f"{pattern.key}) does not match the context "
                f"({context_field}={context_value!r}); adjustments are "
                f"profile-matched",
                law="PRISM-L-3",
            )
        raw_delta = (pattern.success_rate - baseline) * pattern.confidence
        cap = self.adjustment_cap
        delta = max(-cap, min(cap, raw_delta))
        adjusted = min(1.0, max(0.0, baseline + delta))
        return PriorAdjustment(
            pattern_id=pattern.pattern_id,
            pattern_type=pattern.pattern_type,
            key=pattern.key,
            baseline=baseline,
            delta=delta,
            adjusted=adjusted,
            reason=pattern.reason,
            confidence=pattern.confidence,
        )


__all__ = ["PriorAdjustment", "PriorAdjuster"]
