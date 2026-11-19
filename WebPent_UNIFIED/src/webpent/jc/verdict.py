"""Judgment Council — U-JC-5: verdict rules (config layer).

The verdict formula lives in config/jc/verdict_rules.yaml; a missing or
corrupt file fails soft to these defaults. The judge itself is in
``judge.py``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)

VERDICT_DEFAULTS: dict[str, Any] = {
    "high": 0.85,
    "medium": 0.60,
    "clear_winner_ratio": 1.5,
    "tie_epsilon": 1e-9,
    "escalate_on_low_confidence": True,
}

#: tie_epsilon must sit in (0, TIE_EPSILON_MAX]
TIE_EPSILON_MAX = 0.5
#: a clear winner needs top/runner-up at least this large
CLEAR_WINNER_MIN = 1.0


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


@dataclass
class VerdictRules:
    """The thresholds the judge applies (deterministic, documented)."""

    high: float = 0.85
    medium: float = 0.60
    clear_winner_ratio: float = 1.5
    tie_epsilon: float = 1e-9
    escalate_on_low_confidence: bool = True
    source: str = "defaults"

    def tier(self, confidence: float) -> str:
        """Map a confidence to its tier (high/medium/low)."""
        if confidence >= self.high:
            return "high"
        if confidence >= self.medium:
            return "medium"
        return "low"

    def should_escalate(self, confidence: float) -> bool:
        """Low-confidence verdicts go to the operator (JC-L-7)."""
        return bool(self.escalate_on_low_confidence) and confidence < self.medium


def load_verdict_rules(path: Any) -> VerdictRules:
    """Load config/jc/verdict_rules.yaml; corrupt/missing -> defaults."""
    rules = VerdictRules()
    if path is None:
        return rules
    try:
        import yaml

        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return rules
    except Exception as exc:  # noqa: BLE001 - fail-soft by charter
        _LOG.warning("verdict rules unreadable; using defaults: %s", exc)
        return rules
    block = raw.get("verdict") if isinstance(raw, dict) else None
    if not isinstance(block, dict):
        return rules
    thresholds = block.get("confidence_thresholds")
    if isinstance(thresholds, dict):
        with_rules = rules
        try:
            with_rules.high = float(thresholds.get("high", rules.high))
            with_rules.medium = float(thresholds.get("medium", rules.medium))
        except (TypeError, ValueError):
            pass
        rules = with_rules
    try:
        rules.clear_winner_ratio = float(
            block.get("clear_winner_ratio", rules.clear_winner_ratio)
        )
        rules.tie_epsilon = float(block.get("tie_epsilon", rules.tie_epsilon))
    except (TypeError, ValueError):
        pass
    rules.escalate_on_low_confidence = bool(
        block.get("escalate_on_low_confidence", rules.escalate_on_low_confidence)
    )
    rules.source = "config"
    return _sanitize(rules)


def _sanitize(rules: VerdictRules) -> VerdictRules:
    """Clamp thresholds to [0,1] (high >= medium), drop nonsense epsilon/ratio.

    tier() and should_escalate() must agree: an inverted pair is swapped,
    not rejected (fail-soft, deterministic).
    """
    rules.high = _clamp01(float(rules.high))
    rules.medium = _clamp01(float(rules.medium))
    if rules.high < rules.medium:
        rules.high, rules.medium = rules.medium, rules.high
    if not (0.0 < rules.tie_epsilon <= TIE_EPSILON_MAX):
        rules.tie_epsilon = VERDICT_DEFAULTS["tie_epsilon"]
    if not (float(rules.clear_winner_ratio) >= CLEAR_WINNER_MIN):
        rules.clear_winner_ratio = VERDICT_DEFAULTS["clear_winner_ratio"]
    return rules


__all__ = ["CLEAR_WINNER_MIN", "TIE_EPSILON_MAX", "VERDICT_DEFAULTS",
           "VerdictRules", "load_verdict_rules"]
