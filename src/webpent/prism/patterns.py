"""THE PRISM — U-PRISM-6, the Pattern Extractor (v89).

Turns raw outcome records into structured, reusable patterns across
five types: technique_effectiveness, evidence_quality, stack_specific,
family_transfer and target_archetype. Learning is structured
(PRISM-L-3): no pattern exists below min_samples, confidence grows only
with samples, and pruning drops stale (older than stale_days) or
under-sampled patterns. Everything is deterministic (PRISM-L-9):
pattern ids come from SHA-256 of type+key, and time is always passed
in, never sampled.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from webpent.oracle.models import sha256_text
from webpent.prism.errors import PrismLawError

PATTERN_TYPES = (
    "technique_effectiveness",
    "evidence_quality",
    "stack_specific",
    "family_transfer",
    "target_archetype",
)

# the record field each pattern type groups on
_TYPE_KEYS = {
    "technique_effectiveness": "technique",
    "evidence_quality": "signal_kind",
    "stack_specific": "stack",
    "family_transfer": "family",
    "target_archetype": "archetype",
}


@dataclass(frozen=True)
class Pattern:
    pattern_id: str
    pattern_type: str
    key: str
    samples: int
    successes: int
    success_rate: float
    confidence: float
    updated_at: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "pattern_type": self.pattern_type,
            "key": self.key,
            "samples": self.samples,
            "successes": self.successes,
            "success_rate": round(self.success_rate, 6),
            "confidence": round(self.confidence, 6),
            "updated_at": self.updated_at,
            "reason": self.reason,
        }


def _confidence(samples: int) -> float:
    """Deterministic confidence growth: 5 samples → 0.625, 10 → 0.77,
    50 → 0.94. Monotonic in samples, capped at 1.0 by construction."""
    return samples / (samples + 3.0)


class PatternExtractor:
    """Structured pattern extraction (U-PRISM-6)."""

    def __init__(self, config_path: Path | str) -> None:
        path = Path(config_path)
        if not path.is_file():
            raise PrismLawError(
                f"learning params not found: {path}", law="PRISM-L-4"
            )
        config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for key in ("min_samples", "confidence_floor", "adjustment_cap",
                    "stale_days"):
            value = config.get(key)
            if not isinstance(value, (int, float)) or value <= 0:
                raise PrismLawError(
                    f"learning params: '{key}' must be a positive number",
                    law="PRISM-L-1",
                )
        types = config.get("pattern_types")
        if types != list(PATTERN_TYPES):
            raise PrismLawError(
                f"learning params: pattern_types must be {list(PATTERN_TYPES)}",
                law="PRISM-L-1",
            )
        self._config = config

    @property
    def min_samples(self) -> int:
        return int(self._config["min_samples"])

    @property
    def stale_days(self) -> int:
        return int(self._config["stale_days"])

    @property
    def confidence_floor(self) -> float:
        return float(self._config["confidence_floor"])

    # -- extraction -------------------------------------------------------------

    def _records_for(self, records: Sequence[dict[str, Any]],
                     pattern_type: str) -> dict[str, list[dict[str, Any]]]:
        field = _TYPE_KEYS[pattern_type]
        groups: dict[str, list[dict[str, Any]]] = {}
        for record in records:
            key = record.get(field)
            if not key:
                continue
            groups.setdefault(str(key), []).append(record)
        return dict(sorted(groups.items()))

    def extract(self, records: Sequence[dict[str, Any]],
                now: datetime) -> list[Pattern]:
        patterns: list[Pattern] = []
        for pattern_type in PATTERN_TYPES:
            groups = self._records_for(records, pattern_type)
            for key, group in groups.items():
                if len(group) < self.min_samples:
                    continue
                successes = sum(
                    1 for r in group if r.get("outcome") == "confirmed"
                )
                pattern_id = sha256_text(f"{pattern_type}:{key}")[:16]
                patterns.append(Pattern(
                    pattern_id=pattern_id,
                    pattern_type=pattern_type,
                    key=key,
                    samples=len(group),
                    successes=successes,
                    success_rate=successes / len(group),
                    confidence=_confidence(len(group)),
                    updated_at=now.isoformat(),
                    reason=(
                        f"{successes}/{len(group)} confirmed outcomes for "
                        f"{pattern_type}={key}"
                    ),
                ))
        patterns.sort(key=lambda p: (p.pattern_type, p.pattern_id))
        return patterns

    def update(self, pattern: Pattern, outcome: str,
               now: datetime) -> Pattern:
        if outcome not in ("confirmed", "refuted", "inconclusive"):
            raise PrismLawError(
                f"unknown outcome: {outcome!r}", law="PRISM-L-3"
            )
        samples = pattern.samples + 1
        successes = pattern.successes + (1 if outcome == "confirmed" else 0)
        return replace(
            pattern,
            samples=samples,
            successes=successes,
            success_rate=successes / samples,
            confidence=_confidence(samples),
            updated_at=now.isoformat(),
        )

    def prune(self, patterns: Sequence[Pattern],
              now: datetime) -> list[Pattern]:
        # naive and aware datetimes cannot be compared; the ledger stores
        # aware ISO timestamps while callers may pass a naive `now` (or
        # vice versa). Normalizing both sides to UTC-aware (naive is
        # interpreted as UTC) keeps the comparison deterministic
        # (PRISM-L-9) instead of crashing or silently skipping patterns.
        def _aware(value: datetime) -> datetime:
            return (
                value if value.tzinfo is not None
                else value.replace(tzinfo=timezone.utc)
            )

        cutoff = _aware(now) - timedelta(days=self.stale_days)
        kept: list[Pattern] = []
        for pattern in patterns:
            updated = _aware(datetime.fromisoformat(pattern.updated_at))
            if updated < cutoff:
                continue  # stale (PRISM-L-3 decay)
            if pattern.samples < self.min_samples:
                continue  # under-sampled
            kept.append(pattern)
        return kept

    def dedupe(self, patterns: Sequence[Pattern]) -> list[Pattern]:
        seen: dict[str, Pattern] = {}
        for pattern in patterns:
            existing = seen.get(pattern.pattern_id)
            if existing is None or (pattern.samples, pattern.updated_at) > (
                existing.samples, existing.updated_at
            ):
                seen[pattern.pattern_id] = pattern
        return [seen[k] for k in sorted(seen)]


__all__ = ["PATTERN_TYPES", "Pattern", "PatternExtractor"]
