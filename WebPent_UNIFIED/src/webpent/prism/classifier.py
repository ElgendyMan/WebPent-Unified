"""THE PRISM — U-PRISM-2, the Evidence Classifier (v89).

Deterministic pattern matching that turns a raw observation into a
classified, fully-dimensioned evidence candidate. Patterns live in
config/prism/classifier_patterns.yaml and are matched in file order
(first match wins — PRISM-L-9: everything is deterministic).
Reproducibility and corroboration are computed from raw counts
(attempts, independent_sources), never guessed (PRISM-L-1: evidence
is earned).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from webpent.prism.errors import PrismLawError
from webpent.prism.taxonomy import (
    Corroboration,
    EvidenceProfile,
    EvidenceTaxonomy,
    Reproducibility,
)

MIN_PATTERNS = 20


@dataclass(frozen=True)
class Classification:
    """The outcome of a deterministic pattern match."""

    pattern_id: str
    signal_kind: str
    strength: str
    reproducibility: Reproducibility
    corroboration: Corroboration
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "signal_kind": self.signal_kind,
            "strength": self.strength,
            "reproducibility": self.reproducibility.value,
            "corroboration": self.corroboration.value,
            "rationale": self.rationale,
        }


def _matches(when: dict[str, Any], observation: dict[str, Any]) -> bool:
    for key, condition in when.items():
        if key not in observation:
            return False
        value = observation[key]
        if isinstance(condition, dict):
            if "contains" in condition and str(condition["contains"]) not in str(value):
                return False
            try:
                if "min" in condition and float(value) < float(condition["min"]):
                    return False
                if "max" in condition and float(value) > float(condition["max"]):
                    return False
            except (TypeError, ValueError):
                return False
        elif isinstance(condition, list):
            if value not in condition:
                return False
        elif value != condition:
            return False
    return True


def _reproducibility(attempts: int) -> Reproducibility:
    """Reproducibility from the raw attempt count (PRISM-L-1)."""
    if attempts >= 10:
        return Reproducibility.DETERMINISTIC
    if attempts >= 2:
        return Reproducibility.REPEATABLE
    if attempts == 1:
        return Reproducibility.SINGLE_SHOT
    return Reproducibility.UNREPRODUCIBLE


def _corroboration(independent_sources: int) -> Corroboration:
    """Corroboration from the raw independent-source count (PRISM-L-1)."""
    if independent_sources >= 3:
        return Corroboration.INDEPENDENT_MULTIPLE
    if independent_sources == 2:
        return Corroboration.CORROBORATED
    if independent_sources == 1:
        return Corroboration.SINGLE_SOURCE
    return Corroboration.UNCORROBORATED


class EvidenceClassifier:
    """Config-backed, deterministic evidence classifier (U-PRISM-2)."""

    def __init__(
        self, patterns_path: Path | str, taxonomy: EvidenceTaxonomy
    ) -> None:
        path = Path(patterns_path)
        if not path.is_file():
            raise PrismLawError(
                f"classifier patterns file not found: {path}", law="PRISM-L-4"
            )
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        patterns = data.get("patterns")
        if not isinstance(patterns, list) or len(patterns) < MIN_PATTERNS:
            raise PrismLawError(
                f"classifier needs at least {MIN_PATTERNS} patterns "
                f"(found {len(patterns) if isinstance(patterns, list) else 'nothing'})",
                law="PRISM-L-1",
            )
        self._validate_patterns(patterns, taxonomy)
        self._patterns: list[dict[str, Any]] = patterns
        self._taxonomy = taxonomy

    def _validate_patterns(
        self, patterns: list[dict[str, Any]], taxonomy: EvidenceTaxonomy
    ) -> None:
        ids: list[str] = []
        for pattern in patterns:
            # R2-prism-07: a non-mapping entry must fail with the typed
            # law error, not AttributeError inside the field loop.
            if not isinstance(pattern, dict):
                raise PrismLawError(
                    f"classifier patterns must be mappings: {pattern!r}",
                    law="PRISM-L-1",
                )
            for field in ("pattern_id", "signal_kind", "strength", "rationale"):
                if not pattern.get(field):
                    raise PrismLawError(
                        f"classifier pattern missing '{field}': {pattern}",
                        law="PRISM-L-1",
                    )
            if not isinstance(pattern.get("when"), dict) or not pattern["when"]:
                raise PrismLawError(
                    f"classifier pattern {pattern['pattern_id']!r} has no "
                    f"'when' conditions",
                    law="PRISM-L-1",
                )
            ids.append(pattern["pattern_id"])
            # the strength level and the signal kind must exist in the taxonomy
            taxonomy.get_dimension_value("strength", pattern["strength"])
            taxonomy.classify(pattern["signal_kind"])
        if len(set(ids)) != len(ids):
            raise PrismLawError(
                "classifier patterns contain duplicate pattern_id values",
                law="PRISM-L-1",
            )

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)

    def classify_observation(self, observation: dict[str, Any]) -> Classification:
        if not observation:
            raise PrismLawError(
                "cannot classify an empty observation", law="PRISM-L-4"
            )
        for pattern in self._patterns:  # file order: deterministic
            if _matches(pattern.get("when") or {}, observation):
                return Classification(
                    pattern_id=pattern["pattern_id"],
                    signal_kind=pattern["signal_kind"],
                    strength=pattern["strength"],
                    reproducibility=_reproducibility(
                        int(observation.get("attempts", 0))
                    ),
                    corroboration=_corroboration(
                        int(observation.get("independent_sources", 0))
                    ),
                    rationale=pattern["rationale"],
                )
        raise PrismLawError(
            "no classifier pattern matched the observation "
            f"(keys: {sorted(observation)})",
            law="PRISM-L-4",
        )

    def profile_observation(
        self, observation: dict[str, Any], evidence_hash: str
    ) -> EvidenceProfile:
        """Full pipeline: observation → classification → evidence profile."""
        classification = self.classify_observation(observation)
        return self._taxonomy.profile(
            evidence_hash=evidence_hash,
            source=str(observation.get("source", "crawler")),
            signal_kind=classification.signal_kind,
            strength=classification.strength,
            reproducibility=classification.reproducibility.value,
            corroboration=classification.corroboration.value,
            rationale=classification.rationale,
        )


__all__ = ["Classification", "EvidenceClassifier", "MIN_PATTERNS"]
