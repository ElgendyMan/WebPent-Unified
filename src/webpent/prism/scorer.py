"""THE PRISM — U-PRISM-3, the Evidence Scorer (v89).

Formula (documented, deterministic, PRISM-L-9):

    score = base_weight × strength × reproducibility × corroboration
            + type_bonus − noise_penalty        (clamped to [0, 1])

Every component is carried on the result, so every score can be audited
and recomputed (PRISM-L-1/L-4). Tiers A-F and recommendations come from
config. The scorer is advisory-only (PRISM-L-2): it ranks, it never
blocks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from webpent.prism.errors import PrismLawError
from webpent.prism.taxonomy import (
    Corroboration,
    EvidenceProfile,
    EvidenceTaxonomy,
    Reproducibility,
    Strength,
)

TIER_ORDER = ("A", "B", "C", "D", "F")

FORMULA = (
    "score = base_weight × strength × reproducibility × corroboration "
    "+ type_bonus − noise_penalty, clamped to [0, 1]"
)


@dataclass(frozen=True)
class ScoreResult:
    """A transparent, recomputable score (PRISM-L-1: earned, PRISM-L-4:
    no silent components)."""

    evidence_hash: str
    score: float
    tier: str
    recommendation: str
    components: dict[str, float] = field(default_factory=dict)
    formula: str = FORMULA
    rationale: str = ""
    advisory: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_hash": self.evidence_hash,
            "score": round(self.score, 6),
            "tier": self.tier,
            "recommendation": self.recommendation,
            "components": {
                k: round(v, 6) for k, v in self.components.items()
            },
            "formula": self.formula,
            "rationale": self.rationale,
            "advisory": self.advisory,
        }


class EvidenceScorer:
    """Config-backed evidence scorer (U-PRISM-3)."""

    def __init__(
        self, config_path: Path | str, taxonomy: EvidenceTaxonomy
    ) -> None:
        path = Path(config_path)
        if not path.is_file():
            raise PrismLawError(
                f"scorer config not found: {path}", law="PRISM-L-4"
            )
        self._config: dict[str, Any] = (
            yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        )
        self._taxonomy = taxonomy
        self._validate()

    def _validate(self) -> None:
        source_weights = self._config.get("source_weights")
        if not isinstance(source_weights, dict):
            raise PrismLawError(
                "scorer config: 'source_weights' must be a mapping",
                law="PRISM-L-1",
            )
        for source in self._taxonomy.levels("sources"):
            weight = source_weights.get(source)
            if not isinstance(weight, (int, float)) or not 0.0 <= float(weight) <= 1.0:
                raise PrismLawError(
                    f"scorer config: source_weights.{source} must be a "
                    f"weight in [0, 1] (found {weight!r})",
                    law="PRISM-L-1",
                )
        tiers = self._config.get("tiers")
        if not isinstance(tiers, dict) or set(tiers) != {"A", "B", "C", "D"}:
            raise PrismLawError(
                "scorer config: 'tiers' must define exactly A, B, C, D",
                law="PRISM-L-1",
            )
        thresholds = [float(tiers[t]) for t in ("A", "B", "C", "D")]
        if any(
            not 0.0 <= t <= 1.0 for t in thresholds
        ) or thresholds != sorted(thresholds, reverse=True):
            raise PrismLawError(
                "scorer config: tier thresholds must descend within [0, 1]",
                law="PRISM-L-1",
            )
        recommendations = self._config.get("recommendations")
        if not isinstance(recommendations, dict) or set(recommendations) != set(
            TIER_ORDER
        ):
            raise PrismLawError(
                f"scorer config: 'recommendations' must cover {TIER_ORDER}",
                law="PRISM-L-1",
            )
        penalties = self._config.get("noise_penalties")
        if not isinstance(penalties, dict) or not penalties:
            raise PrismLawError(
                "scorer config: 'noise_penalties' must be a non-empty mapping",
                law="PRISM-L-1",
            )
        # R2-prism-05: the three rule keys are consumed at scoring time;
        # a config missing one used to load fine and silently stop
        # penalizing that condition (errors.py: never a silent default).
        missing = sorted(
            {"negligible_strength", "unreproducible", "uncorroborated"}
            - set(penalties)
        )
        if missing:
            raise PrismLawError(
                f"scorer config: noise_penalties missing {missing}",
                law="PRISM-L-1",
            )

    # -- scoring ---------------------------------------------------------------

    @property
    def integration_config(self) -> dict[str, Any]:
        """The integration block shared with U-PRISM-4 (validated lazily
        there; exposed here so Wave 2 needs one config file)."""
        return dict(self._config.get("integration") or {})

    def tier_for(self, score: float) -> str:
        tiers = self._config["tiers"]
        for tier in ("A", "B", "C", "D"):
            if score >= float(tiers[tier]):
                return tier
        return "F"

    def _noise_penalty(self, profile: EvidenceProfile) -> tuple[float, list[str]]:
        penalties = self._config.get("noise_penalties") or {}
        applied: list[str] = []
        total = 0.0
        if profile.strength is Strength.NEGLIGIBLE:
            applied.append("negligible_strength")
        if profile.reproducibility is Reproducibility.UNREPRODUCIBLE:
            applied.append("unreproducible")
        if profile.corroboration is Corroboration.UNCORROBORATED:
            applied.append("uncorroborated")
        for key in applied:
            # R2-prism-05: _validate guarantees all rule keys exist, so a
            # missing key can no longer degrade into a silent 0.0 penalty.
            total += float(penalties[key])
        return total, applied

    def score(self, profile: EvidenceProfile) -> ScoreResult:
        source_weight = float(
            self._config["source_weights"][profile.source.value]
        )
        strength = self._taxonomy.get_dimension_value(
            "strength", profile.strength.value
        )
        reproducibility = self._taxonomy.get_dimension_value(
            "reproducibility", profile.reproducibility.value
        )
        corroboration = self._taxonomy.get_dimension_value(
            "corroboration", profile.corroboration.value
        )
        type_bonus = self._taxonomy.type_bonus(profile.evidence_type)
        penalty, applied = self._noise_penalty(profile)

        raw = (
            source_weight * strength * reproducibility * corroboration
            + type_bonus
            - penalty
        )
        value = min(1.0, max(0.0, raw))
        tier = self.tier_for(value)
        return ScoreResult(
            evidence_hash=profile.evidence_hash,
            score=value,
            tier=tier,
            recommendation=self._config["recommendations"][tier],
            components={
                "base_weight": source_weight,
                "strength": strength,
                "reproducibility": reproducibility,
                "corroboration": corroboration,
                "type_bonus": type_bonus,
                "noise_penalty": -penalty,
            },
            rationale=profile.rationale,
        )


__all__ = ["FORMULA", "ScoreResult", "EvidenceScorer", "TIER_ORDER"]
