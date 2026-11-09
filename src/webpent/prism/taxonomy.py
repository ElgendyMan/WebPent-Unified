"""THE PRISM — U-PRISM-1, the Evidence Taxonomy (v89).

Every piece of evidence Prism touches carries a full profile across five
dimensions: source, type, strength, reproducibility and corroboration
(PRISM-L-1: evidence is earned — no dimension, no profile, no score).
The taxonomy is config-driven and validated at load time (PRISM-L-4:
no silent failures, PRISM-L-9: deterministic).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from webpent.prism.errors import PrismLawError


class EvidenceSource(str, Enum):
    CRAWLER = "crawler"
    PROBE = "probe"
    BROWSER = "browser"
    ORACLE = "oracle"
    VALIDATOR = "validator"
    BRAIN = "brain"
    OPERATOR = "operator"
    LEDGER = "ledger"


class EvidenceType(str, Enum):
    DIRECT = "direct"
    INFERENCE = "inference"
    SIDE_EFFECT = "side_effect"
    ANOMALY = "anomaly"


class Strength(str, Enum):
    DECISIVE = "decisive"
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    NEGLIGIBLE = "negligible"


class Reproducibility(str, Enum):
    DETERMINISTIC = "deterministic"
    REPEATABLE = "repeatable"
    OCCASIONAL = "occasional"
    UNREPRODUCIBLE = "unreproducible"
    SINGLE_SHOT = "single_shot"


class Corroboration(str, Enum):
    INDEPENDENT_MULTIPLE = "independent_multiple"
    CORROBORATED = "corroborated"
    SINGLE_SOURCE = "single_source"
    UNCORROBORATED = "uncorroborated"


# The canonical signal kinds Prism understands. The config may extend the
# mapping, but every one of these must be present and classified.
CANONICAL_SIGNAL_KINDS = (
    "direct_response",
    "error_message",
    "timing_delta",
    "header_anomaly",
    "behavior_diff",
    "side_effect",
    "inference",
)

_DIMENSION_ENUMS: dict[str, type[Enum]] = {
    "sources": EvidenceSource,
    "types": EvidenceType,
    "strength": Strength,
    "reproducibility": Reproducibility,
    "corroboration": Corroboration,
}

_DIMENSION_EXPECTED = {
    "sources": 8,
    "types": 4,
    "strength": 5,
    "reproducibility": 5,
    "corroboration": 4,
}

_WEIGHTED_DIMENSIONS = ("strength", "reproducibility", "corroboration", "type_bonus")


@dataclass(frozen=True)
class EvidenceProfile:
    """A fully-dimensioned evidence profile (PRISM-L-1)."""

    evidence_hash: str
    source: EvidenceSource
    evidence_type: EvidenceType
    strength: Strength
    reproducibility: Reproducibility
    corroboration: Corroboration
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        raw = asdict(self)
        for key in (
            "source", "evidence_type", "strength",
            "reproducibility", "corroboration",
        ):
            raw[key] = raw[key].value
        return raw


class EvidenceTaxonomy:
    """Config-backed, validated evidence taxonomy."""

    def __init__(self, config_path: Path | str) -> None:
        path = Path(config_path)
        if not path.is_file():
            raise PrismLawError(
                f"taxonomy config not found: {path}", law="PRISM-L-4"
            )
        self._config: dict[str, Any] = (
            yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        )
        self.validate()

    # -- validation ------------------------------------------------------------

    def validate(self) -> None:
        for dimension, expected in _DIMENSION_EXPECTED.items():
            block = self._config.get(dimension)
            if not isinstance(block, (list, dict)) or len(block) != expected:
                found = (
                    len(block)
                    if isinstance(block, (list, dict)) else "nothing"
                )
                raise PrismLawError(
                    f"taxonomy config: '{dimension}' must define exactly "
                    f"{expected} entries (found {found})",
                    law="PRISM-L-1",
                )
            enum_cls = _DIMENSION_ENUMS[dimension]
            valid = {member.value for member in enum_cls}
            unknown = [name for name in block if name not in valid]
            if unknown:
                raise PrismLawError(
                    f"taxonomy config: unknown {dimension} entries: {unknown}",
                    law="PRISM-L-1",
                )
        for dimension in _WEIGHTED_DIMENSIONS:
            values = self._config.get(dimension)
            if not isinstance(values, dict) or not values:
                raise PrismLawError(
                    f"taxonomy config: '{dimension}' must be a non-empty weight map",
                    law="PRISM-L-1",
                )
            for name, value in values.items():
                if not isinstance(value, (int, float)) or not 0.0 <= float(value) <= 1.0:
                    raise PrismLawError(
                        f"taxonomy config: {dimension}.{name} must be a "
                        f"weight in [0, 1] (found {value!r})",
                        law="PRISM-L-1",
                    )
        kinds = self._config.get("signal_kinds")
        if not isinstance(kinds, dict) or not kinds:
            raise PrismLawError(
                "taxonomy config: 'signal_kinds' must be a non-empty mapping",
                law="PRISM-L-1",
            )
        valid_types = {t.value for t in EvidenceType}
        for kind, evidence_type in kinds.items():
            if evidence_type not in valid_types:
                raise PrismLawError(
                    f"taxonomy config: signal kind {kind!r} maps to unknown "
                    f"evidence type {evidence_type!r}",
                    law="PRISM-L-1",
                )
        missing = [k for k in CANONICAL_SIGNAL_KINDS if k not in kinds]
        if missing:
            raise PrismLawError(
                f"taxonomy config: canonical signal kinds missing: {missing}",
                law="PRISM-L-1",
            )

    # -- lookups ---------------------------------------------------------------

    def levels(self, dimension: str) -> list[str]:
        block = self._config.get(dimension)
        if not isinstance(block, (list, dict)):
            raise PrismLawError(
                f"unknown taxonomy dimension: {dimension!r}", law="PRISM-L-1"
            )
        return list(block)

    def get_dimension_value(self, dimension: str, level: str) -> float:
        block = self._config.get(dimension)
        if not isinstance(block, dict) or level not in block:
            raise PrismLawError(
                f"unknown dimension level: {dimension}.{level}",
                law="PRISM-L-1",
            )
        return float(block[level])

    def classify(self, signal_kind: str) -> EvidenceType:
        evidence_type = (self._config.get("signal_kinds") or {}).get(signal_kind)
        if evidence_type is None:
            raise PrismLawError(
                f"unknown signal kind: {signal_kind!r}", law="PRISM-L-4"
            )
        return EvidenceType(evidence_type)

    def type_bonus(self, evidence_type: EvidenceType) -> float:
        return float(
            (self._config.get("type_bonus") or {}).get(evidence_type.value, 0.0)
        )

    # -- profiling ---------------------------------------------------------------

    def profile(
        self,
        evidence_hash: str,
        source: str,
        signal_kind: str,
        strength: str,
        reproducibility: str,
        corroboration: str,
        rationale: str,
    ) -> EvidenceProfile:
        if not evidence_hash or not rationale:
            raise PrismLawError(
                "a profile requires both an evidence hash and a rationale",
                law="PRISM-L-1",
            )
        try:
            src = EvidenceSource(source)
        except ValueError:
            raise PrismLawError(
                f"unknown evidence source: {source!r}", law="PRISM-L-1"
            ) from None
        evidence_type = self.classify(signal_kind)
        for dimension, level in (
            ("strength", strength),
            ("reproducibility", reproducibility),
            ("corroboration", corroboration),
        ):
            self.get_dimension_value(dimension, level)
        return EvidenceProfile(
            evidence_hash=evidence_hash,
            source=src,
            evidence_type=evidence_type,
            strength=Strength(strength),
            reproducibility=Reproducibility(reproducibility),
            corroboration=Corroboration(corroboration),
            rationale=rationale,
        )


__all__ = [
    "CANONICAL_SIGNAL_KINDS",
    "Corroboration",
    "EvidenceProfile",
    "EvidenceSource",
    "EvidenceTaxonomy",
    "EvidenceType",
    "Reproducibility",
    "Strength",
]
