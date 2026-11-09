"""THE PRISM — U-PRISM-14, the Cold-Start Accelerator (v89).

A new target means zero knowledge — unless Prism transfers what it
learned from similar targets. Feature-based archetype matching gives a
new target a plan (techniques, priorities, time-to-first-finding
estimate) instantly and deterministically (PRISM-L-8: cold start in
under 5 minutes — this is pure local computation, no network,
PRISM-L-9). Confidence is earned from match quality, never assumed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from webpent.prism.errors import PrismLawError

BASE_HOURS = 4.0


@dataclass(frozen=True)
class Archetype:
    name: str
    features: dict[str, Any]
    typical_techniques: tuple[str, ...]
    learned_from_campaigns: int = 0


@dataclass(frozen=True)
class ColdStartPlan:
    target_id: str
    matched_archetypes: tuple[str, ...]
    recommended_techniques: tuple[str, ...]
    recommended_priorities: tuple[str, ...]
    estimated_time_to_first_finding: float
    confidence: float
    mode: str = "advisory-only (PRISM-L-2)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "matched_archetypes": list(self.matched_archetypes),
            "recommended_techniques": list(self.recommended_techniques),
            "recommended_priorities": list(self.recommended_priorities),
            "estimated_time_to_first_finding": round(
                self.estimated_time_to_first_finding, 6),
            "confidence": round(self.confidence, 6),
            "mode": self.mode,
        }


def _feature_values(features: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for key, value in features.items():
        values.add(f"{key}={str(value).lower()}")
    return values


class ColdStartAccelerator:
    """Archetype matching for brand-new targets (U-PRISM-14)."""

    def __init__(self, config_path: Path | str) -> None:
        path = Path(config_path)
        if not path.is_file():
            raise PrismLawError(
                f"archetypes config not found: {path}", law="PRISM-L-4"
            )
        config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        raw = config.get("archetypes")
        if not isinstance(raw, list) or len(raw) < 5:
            raise PrismLawError(
                "archetypes: at least 5 archetypes are required for a "
                "meaningful cold start (PRISM-L-8)",
                law="PRISM-L-4",
            )
        self._archetypes: list[Archetype] = []
        for entry in raw:
            name = str(entry.get("name", "")).strip()
            if not name:
                raise PrismLawError(
                    "archetypes: every archetype needs a name",
                    law="PRISM-L-4",
                )
            self._archetypes.append(Archetype(
                name=name,
                features=dict(entry.get("features", {})),
                typical_techniques=tuple(
                    str(t) for t in entry.get("typical_techniques", [])
                ),
                learned_from_campaigns=int(
                    entry.get("learned_from_campaigns", 0)
                ),
            ))

    @property
    def archetypes(self) -> list[Archetype]:
        return list(self._archetypes)

    def match_archetypes(
        self, target_features: dict[str, Any]
    ) -> list[tuple[Archetype, float]]:
        if not target_features:
            return []
        wanted = _feature_values(target_features)
        matches: list[tuple[Archetype, float]] = []
        for archetype in self._archetypes:
            have = _feature_values(archetype.features)
            overlap = len(wanted & have)
            score = overlap / len(wanted)
            if overlap:
                matches.append((archetype, score))
        matches.sort(key=lambda pair: (-pair[1], pair[0].name))
        return matches

    def plan(self, target_id: str,
             target_features: dict[str, Any]) -> ColdStartPlan:
        if not target_id:
            raise PrismLawError(
                "a cold-start plan needs a target id", law="PRISM-L-4"
            )
        matches = self.match_archetypes(target_features)
        if not matches:
            raise PrismLawError(
                f"no archetype data matches target {target_id!r}; no plan "
                f"without data (PRISM-L-8)",
                law="PRISM-L-8",
            )
        top_archetype, top_score = matches[0]
        techniques: list[str] = []
        for archetype, _score in matches:
            for technique in archetype.typical_techniques:
                if technique not in techniques:
                    techniques.append(technique)
        priorities = tuple(
            f"{'high' if i < 2 else 'medium' if i < 4 else 'low'}:"
            f"{technique}"
            for i, technique in enumerate(techniques)
        )
        # confidence = match quality, dented when the archetype is
        # still unproven (no campaigns learned from it yet)
        confidence = (
            top_score if top_archetype.learned_from_campaigns > 0
            else top_score * 0.5
        )
        estimated = BASE_HOURS * (1.0 - 0.5 * confidence)
        return ColdStartPlan(
            target_id=target_id,
            matched_archetypes=tuple(a.name for a, _ in matches),
            recommended_techniques=tuple(techniques),
            recommended_priorities=priorities,
            estimated_time_to_first_finding=estimated,
            confidence=confidence,
        )

    @staticmethod
    def estimate_first_finding_time(plan: ColdStartPlan) -> float:
        return plan.estimated_time_to_first_finding


__all__ = ["Archetype", "ColdStartAccelerator", "ColdStartPlan"]
