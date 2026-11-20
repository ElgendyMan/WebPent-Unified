"""Judgment Council — U-JC-4: the Evidence Weigher.

Deterministic weighting of evidence (JC-L-2):

    Weight = source_reliability x recency_factor x specificity_factor
             x corroboration_factor

    source_reliability    0.3-1.0   documented table (signal 1.0,
                                    metric 0.9, lesson 0.7, prior 0.5,
                                    unknown 0.3)
    recency_factor        0.5-1.0   exponential decay, half-life 30 days
    specificity_factor    0.4-1.0   0.4 + 0.6 x specificity
    corroboration_factor  1.0-1.5   1.5 when >= 2 independent sources
                                    carry the same claim

Every weight carries its full component breakdown (L-4).
"""

from __future__ import annotations

from typing import Any

from webpent.jc.contracts import (
    SOURCE_RELIABILITY,
    Evidence,
    WeightedEvidence,
    utc,
)

HALF_LIFE_DAYS = 30.0
MIN_RECENCY = 0.5
MIN_SPECIFICITY = 0.4
CORROBORATION_BONUS = 1.5


def recency_factor(observed_at: Any, now: Any) -> float:
    """Exponential decay with a 30-day half-life, floor 0.5."""
    observed = utc(observed_at)
    reference = utc(now)
    age_days = max(0.0, (reference - observed).total_seconds() / 86400.0)
    decayed = 0.5 ** (age_days / HALF_LIFE_DAYS)
    return max(MIN_RECENCY, decayed)


def specificity_factor(specificity: float) -> float:
    """Specific evidence outweighs generic evidence, floor 0.4."""
    return MIN_SPECIFICITY + (1.0 - MIN_SPECIFICITY) * max(0.0, min(1.0, specificity))


class EvidenceWeigher:
    """Weights evidence with a fully transparent component breakdown."""

    def __init__(self, *, now: Any = None) -> None:
        self._now = utc(now)

    def weigh(self, evidence: Evidence, context: dict | None = None) -> WeightedEvidence:
        """Weight one evidence item (no corroboration possible alone)."""
        return self._weigh_one(evidence, corroboration=1.0, now=self._now)

    def weigh_all(self, evidence_list: list[Evidence]) -> list[WeightedEvidence]:
        """Weight a list; items repeated across >=2 independent sources
        earn the corroboration bonus (same kind+content, distinct source).
        """
        items = list(evidence_list or [])
        # corroborated claims: identical (kind, content) from distinct sources
        groups: dict[tuple[str, str], set[str]] = {}
        for e in items:
            groups.setdefault((e.kind, e.content), set()).add(e.source)
        corroborated = {
            key for key, sources in groups.items() if len(sources) >= 2
        }
        weighted = []
        for e in items:
            bonus = CORROBORATION_BONUS if (e.kind, e.content) in corroborated else 1.0
            weighted.append(self._weigh_one(e, corroboration=bonus, now=self._now))
        return weighted

    @staticmethod
    def _weigh_one(e: Evidence, *, corroboration: float, now: Any) -> WeightedEvidence:
        reliability = SOURCE_RELIABILITY.get(e.kind, SOURCE_RELIABILITY["unknown"])
        recency = recency_factor(e.observed_at, now)
        specificity = specificity_factor(e.specificity)
        weight = reliability * recency * specificity * corroboration
        components = {
            "source_reliability": reliability,
            "recency_factor": recency,
            "specificity_factor": specificity,
            "corroboration_factor": corroboration,
        }
        rationale = (
            f"kind {e.kind} -> reliability {reliability:.2f}; recency "
            f"{recency:.2f} (30d half-life); specificity {specificity:.2f}; "
            f"corroboration x{corroboration:.2f}"
        )
        return WeightedEvidence(
            evidence=e, weight=weight, components=components, rationale=rationale
        )


__all__ = [
    "CORROBORATION_BONUS",
    "HALF_LIFE_DAYS",
    "EvidenceWeigher",
    "recency_factor",
    "specificity_factor",
]
