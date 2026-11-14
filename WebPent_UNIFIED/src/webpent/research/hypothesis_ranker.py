"""Deterministic ranking for open hypotheses."""

from __future__ import annotations

from typing import Any

from webpent.models.hypothesis import Hypothesis
from webpent.research.hypothesis_engine import HypothesisEngine


class HypothesisRanker:
    """Rank hypotheses without using an LLM-generated score."""

    @staticmethod
    def score(value: Hypothesis | dict[str, Any]) -> float:
        hypothesis = HypothesisEngine.coerce(value)
        evidence_factor = min(len(hypothesis.evidence_refs), 4) / 4.0
        return round(
            (0.60 * hypothesis.confidence_score)
            + (0.25 * hypothesis.novelty_score)
            + (0.15 * evidence_factor),
            6,
        )

    @classmethod
    def rank(cls, hypotheses: list[Hypothesis | dict[str, Any]]) -> list[Hypothesis]:
        """Return open hypotheses in stable descending priority order."""
        coerced = [HypothesisEngine.coerce(item) for item in hypotheses]
        open_hypotheses = [item for item in coerced if item.is_open()]
        return sorted(open_hypotheses, key=lambda item: (-cls.score(item), str(item.id)))
