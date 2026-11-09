"""Deterministic, non-authoritative attack-path ranking."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class AttackPathRanker:
    """Rank observed graph edges for planning and coverage display."""

    _CONFIDENCE = {
        "observed": 1,
        "mental_model_observed": 2,
        "relational_observed": 3,
        "relational_differential": 4,
        "causal_observed": 5,
    }

    def rank(self, graph: Mapping[str, Any]) -> list[dict[str, Any]]:
        edges = graph.get("edges", []) if isinstance(graph, Mapping) else []
        ranked = [dict(edge) for edge in edges if isinstance(edge, Mapping)]
        ranked.sort(
            key=lambda edge: (
                self._CONFIDENCE.get(str(edge.get("confidence", "observed")), 0),
                bool(edge.get("evidence_refs")),
                str(edge.get("id", "")),
            ),
            reverse=True,
        )
        return ranked


__all__ = ["AttackPathRanker"]
