"""U-FORGE-6 — The Query Engine.

Publishes the ranking arithmetic from THE FORGE spec:
    score = context_match*0.4 + quality*0.3 + success_rate*0.2
          + novelty*0.1
Deterministic ordering (score desc, then payload_id asc) and a
transparent breakdown on every hit (FORGE-L-9, L-7).
"""
from __future__ import annotations

from webpent.forge.schemas import (
    Family,
    NormalizedPayload,
    ScoredPayload,
    TargetContext,
)

WEIGHT_CONTEXT = 0.4
WEIGHT_QUALITY = 0.3
WEIGHT_SUCCESS = 0.2
WEIGHT_NOVELTY = 0.1

# Content-type to context vocabulary mapping (documented).
_CONTENT_TYPE_CONTEXTS = {
    "application/json": "json",
    "text/html": "html_body",
    "application/xml": "xml",
}


class PayloadQueryEngine:
    """Ranks the corpus against a target context."""

    def __init__(self, indexer) -> None:
        self._indexer = indexer

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def find(self, family: Family, target: TargetContext,
             limit: int = 20, min_quality: float = 0.0
             ) -> list[ScoredPayload]:
        scored: list[ScoredPayload] = []
        for payload in self._indexer.list_by_family(family):
            if payload.quality_score < min_quality:
                continue
            scored.append(self._score(payload, target))
        scored.sort(key=self._sort_key)
        return scored[:limit]

    def find_polyglots(self, contexts: list[str],
                       limit: int = 20) -> list[ScoredPayload]:
        """Payloads that speak several syntaxes; ranked by quality
        first, then novelty, then id (deterministic)."""
        hits = [p for p in self._indexer.list_all()
                if p.is_polyglot and set(contexts) <= set(p.target_context)]
        hits.sort(key=lambda p: (-p.quality_score, -p.novelty_score,
                                 p.payload_id))
        return [ScoredPayload(payload=p, score=p.quality_score,
                              breakdown={"quality": p.quality_score,
                                         "novelty": p.novelty_score})
                for p in hits[:limit]]

    def find_chained(self, base_payload_id: str,
                     limit: int = 20) -> list[ScoredPayload]:
        """Payloads that declare they chain with the base one."""
        hits = [p for p in self._indexer.list_all()
                if base_payload_id in p.chains_with]
        hits.sort(key=lambda p: (-p.quality_score, p.payload_id))
        return [ScoredPayload(payload=p, score=p.quality_score,
                              breakdown={"quality": p.quality_score})
                for p in hits[:limit]]

    # ------------------------------------------------------------------
    # Published arithmetic
    # ------------------------------------------------------------------

    def context_match(self, payload: NormalizedPayload,
                      target: TargetContext) -> float:
        """Mean of three dimensions, each in [0, 1]:
        - if the payload declares no requirement for a dimension, the
          dimension is neutral (0.5): unknown, not zero (L-1 — the
          corpus never claims more than it knows);
        - any overlap with the target's declared value scores 1.0;
        - declared requirement with no overlap scores 0.0.
        """
        tech = self._dimension(payload.target_tech, target.tech_stack)
        waf = self._dimension(payload.target_waf, target.waf_detected)
        target_contexts = list(target.param_context)
        mapped = _CONTENT_TYPE_CONTEXTS.get(target.response_content_type)
        if mapped:
            target_contexts.append(mapped)
        context = self._dimension(payload.target_context, target_contexts)
        return round((tech + waf + context) / 3.0, 4)

    @staticmethod
    def _dimension(required: tuple[str, ...],
                   available: list[str]) -> float:
        if not required:
            return 0.5
        if any(r in available for r in required):
            return 1.0
        return 0.0

    def _score(self, payload: NormalizedPayload,
               target: TargetContext) -> ScoredPayload:
        breakdown = {
            "context_match": self.context_match(payload, target),
            "quality": payload.quality_score,
            "success_rate": self._indexer.success_rate(payload.payload_id),
            "novelty": payload.novelty_score,
        }
        score = (
            breakdown["context_match"] * WEIGHT_CONTEXT
            + breakdown["quality"] * WEIGHT_QUALITY
            + breakdown["success_rate"] * WEIGHT_SUCCESS
            + breakdown["novelty"] * WEIGHT_NOVELTY)
        return ScoredPayload(payload=payload, score=score,
                             breakdown=breakdown)

    @staticmethod
    def _sort_key(scored: ScoredPayload) -> tuple[float, str]:
        return (-scored.score, scored.payload.payload_id)
