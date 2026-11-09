# src/webpent/causal_reasoning_v2/confidence_engine.py
"""ConfidenceEngine — Red-Team fix Phase 3.

Fixes vs v1/v2 confidence:
  1. Jeffrey's uninformative prior: confidence = (confirmed + 0.5)/(total + 1).
     A brand-new pattern with 0 observations has NO confidence (not surfaced).
     After 1 confirmation: 1.5/2 = 0.75 (surfaced only at exploratory threshold).
     After 5 confirmations: 5.5/6 = 0.917 (solid).  No inflated 0.5 default.
  2. Adaptive causal weight: weight = confidence * min(1.0, ln(1+total)/ln(10)).
     A pattern with 1 observation gets ~0.3 of the weight of a pattern with 10+.
     The 40% fixed weight is gone — weight scales with evidence.
  3. Feedback states (4-way, not binary):
       EXAMINED_MATCHED   -> full confirmation, confidence rises.
       EXAMINED_UNRELATED -> full refutation, confidence drops (specific component).
       PARTIAL            -> small penalty, stays in queue.
       NOT_EXAMINED       -> stays in pending queue, NO confidence change.
     "Not yet examined" is never treated as "safe".
  4. Pending queue: suggestions remain until explicitly resolved.  No silent
     removal.  No global confidence drop — only the failed component is penalised.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping


class FeedbackState(str, Enum):
    EXAMINED_MATCHED = "examined_matched"       # found the predicted flaw
    EXAMINED_UNRELATED = "examined_unrelated"   # fully examined, nothing there
    PARTIAL = "partial"                         # partially examined, inconclusive
    NOT_EXAMINED = "not_examined"               # not yet looked at


_COMPONENTS = ("structural_match", "historical_success", "relevance")


@dataclass
class PatternConfidence:
    pattern_id: str
    confirmed: int = 0
    total: int = 0
    component_weights: dict[str, float] = field(default_factory=lambda: {c: 1.0 for c in _COMPONENTS})
    pending: dict[str, FeedbackState] = field(default_factory=dict)  # route -> state

    @property
    def jeffrey_confidence(self) -> float:
        """Jeffrey's prior: (c+0.5)/(n+1).  0 observations -> 0.5 but weight≈0."""
        return (self.confirmed + 0.5) / (self.total + 1)

    @property
    def evidence_weight(self) -> float:
        """How much evidence backs this pattern: ln(1+n)/ln(10), capped at 1.
        n=0 -> 0, n=1 -> 0.30, n=9 -> 1.0.  New patterns carry little weight."""
        return min(1.0, math.log(1 + self.total) / math.log(10))

    def effective_weight(self) -> float:
        """Combined weight for priority blending.  0 for unobserved patterns."""
        return round(self.jeffrey_confidence * self.evidence_weight, 4)

    def blended_score(self, structural_match: float = 1.0, relevance: float = 1.0) -> float:
        w = self.component_weights
        comp = (
            min(1.0, structural_match) * w.get("structural_match", 1.0) * 0.4
            + self.jeffrey_confidence * w.get("historical_success", 1.0) * 0.4
            + min(1.0, relevance) * w.get("relevance", 1.0) * 0.2
        )
        return round(min(1.0, max(0.0, comp * self.evidence_weight)), 4)


class ConfidenceEngine:
    """Tracks pattern confidence with Jeffrey prior + adaptive weight + 4-way feedback."""

    SURFACE_THRESHOLD = 0.55  # minimum effective_weight to surface a suggestion

    def __init__(self) -> None:
        self.patterns: dict[str, PatternConfidence] = {}

    def register(self, pattern_id: str) -> PatternConfidence:
        if pattern_id not in self.patterns:
            self.patterns[pattern_id] = PatternConfidence(pattern_id=pattern_id)
        return self.patterns[pattern_id]

    def add_pending(self, pattern_id: str, route: str) -> None:
        pat = self.register(pattern_id)
        if route not in pat.pending:
            pat.pending[route] = FeedbackState.NOT_EXAMINED

    def record_feedback(
        self,
        pattern_id: str,
        route: str,
        state: FeedbackState,
        *,
        failed_component: str | None = None,
    ) -> None:
        """Record feedback.  Only EXAMINED_UNRELATED reduces confidence;
        PARTIAL gives a small penalty; NOT_EXAMINED does nothing."""
        pat = self.register(pattern_id)
        if route not in pat.pending:
            pat.pending[route] = state
        else:
            pat.pending[route] = state

        if state == FeedbackState.EXAMINED_MATCHED:
            pat.total += 1
            pat.confirmed += 1
            for c in _COMPONENTS:
                pat.component_weights[c] = min(2.0, pat.component_weights.get(c, 1.0) * 1.05)
        elif state == FeedbackState.EXAMINED_UNRELATED:
            pat.total += 1
            # confirmed unchanged — this observation was a miss.
            if failed_component in _COMPONENTS:
                pat.component_weights[failed_component] = max(
                    0.1, pat.component_weights.get(failed_component, 1.0) * 0.85,
                )
            else:
                for c in _COMPONENTS:
                    pat.component_weights[c] = max(0.5, pat.component_weights.get(c, 1.0) * 0.97)
        elif state == FeedbackState.PARTIAL:
            # Small penalty on relevance only, stays in queue.
            pat.component_weights["relevance"] = max(
                0.3, pat.component_weights.get("relevance", 1.0) * 0.95,
            )
        # NOT_EXAMINED: no change, stays pending.

    def pending_routes(self, pattern_id: str) -> tuple[str, ...]:
        pat = self.patterns.get(pattern_id)
        if not pat:
            return ()
        return tuple(r for r, s in pat.pending.items() if s == FeedbackState.NOT_EXAMINED)

    def surfaceable_patterns(self, pattern_ids: Iterable[str]) -> list[str]:
        """Return only patterns whose effective_weight >= SURFACE_THRESHOLD."""
        out = []
        for pid in pattern_ids:
            pat = self.patterns.get(pid)
            if pat and pat.effective_weight() >= self.SURFACE_THRESHOLD:
                out.append(pid)
        return out

    def causal_weight_for(self, pattern_id: str) -> float:
        """Adaptive causal weight for priority blending — scales with evidence."""
        pat = self.patterns.get(pattern_id)
        if not pat:
            return 0.0
        # Max 0.40 (the old fixed weight), scaled by evidence_weight.
        return round(0.40 * pat.evidence_weight, 4)

    def summary(self) -> dict[str, Any]:
        total_pending = sum(
            1 for p in self.patterns.values()
            for s in p.pending.values() if s == FeedbackState.NOT_EXAMINED
        )
        return {
            "patterns": len(self.patterns),
            "surfaceable": len(self.surfaceable_patterns(self.patterns.keys())),
            "pending_not_examined": total_pending,
            "details": [
                {"pattern_id": p.pattern_id, "confirmed": p.confirmed, "total": p.total,
                 "jeffrey_confidence": round(p.jeffrey_confidence, 4),
                 "evidence_weight": round(p.evidence_weight, 4),
                 "effective_weight": p.effective_weight()}
                for p in sorted(self.patterns.values(), key=lambda x: x.effective_weight(), reverse=True)
            ],
        }


__all__ = ["ConfidenceEngine", "PatternConfidence", "FeedbackState"]
