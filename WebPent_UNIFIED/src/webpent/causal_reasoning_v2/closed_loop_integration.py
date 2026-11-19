# src/webpent/causal_reasoning_v2/closed_loop_integration.py
"""ClosedLoopIntegrator — Deep-fix Phase 4.

Closes the loop between causal recommendations and the actual search queue:

  1. generate_priorities(base_candidates) — merges the scanner's own priority
     list with causal recommendations at a documented weight (default 40%
     causal / 60% direct discovery).  Every output entry carries
     `causal_contribution` so the audit trail shows exactly how much the
     causal engine influenced each decision.

  2. submit_feedback(route, examined, finding) — when a recommended route is
     actually examined, the result (found a vulnerability / nothing found)
     feeds back into the StructuralKnowledgeBase, updating the pattern's
     bayesian confidence and per-component weights.  Refuted patterns decay
     and eventually fall below threshold.

  3. final_report() — impact summary: how many causal recommendations were
     made, how many were examined, confirmation rate, active patterns.

Safe-failure: on ANY exception, generate_priorities returns the base
candidates unchanged (sorted by their original priority) — the pipeline
behaves exactly as it would without the causal engine.  The disabled flag
achieves the same explicitly.
"""
from __future__ import annotations

import traceback
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from webpent.causal_reasoning_v2.architecture_extractor import ArchitectureExtractor
from webpent.causal_reasoning_v2.root_cause_analyzer_v2 import RootCauseAnalyzerV2
from webpent.causal_reasoning_v2.structural_knowledge_base import StructuralKnowledgeBase


@dataclass
class _PendingHint:
    route: str
    pattern_id: str | None
    base_priority: float
    causal_score: float
    examined: bool = False
    found: bool = False


class ClosedLoopIntegrator:
    """Bidirectional integration: causal -> priorities, feedback -> confidence."""

    def __init__(
        self,
        extractor: ArchitectureExtractor | None = None,
        analyzer: RootCauseAnalyzerV2 | None = None,
        knowledge_base: StructuralKnowledgeBase | None = None,
        *,
        causal_weight: float = 0.40,
        disabled: bool = False,
    ):
        self.extractor = extractor
        self.analyzer = analyzer or RootCauseAnalyzerV2(extractor)
        self.kb = knowledge_base or StructuralKnowledgeBase()
        self.causal_weight = max(0.0, min(1.0, float(causal_weight)))
        self.disabled = bool(disabled)
        self.project_id: str = "unknown"
        self.target_profile: dict[str, Any] = {}
        self._pending: dict[str, _PendingHint] = {}
        self._examined_count = 0
        self._confirmed_count = 0
        self._refuted_count = 0

    # ------------------------------------------------------------------
    # Engagement lifecycle
    # ------------------------------------------------------------------
    def set_context(self, project_id: str, target_profile: Mapping[str, Any] | None = None) -> None:
        self.project_id = str(project_id)[:120]
        self.target_profile = dict(target_profile or {})

    def generate_priorities(self, base_candidates: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Merge scanner priorities with causal recommendations.

        Each base candidate is a dict with at least `endpoint`/`route` and
        `priority` (0-1).  Returns a new sorted list; each entry has
        `causal_contribution` (0-1) showing how much the causal engine
        added.  On any error, returns base candidates unchanged.
        """
        base = [dict(c) for c in base_candidates]
        if self.disabled:
            return sorted(base, key=lambda c: c.get("priority", 0.5), reverse=True)
        try:
            return self._generate(base)
        except Exception:
            # Fail-safe: never break the pipeline.  Return base unchanged.
            return sorted(base, key=lambda c: c.get("priority", 0.5), reverse=True)

    def _generate(self, base: list[dict[str, Any]]) -> list[dict[str, Any]]:
        direct_weight = 1.0 - self.causal_weight

        # 1. Query knowledge base for applicable patterns.
        structural_sigs: list[str] = []
        if self.extractor:
            for flaw in self.extractor.detect_verification_order_flaws():
                structural_sigs.append(f"order_flaw {flaw.mutator}")
            for node in self.extractor.nodes.values():
                if node.is_verifier or node.is_mutator:
                    structural_sigs.append(node.qualname)
        patterns = self.kb.query_for_target(
            target_profile=self.target_profile,
            structural_signatures=structural_sigs,
        )

        # 2. Routes flagged by static analysis (verification-order flaws).
        flaw_routes: dict[str, float] = {}
        if self.extractor:
            for flaw in self.extractor.detect_verification_order_flaws():
                flaw_routes[flaw.route] = flaw.confidence

        # 3. Score each base candidate.
        scored: list[dict[str, Any]] = []
        base_routes = {str(c.get("endpoint") or c.get("route") or "") for c in base}
        for c in base:
            route = str(c.get("endpoint") or c.get("route") or "")
            base_prio = float(c.get("priority", 0.5))
            causal_boost = 0.0
            matched_pattern: str | None = None
            if route in flaw_routes:
                causal_boost = max(causal_boost, flaw_routes[route])
                matched_pattern = "static_order_flaw"
            for pat in patterns:
                for glob in pat.get("route_globs", []):
                    if _glob_match(glob, route):
                        causal_boost = max(causal_boost, pat["effective_score"])
                        matched_pattern = pat["pattern_id"]
                        break
            total = min(1.0, base_prio * direct_weight + causal_boost * self.causal_weight)
            contribution = round(max(0.0, total - base_prio * direct_weight), 4)
            entry = {**c, "priority": round(total, 4), "causal_contribution": contribution,
                     "matched_pattern": matched_pattern}
            scored.append(entry)
            if matched_pattern and causal_boost > 0:
                self._pending[route] = _PendingHint(
                    route=route, pattern_id=matched_pattern if matched_pattern != "static_order_flaw" else None,
                    base_priority=base_prio, causal_score=causal_boost,
                )

        # 4. Add routes from knowledge base not already in base (causal-only candidates).
        for pat in patterns:
            for glob in pat.get("route_globs", []):
                if not any(_glob_match(glob, r) for r in base_routes):
                    route = glob
                    if route in self._pending:
                        continue
                    score = pat["effective_score"] * self.causal_weight
                    scored.append({
                        "endpoint": route, "route": route,
                        "priority": round(score, 4),
                        "causal_contribution": round(score, 4),
                        "matched_pattern": pat["pattern_id"],
                        "source": "causal_recommendation",
                    })
                    self._pending[route] = _PendingHint(
                        route=route, pattern_id=pat["pattern_id"],
                        base_priority=0.0, causal_score=pat["effective_score"],
                    )

        scored.sort(key=lambda c: c["priority"], reverse=True)
        return scored

    # ------------------------------------------------------------------
    # Feedback loop
    # ------------------------------------------------------------------
    def submit_feedback(self, route: str, examined: bool, finding: Mapping[str, Any] | None = None) -> None:
        """Record that a recommended route was examined and what was found.

        Updates the knowledge base: confirmed -> pattern confidence rises;
        refuted (examined, nothing found) -> the responsible component is
        down-weighted.  Never raises.
        """
        try:
            hint = self._pending.get(route)
            if hint is None:
                return
            hint.examined = bool(examined)
            if not examined:
                return
            self._examined_count += 1
            confirmed = finding is not None
            hint.found = confirmed
            if confirmed:
                self._confirmed_count += 1
            else:
                self._refuted_count += 1
            if hint.pattern_id and hint.pattern_id in self.kb.patterns:
                pat = self.kb.patterns[hint.pattern_id]
                # Determine which component failed (if refuted): structural
                # mismatch -> structural_match; otherwise -> relevance.
                failed_component = None
                if not confirmed:
                    failed_component = "relevance"  # pattern existed but didn't apply here
                self.kb.add_observation(
                    structural_signature=pat.structural_signature,
                    cause_type=pat.cause_type,
                    confirmed=confirmed,
                    project_id=self.project_id,
                    description=pat.description,
                    fix_hint=pat.fix_hint,
                    route_globs=pat.affected_route_globs,
                    failed_component=failed_component,
                )
        except Exception:
            pass  # feedback must never break the pipeline

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def final_report(self) -> dict[str, Any]:
        total_hints = len(self._pending)
        confirmation_rate = (
            round(self._confirmed_count / max(1, self._examined_count), 4)
            if self._examined_count else 0.0
        )
        return {
            "project_id": self.project_id,
            "causal_weight_used": self.causal_weight,
            "total_causal_recommendations": total_hints,
            "examined": self._examined_count,
            "confirmed_findings": self._confirmed_count,
            "refuted": self._refuted_count,
            "confirmation_rate": confirmation_rate,
            "knowledge_base_summary": self.kb.summary(),
        }


def _glob_match(glob: str, route: str) -> bool:
    """Simple glob: '*' matches one or more path segments (deterministic)."""
    g = [s for s in glob.strip("/").split("/") if s]
    r = [s for s in route.strip("/").split("?")[0].split("#")[0].strip("/").split("/") if s]
    if not g:
        return not r
    if g[-1] == "*":
        # trailing wildcard: prefix match
        return r[: len(g) - 1] == g[:-1] and len(r) >= len(g) - 1
    if len(g) != len(r):
        return False
    for gs, rs in zip(g, r):
        if gs == "*":
            continue
        if gs.lower() != rs.lower():
            return False
    return True


__all__ = ["ClosedLoopIntegrator"]
