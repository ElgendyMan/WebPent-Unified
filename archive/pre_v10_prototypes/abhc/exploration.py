"""Adaptive, offline attack-surface exploration for ABHC v3."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .contracts import CoverageState, SurfaceCandidate, SurfaceExplorationReport


class AdaptiveSurfaceExplorer:
    """Rank modeled surfaces and expose gaps; never probes or sends requests."""

    _weights = {
        "privilege": 1.00,
        "permission": 1.00,
        "identity": 0.95,
        "workflow": 0.90,
        "state": 0.88,
        "resource": 0.78,
        "object": 0.76,
        "endpoint": 0.62,
        "asset": 0.50,
    }

    def explore(
        self,
        *,
        attack_graph: object | None = None,
        world_model: object | None = None,
        prior_coverage: CoverageState | Mapping[str, object] | None = None,
        max_surfaces: int = 64,
    ) -> SurfaceExplorationReport:
        if max_surfaces < 1:
            raise ValueError("max_surfaces_must_be_positive")
        candidates: dict[str, SurfaceCandidate] = {}
        for node in self._items(attack_graph, "nodes"):
            node_id = self._text(node, "id", "node_id", default="node")
            kind = self._text(node, "kind", "category", default="asset").lower()
            label = self._text(node, "label", "name", default=node_id)
            metadata = self._mapping(node, "metadata")
            criticality = str(
                metadata.get("criticality", self._text(node, "criticality", default="medium"))
            ).lower()
            confidence = self._confidence(node, metadata)
            explored = node_id in self._coverage_values(prior_coverage, "explored")
            base = self._weights.get(kind, 0.45)
            criticality_bonus = {"critical": 0.15, "high": 0.10, "medium": 0.04, "low": 0.0}.get(
                criticality, 0.0
            )
            potential = min(1.0, base + criticality_bonus)
            priority = min(
                1.0,
                0.55 * potential + 0.30 * (1.0 - confidence) + 0.15 * (0.0 if explored else 1.0),
            )
            refs = self._refs(node)
            reasons = [f"category={kind}", f"criticality={criticality}"]
            if not explored:
                reasons.append("unexplored")
            if confidence < 0.6:
                reasons.append("low_confidence")
            candidates[node_id] = SurfaceCandidate(
                surface_id=node_id,
                category=kind,
                label=label,
                priority=round(priority, 6),
                confidence=round(confidence, 6),
                potential=round(potential, 6),
                explored=explored,
                evidence_refs=refs,
                reasons=tuple(reasons),
            )
        for observation in self._items(
            world_model, "observations", "invariants", "business_intents"
        ):
            identifier = self._text(
                observation, "id", "name", "invariant_id", default="world-observation"
            )
            if identifier in candidates:
                continue
            label = self._text(observation, "description", "statement", "name", default=identifier)
            candidates[identifier] = SurfaceCandidate(
                surface_id=identifier,
                category="world_model",
                label=label,
                priority=0.70,
                confidence=self._confidence(observation, {}),
                potential=0.76,
                explored=identifier in self._coverage_values(prior_coverage, "explored"),
                evidence_refs=self._refs(observation),
                reasons=("modeled_invariant", "requires_semantic_review"),
            )
        ordered = tuple(
            sorted(candidates.values(), key=lambda item: (-item.priority, item.surface_id))
        )[:max_surfaces]
        explored = tuple(item.surface_id for item in ordered if item.explored)
        unexplored = tuple(item.surface_id for item in ordered if not item.explored)
        low_confidence = tuple(item.surface_id for item in ordered if item.confidence < 0.6)
        high_potential = tuple(item.surface_id for item in ordered if item.potential >= 0.75)
        gaps = tuple(dict.fromkeys((*unexplored, *low_confidence)))[:128]
        return SurfaceExplorationReport(
            surfaces=ordered,
            coverage=CoverageState(
                explored=explored,
                unexplored=unexplored,
                low_confidence=low_confidence,
                high_potential=high_potential,
            ),
            knowledge_gaps=gaps,
        )

    @staticmethod
    def _items(value: object | None, *names: str) -> tuple[object, ...]:
        if value is None:
            return ()
        for name in names:
            candidate = (
                value.get(name) if isinstance(value, Mapping) else getattr(value, name, None)
            )
            if isinstance(candidate, Mapping):
                return tuple(candidate.values())
            if isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes)):
                return tuple(candidate)
        return ()

    @staticmethod
    def _mapping(item: object, name: str) -> dict[str, Any]:
        value = item.get(name, {}) if isinstance(item, Mapping) else getattr(item, name, {})
        return dict(value) if isinstance(value, Mapping) else {}

    @staticmethod
    def _text(item: object, *names: str, default: str = "") -> str:
        for name in names:
            value = item.get(name) if isinstance(item, Mapping) else getattr(item, name, None)
            if value is not None:
                return str(value)
        return default

    @staticmethod
    def _refs(item: object) -> tuple[str, ...]:
        value = (
            item.get("source_refs", ())
            if isinstance(item, Mapping)
            else getattr(item, "source_refs", ())
        )
        if not value:
            value = (
                item.get("evidence_refs", ())
                if isinstance(item, Mapping)
                else getattr(item, "evidence_refs", ())
            )
        return tuple(dict.fromkeys(str(ref).strip() for ref in value if str(ref).strip()))[:32]

    @staticmethod
    def _confidence(item: object, metadata: Mapping[str, Any]) -> float:
        raw = metadata.get("confidence")
        if raw is None:
            raw = (
                item.get("confidence")
                if isinstance(item, Mapping)
                else getattr(item, "confidence", None)
            )
        if isinstance(raw, (int, float)):
            return max(0.0, min(1.0, float(raw)))
        if str(raw).lower() in {"high", "confirmed"}:
            return 0.9
        if str(raw).lower() in {"medium", "observed"}:
            return 0.65
        return 0.35

    @staticmethod
    def _coverage_values(coverage: object | None, field: str) -> tuple[str, ...]:
        if coverage is None:
            return ()
        value = (
            coverage.get(field, ())
            if isinstance(coverage, Mapping)
            else getattr(coverage, field, ())
        )
        return tuple(str(item).strip() for item in value if str(item).strip())


__all__ = ["AdaptiveSurfaceExplorer"]
