"""Autonomous research objective selection for ABHC v3."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from hashlib import sha256
from typing import Any

from .contracts import CoverageState, ResearchMission


def _items(value: object, *names: str) -> tuple[object, ...]:
    if isinstance(value, Mapping):
        for name in names:
            candidate = value.get(name)
            if isinstance(candidate, Mapping):
                return tuple(candidate.values())
            if isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes)):
                return tuple(candidate)
    for name in names:
        candidate = getattr(value, name, None)
        if isinstance(candidate, Mapping):
            return tuple(candidate.values())
        if isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes)):
            return tuple(candidate)
    return ()


def _text(item: object, *names: str, default: str = "") -> str:
    if isinstance(item, Mapping):
        for name in names:
            value = item.get(name)
            if value is not None:
                return str(value)
    for name in names:
        value = getattr(item, name, None)
        if value is not None:
            return str(value)
    return default


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


class AutonomousResearchDirector:
    """Select high-value objectives without executing actions or changing policy."""

    def __init__(self, *, budget: float = 5.0) -> None:
        if budget < 0.0:
            raise ValueError("research_budget_must_be_non_negative")
        self.budget = float(budget)

    def decide(
        self,
        *,
        world_model: object | None = None,
        attack_graph: object | None = None,
        knowledge_graph: object | None = None,
        memory: object | None = None,
        coverage: CoverageState | Mapping[str, object] | None = None,
    ) -> tuple[ResearchMission, ...]:
        candidates: list[tuple[float, str, str, str, tuple[str, ...], tuple[str, ...]]] = []
        for node in _items(attack_graph, "nodes"):
            node_id = _text(node, "id", "node_id", default="node")
            kind = _text(node, "kind", "category", default="asset")
            label = _text(node, "label", "name", default=node_id)
            criticality = _text(node, "criticality", default="medium").lower()
            score = {"critical": 0.95, "high": 0.85, "medium": 0.60, "low": 0.35}.get(
                criticality, 0.45
            )
            category = kind.lower()
            capability = "read_only_observation"
            if category in {"permission", "privilege", "identity", "workflow", "state"}:
                capability = "bounded_boundary_analysis"
            candidates.append(
                (
                    score,
                    node_id,
                    f"Investigate security assumptions around {label}",
                    category,
                    _refs(node),
                    (capability,),
                )
            )
        for item in _items(world_model, "invariants", "observations", "business_intents"):
            identifier = _text(item, "id", "name", "invariant_id", default="world-observation")
            description = _text(item, "description", "statement", "name", default=identifier)
            candidates.append(
                (
                    0.72,
                    identifier,
                    f"Challenge modeled invariant: {description}",
                    "world_model",
                    _refs(item),
                    ("invariant_analysis",),
                )
            )
        for item in _items(knowledge_graph, "entities", "relations", "knowledge_gaps"):
            identifier = _text(item, "id", "relation_id", "name", default="knowledge-item")
            description = _text(item, "description", "relation", "label", default=identifier)
            candidates.append(
                (
                    0.68,
                    identifier,
                    f"Resolve knowledge gap: {description}",
                    "knowledge",
                    _refs(item),
                    ("evidence_review",),
                )
            )
        coverage_unexplored = self._coverage_values(coverage, "unexplored")
        coverage_low = self._coverage_values(coverage, "low_confidence")
        for identifier in coverage_unexplored:
            candidates.append(
                (
                    0.80,
                    identifier,
                    f"Explore uncovered surface {identifier}",
                    "coverage_gap",
                    (),
                    ("surface_discovery",),
                )
            )
        for identifier in coverage_low:
            candidates.append(
                (
                    0.76,
                    identifier,
                    f"Improve confidence for {identifier}",
                    "low_confidence",
                    (),
                    ("evidence_review",),
                )
            )
        memory_summary = self._memory_summary(memory)
        if memory_summary.get("items"):
            candidates.append(
                (
                    0.64,
                    "memory-gaps",
                    "Revisit prior blocked or low-value research paths",
                    "memory",
                    (),
                    ("failure_analysis",),
                )
            )
        unique: dict[str, tuple[float, str, str, str, tuple[str, ...], tuple[str, ...]]] = {}
        for candidate in candidates:
            previous = unique.get(candidate[1])
            if previous is None or candidate[0] > previous[0]:
                unique[candidate[1]] = candidate
        ordered = sorted(unique.values(), key=lambda item: (-item[0], item[1]))
        missions: list[ResearchMission] = []
        remaining = self.budget
        for rank, (score, identifier, objective, area, refs, capabilities) in enumerate(
            ordered, start=1
        ):
            cost = 1.0
            if remaining < cost:
                break
            mission_id = "mission:" + sha256(f"{identifier}|{objective}".encode()).hexdigest()[:16]
            reasoning = f"priority={score:.3f}; source_refs={','.join(refs) or 'none'}; rank={rank}"
            missions.append(
                ResearchMission(
                    mission_id=mission_id,
                    objective=objective,
                    reasoning=reasoning,
                    target_area=area,
                    expected_security_value=round(score, 3),
                    required_capabilities=capabilities,
                    validation_criteria=(
                        "obtain canonical evidence",
                        "apply causal oracle if authorized",
                    ),
                    priority=round(score, 3),
                    budget_cost=cost,
                )
            )
            remaining -= cost
        return tuple(missions)

    @staticmethod
    def _coverage_values(coverage: object | None, field: str) -> tuple[str, ...]:
        if coverage is None:
            return ()
        values = (
            coverage.get(field, ())
            if isinstance(coverage, Mapping)
            else getattr(coverage, field, ())
        )
        return tuple(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))[
            :128
        ]

    @staticmethod
    def _memory_summary(memory: object | None) -> dict[str, Any]:
        if memory is None:
            return {}
        summary = getattr(memory, "researcher_summary", None)
        if callable(summary):
            value = summary(limit=16)
            return value if isinstance(value, dict) else {}
        value = getattr(memory, "summary", None)
        if callable(value):
            result = value()
            return result if isinstance(result, dict) else {}
        return {}


__all__ = ["AutonomousResearchDirector"]
