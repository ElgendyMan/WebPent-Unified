"""Unified research brain construction for ABHIE v4."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import replace
from typing import Any

from .contracts import (
    BrainObservation,
    EvidenceRef,
    ResearchBrainState,
    SecurityAssumption,
)


def _read(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _items(value: Any) -> tuple[Any, ...]:
    if isinstance(value, Mapping):
        return tuple(value.values())
    return tuple(value or ())


class ResearchBrainBuilder:
    """Builds a bounded state projection; it never executes a research action."""

    def build(
        self,
        *,
        target_ref: str,
        engagement_ref: str,
        knowledge: Any = None,
        attack_graph: Any = None,
        invariants: Iterable[Any] = (),
        memory_lessons: Iterable[str] = (),
        evidence: Iterable[EvidenceRef] = (),
        history: Iterable[str] = (),
    ) -> ResearchBrainState:
        observations: list[BrainObservation] = []
        unknowns: set[str] = set()
        assumptions: list[SecurityAssumption] = []

        entities = _items(_read(knowledge, "entities", ()))
        for index, entity in enumerate(entities):
            asset = str(_read(entity, "name", _read(entity, "entity_id", f"asset-{index}")))
            statement = str(_read(entity, "description", _read(entity, "content", asset)))
            observations.append(
                BrainObservation(
                    observation_id=f"knowledge-{index}",
                    target_ref=target_ref,
                    asset=asset,
                    domain=str(_read(entity, "kind", "asset")),
                    statement=statement,
                    confidence=float(_read(entity, "confidence", 0.5) or 0.5),
                )
            )

        nodes = _items(_read(attack_graph, "nodes", ()))
        for index, node in enumerate(nodes):
            asset = str(_read(node, "node_id", _read(node, "id", f"graph-{index}")))
            label = str(_read(node, "label", _read(node, "name", asset)))
            observations.append(
                BrainObservation(
                    observation_id=f"graph-{index}",
                    target_ref=target_ref,
                    asset=asset,
                    domain=str(_read(node, "kind", _read(node, "node_type", "graph"))),
                    statement=label,
                    confidence=0.6,
                )
            )

        for index, invariant in enumerate(invariants):
            statement = str(_read(invariant, "statement", _read(invariant, "name", "invariant")))
            refs = tuple(str(item) for item in (_read(invariant, "evidence_refs", ()) or ()))
            assumptions.append(
                SecurityAssumption(
                    assumption_id=f"assumption-{index}",
                    statement=statement,
                    domain=str(_read(invariant, "domain", "security")),
                    affected_assets=tuple(
                        str(item) for item in (_read(invariant, "assets", ()) or ())
                    ),
                    risk=0.65,
                    source_refs=refs,
                    falsifiers=("independent negative control", "causal evidence"),
                )
            )

        if not observations:
            unknowns.add("application asset semantics are not sufficiently observed")
        if not assumptions:
            unknowns.add(
                "security invariants and ownership assumptions are not sufficiently observed"
            )
        if not nodes:
            unknowns.add("attack-surface graph coverage is incomplete")

        dedup_observations = tuple(
            sorted(
                {item.observation_id: item for item in observations}.values(),
                key=lambda item: item.observation_id,
            )
        )
        dedup_assumptions = tuple(
            sorted(
                {item.assumption_id: item for item in assumptions}.values(),
                key=lambda item: item.assumption_id,
            )
        )
        return ResearchBrainState(
            target_ref=target_ref,
            engagement_ref=engagement_ref,
            known=dedup_observations,
            unknowns=tuple(sorted(unknowns)),
            risky_assumptions=dedup_assumptions,
            research_history=tuple(sorted({str(item) for item in history})),
            evidence=tuple(sorted(set(evidence), key=lambda item: item.evidence_id)),
        )

    def append_history(self, state: ResearchBrainState, event: str) -> ResearchBrainState:
        if not event.strip():
            raise ValueError("history event must not be empty")
        return replace(
            state,
            research_history=tuple(sorted(set(state.research_history + (event,)))),
        )


class ResearchBrainStateStore:
    """Explicit target/engagement-scoped store with no implicit global state."""

    def __init__(self) -> None:
        self._states: dict[tuple[str, str], ResearchBrainState] = {}

    def put(self, state: ResearchBrainState) -> None:
        self._states[(state.target_ref, state.engagement_ref)] = state

    def get(self, target_ref: str, engagement_ref: str) -> ResearchBrainState | None:
        return self._states.get((target_ref, engagement_ref))

    def snapshot(self, target_ref: str, engagement_ref: str) -> str:
        state = self.get(target_ref, engagement_ref)
        if state is None:
            raise KeyError("scoped brain state not found")
        return state.snapshot()

    def restore(self, snapshot: str) -> ResearchBrainState:
        state = ResearchBrainState.restore(snapshot)
        self.put(state)
        return state
