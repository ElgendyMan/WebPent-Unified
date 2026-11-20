"""Adaptive path selection and dynamic graph updates without exploitation."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import AdaptiveHuntingStrategyV8, DynamicAttackGraphUpdateV8, StrategyMode, V8Status
from .utils import evidence_refs, gap_values, get_value, stable_id, strings, unique_sorted


@dataclass(frozen=True, slots=True)
class AdaptiveHuntingStrategyEngineV8:
    def choose(
        self,
        *,
        engagement_id: str,
        target_id: str,
        investigations: tuple[object, ...] = (),
        hypotheses: tuple[object, ...] = (),
        previous_failures: tuple[str, ...] = (),
        available_capability: tuple[str, ...] = (),
    ) -> AdaptiveHuntingStrategyV8:
        failure_count = len(previous_failures)
        investigation_count = len(investigations)
        hypothesis_count = len(hypotheses)
        if not investigation_count and not hypothesis_count:
            mode = StrategyMode.BROAD_EXPLORATION
            paths = ("record missing model information",)
        elif failure_count:
            mode = StrategyMode.ALTERNATIVE_TESTING
            paths = ("challenge the leading explanation", "compare an independent alternative")
        elif any(
            "evidence" in str(get_value(item, "status", default="")) for item in investigations
        ):
            mode = StrategyMode.EVIDENCE_COLLECTION
            paths = ("close the highest-value evidence gap",)
        else:
            mode = StrategyMode.DEEP_INVESTIGATION
            paths = tuple(
                f"trace investigation {get_value(item, 'investigation_id', default='unknown')}"
                for item in investigations[:3]
            ) or ("trace the highest-value recorded assumption",)
        factors = (
            f"potential paths={max(investigation_count, hypothesis_count)}",
            f"previous failures={failure_count}",
            f"available capabilities={len(available_capability)}",
            "information gain is prioritized over unproven impact",
        )
        next_actions = (
            "read and normalize recorded evidence",
            "compare candidate and negative-control requirements",
            "reassess after contradictory or missing evidence",
        )
        stops = (
            "stop when causal oracle, safe precondition, or replay is absent",
            "stop when behavior may be intended or impact is unproven",
            "stop before network, mutation, credentials, or external scope",
        )
        return AdaptiveHuntingStrategyV8(
            strategy_id=stable_id("strategy", engagement_id, target_id, mode.value, paths),
            mode=mode,
            rationale="select a bounded research mode from recorded state and prior outcomes",
            decision_factors=factors,
            selected_paths=paths,
            next_actions=next_actions,
            stop_conditions=stops,
            adapted_from=tuple(sorted(previous_failures)),
            status=V8Status.ADVISORY,
        )


@dataclass(frozen=True, slots=True)
class DynamicAttackGraphIntelligenceV8:
    def update(
        self,
        *,
        graph_id: str,
        mental_model: object | None = None,
        attack_graph: object | None = None,
        investigations: tuple[object, ...] = (),
    ) -> DynamicAttackGraphUpdateV8:
        assets = strings(get_value(mental_model, "protected_assets", "assets"))
        identities = strings(get_value(attack_graph, "identities", "identity_nodes"))
        permissions = strings(get_value(attack_graph, "permissions", "permission_nodes"))
        actions = strings(get_value(attack_graph, "actions", "action_nodes"))
        states = strings(get_value(attack_graph, "states", "state_nodes"))
        nodes = unique_sorted((*assets, *identities, *permissions, *actions, *states))
        boundaries = unique_sorted(
            [
                (
                    "possible crossing between "
                    f"{get_value(item, 'trust_boundary', default='unknown boundary')} and "
                    f"{get_value(item, 'assumption', default='unknown assumption')}"
                )
                for item in investigations
            ]
        )
        dependencies = gap_values(attack_graph, mental_model)
        edges = tuple(
            (nodes[index], nodes[index + 1], "recorded relationship; causal effect unproven")
            for index in range(max(0, len(nodes) - 1))
        )
        refs = tuple(sorted(set(evidence_refs(mental_model)) | set(evidence_refs(attack_graph))))
        return DynamicAttackGraphUpdateV8(
            graph_id=graph_id,
            added_nodes=nodes,
            added_edges=edges,
            boundary_crossings=boundaries,
            unresolved_dependencies=dependencies,
            trust_relationships=unique_sorted(
                strings(get_value(mental_model, "trust_relationships"))
            ),
            confidence=0.35 if not refs else 0.55,
            evidence_refs=refs,
        )


__all__ = ["AdaptiveHuntingStrategyEngineV8", "DynamicAttackGraphIntelligenceV8"]
