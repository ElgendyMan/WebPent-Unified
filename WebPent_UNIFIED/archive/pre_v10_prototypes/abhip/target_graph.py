"""Evidence-linked target intelligence graph for ABHIP v5."""

from __future__ import annotations

from collections.abc import Iterable

from webpent.knowledge.model_v2 import TargetKnowledgeV2

from .contracts import IntelligenceNode, TargetIntelligenceGraph


class TargetIntelligenceGraphBuilder:
    """Project existing target knowledge into a deeper, non-authoritative graph."""

    def build(
        self,
        knowledge: TargetKnowledgeV2,
        *,
        coverage_gaps: Iterable[str] = (),
    ) -> TargetIntelligenceGraph:
        graph = TargetIntelligenceGraph.from_target_knowledge(knowledge)
        gaps = tuple(
            dict.fromkeys(str(item).strip()[:240] for item in coverage_gaps if str(item).strip())
        )[:128]
        return TargetIntelligenceGraph(
            engagement_id=graph.engagement_id,
            target_id=graph.target_id,
            knowledge_hash=graph.knowledge_hash,
            nodes=graph.nodes,
            relations=graph.relations,
            coverage_gaps=gaps,
        )

    @staticmethod
    def node(graph: TargetIntelligenceGraph, node_id: str) -> IntelligenceNode | None:
        return next((item for item in graph.nodes if item.node_id == node_id), None)

    @staticmethod
    def neighbors(graph: TargetIntelligenceGraph, node_id: str) -> tuple[IntelligenceNode, ...]:
        related_ids: list[str] = []
        for relation in graph.relations:
            if relation.source_node == node_id:
                related_ids.append(relation.destination_node)
            elif relation.destination_node == node_id:
                related_ids.append(relation.source_node)
        return tuple(
            item for item in graph.nodes if item.node_id in set(related_ids)
        )


__all__ = ["TargetIntelligenceGraphBuilder"]
