"""Read-only entity graph facade over :class:`TargetKnowledgeModel`."""

from __future__ import annotations

from collections.abc import Iterable

from webpent.knowledge.target_knowledge import KnowledgeEdge, KnowledgeNode, TargetKnowledgeModel


class EntityGraph:
    """Bounded graph view used by planners and coverage reporting."""

    def __init__(self, model: TargetKnowledgeModel) -> None:
        self.model = model

    @classmethod
    def from_model(cls, model: TargetKnowledgeModel) -> EntityGraph:
        return cls(model)

    @property
    def nodes(self) -> tuple[KnowledgeNode, ...]:
        return tuple(self.model.nodes.values())

    @property
    def edges(self) -> tuple[KnowledgeEdge, ...]:
        return tuple(self.model.edges)

    def nodes_of_kind(self, kind: str) -> tuple[KnowledgeNode, ...]:
        return tuple(node for node in self.nodes if node.kind.value == str(kind))

    def neighbors(self, node_id: str) -> tuple[str, ...]:
        related: list[str] = []
        for edge in self.edges:
            if edge.source_id == node_id:
                related.append(edge.target_id)
            elif edge.target_id == node_id:
                related.append(edge.source_id)
        return tuple(dict.fromkeys(related))

    def evidence_refs(self, node_ids: Iterable[str] = ()) -> tuple[str, ...]:
        selected = set(node_ids)
        refs: list[str] = []
        for node in self.nodes:
            if not selected or node.node_id in selected:
                refs.extend(node.evidence_refs)
        for edge in self.edges:
            if not selected or edge.source_id in selected or edge.target_id in selected:
                refs.extend(edge.evidence_refs)
        return tuple(dict.fromkeys(ref for ref in refs if ref))


__all__ = ["EntityGraph"]
