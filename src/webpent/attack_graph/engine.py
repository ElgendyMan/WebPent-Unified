"""Deterministic Attack Graph Engine for advisory security research.

The engine projects already-collected target knowledge into a typed graph.  It
never sends requests, authorizes actions, or treats a graph path as a finding.
Every edge must retain an evidence reference, and inconsistent input is
reported rather than repaired silently.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from webpent.knowledge.model_v2 import KnowledgeEntityKind, TargetKnowledgeV2
from webpent.models.attack_graph import (
    AttackGraph,
    AttackGraphEdge,
    AttackGraphNode,
    AttackGraphNodeKind,
)

_KIND_MAP = {
    KnowledgeEntityKind.APPLICATION.value: AttackGraphNodeKind.ASSET,
    KnowledgeEntityKind.ENDPOINT.value: AttackGraphNodeKind.ENDPOINT,
    KnowledgeEntityKind.PARAMETER.value: AttackGraphNodeKind.OBJECT,
    KnowledgeEntityKind.ROLE.value: AttackGraphNodeKind.IDENTITY,
    KnowledgeEntityKind.USER.value: AttackGraphNodeKind.IDENTITY,
    KnowledgeEntityKind.IDENTITY.value: AttackGraphNodeKind.IDENTITY,
    KnowledgeEntityKind.RESOURCE.value: AttackGraphNodeKind.RESOURCE,
    KnowledgeEntityKind.OBJECT.value: AttackGraphNodeKind.OBJECT,
    KnowledgeEntityKind.PERMISSION.value: AttackGraphNodeKind.PERMISSION,
    KnowledgeEntityKind.DATA_FLOW.value: AttackGraphNodeKind.OBJECT,
    KnowledgeEntityKind.WORKFLOW.value: AttackGraphNodeKind.WORKFLOW,
    KnowledgeEntityKind.TRUST_BOUNDARY.value: AttackGraphNodeKind.STATE,
    KnowledgeEntityKind.SECURITY_CONTROL.value: AttackGraphNodeKind.PRIVILEGE,
    KnowledgeEntityKind.SERVICE.value: AttackGraphNodeKind.ASSET,
}


class AttackGraphEngine:
    """Build and inspect a deterministic, evidence-linked attack graph."""

    def build(self, knowledge: TargetKnowledgeV2) -> AttackGraph:
        if not isinstance(knowledge, TargetKnowledgeV2):
            raise TypeError("target_knowledge_v2_required")
        nodes: dict[str, AttackGraphNode] = {}
        errors: list[str] = []
        for entity_id in sorted(knowledge.entities):
            entity = knowledge.entities[entity_id]
            node_kind = _KIND_MAP.get(entity.kind.value)
            if node_kind is None:
                errors.append(f"unsupported_entity_kind:{entity.kind.value}")
                continue
            nodes[entity_id] = AttackGraphNode(
                id=entity.entity_id,
                kind=node_kind,
                label=entity.canonical_key,
                status=entity.lifecycle.value,
                criticality="high"
                if entity.kind
                in {
                    KnowledgeEntityKind.PERMISSION,
                    KnowledgeEntityKind.TRUST_BOUNDARY,
                }
                else "medium",
                source_refs=list(entity.evidence_refs),
                metadata={"source_observation": entity.source_observation},
            )

        edges: list[AttackGraphEdge] = []
        for relation in sorted(knowledge.relations, key=lambda item: item.relation_id):
            if relation.source_entity not in nodes or relation.target_entity not in nodes:
                errors.append(f"relation_endpoint_missing:{relation.relation_id}")
                continue
            if relation.source_observation not in knowledge.observations:
                errors.append(f"relation_observation_missing:{relation.relation_id}")
                continue
            if not relation.evidence_refs:
                errors.append(f"relation_evidence_missing:{relation.relation_id}")
                continue
            edges.append(
                AttackGraphEdge(
                    id=relation.relation_id,
                    kind=relation.relation,
                    source_id=relation.source_entity,
                    target_id=relation.target_entity,
                    confidence=("validated" if relation.confidence >= 0.9 else "observed"),
                    evidence_refs=list(relation.evidence_refs),
                )
            )

        graph = AttackGraph(
            version="2",
            nodes=nodes,
            edges=edges,
            coverage_gaps=self._coverage_gaps(knowledge),
            generated_from=[knowledge.content_hash()],
            consistency_errors=sorted(set(errors)),
        )
        return graph.model_copy(update={"recommended_path_ids": self.recommend_paths(graph)})

    @staticmethod
    def _coverage_gaps(knowledge: TargetKnowledgeV2) -> list[str]:
        present = {entity.kind.value for entity in knowledge.entities.values()}
        gaps: list[str] = []
        if KnowledgeEntityKind.ENDPOINT.value not in present:
            gaps.append("no_endpoints")
        if (
            KnowledgeEntityKind.IDENTITY.value not in present
            and KnowledgeEntityKind.USER.value not in present
        ):
            gaps.append("no_identity_model")
        if KnowledgeEntityKind.PERMISSION.value not in present:
            gaps.append("no_permission_model")
        if not knowledge.relations:
            gaps.append("no_relationships")
        return gaps

    @staticmethod
    def consistency_errors(graph: AttackGraph | Mapping[str, Any]) -> tuple[str, ...]:
        if isinstance(graph, AttackGraph):
            return tuple(graph.consistency_errors)
        if not isinstance(graph, Mapping):
            return ("graph_not_mapping",)
        raw = graph.get("consistency_errors") or ()
        return tuple(dict.fromkeys(str(item) for item in raw if str(item).strip()))

    @staticmethod
    def recommend_paths(graph: AttackGraph | Mapping[str, Any], *, max_paths: int = 8) -> list[str]:
        """Return path IDs that have explicit evidence and cross a boundary.

        This is a planning hint only.  The engine does not infer that a path is
        exploitable, and it never emits a confirmed vulnerability verdict.
        """
        if isinstance(graph, AttackGraph):
            nodes = graph.nodes
            edges = graph.edges
        elif isinstance(graph, Mapping):
            nodes = graph.get("nodes") or {}
            edges = graph.get("edges") or []
        else:
            return []
        adjacency: dict[str, list[AttackGraphEdge | Mapping[str, Any]]] = {}
        for raw_edge in edges:
            edge = raw_edge if isinstance(raw_edge, AttackGraphEdge) else raw_edge
            source = (
                edge.source_id
                if isinstance(edge, AttackGraphEdge)
                else str(edge.get("source_id") or "")
            )
            if not source:
                continue
            refs = (
                edge.evidence_refs
                if isinstance(edge, AttackGraphEdge)
                else edge.get("evidence_refs")
            )
            if not refs:
                continue
            adjacency.setdefault(source, []).append(edge)
        candidates: list[tuple[float, str]] = []
        for source_id, outgoing in adjacency.items():
            source_kind = AttackGraphEngine._node_kind(nodes, source_id)
            for raw_edge in outgoing:
                target_id = (
                    raw_edge.target_id
                    if isinstance(raw_edge, AttackGraphEdge)
                    else str(raw_edge.get("target_id") or "")
                )
                target_kind = AttackGraphEngine._node_kind(nodes, target_id)
                kind = (
                    raw_edge.kind
                    if isinstance(raw_edge, AttackGraphEdge)
                    else str(raw_edge.get("kind") or "")
                )
                if not target_id or not target_kind:
                    continue
                boundary = source_kind in {
                    "identity",
                    "permission",
                    "privilege",
                    "state",
                } or target_kind in {"identity", "permission", "privilege", "state"}
                if not boundary:
                    continue
                edge_id = (
                    raw_edge.id
                    if isinstance(raw_edge, AttackGraphEdge)
                    else str(raw_edge.get("id") or "")
                )
                digest = hashlib.sha256(
                    f"{source_id}|{target_id}|{kind}|{edge_id}".encode()
                ).hexdigest()[:16]
                score = 1.0 if kind in {"can_access", "can_modify", "exposes", "trusts"} else 0.5
                candidates.append((score, f"path:{digest}"))
        candidates.sort(key=lambda item: (-item[0], item[1]))
        return [path_id for _, path_id in candidates[: max(1, min(int(max_paths), 32))]]

    @staticmethod
    def _node_kind(nodes: Any, node_id: str) -> str:
        node = nodes.get(node_id) if isinstance(nodes, Mapping) else None
        if isinstance(node, AttackGraphNode):
            return getattr(node.kind, "value", str(node.kind))
        if isinstance(node, Mapping):
            kind = node.get("kind")
            return getattr(kind, "value", str(kind or ""))
        return ""


__all__ = ["AttackGraphEngine"]
