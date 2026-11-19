"""Target-scoped vulnerability knowledge graph for ASROS.

The graph is an advisory knowledge projection.  It stores redacted labels and
references only; it cannot execute, authorize, promote, or create findings.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from webpent.models.evidence import redact_sensitive


class KnowledgeNodeKind(str, Enum):
    VULNERABILITY_CLASS = "vulnerability_class"
    ATTACK_PATTERN = "attack_pattern"
    PREREQUISITE = "prerequisite"
    EVIDENCE_PATTERN = "evidence_pattern"
    VALIDATION_STRATEGY = "validation_strategy"


class KnowledgeEdgeKind(str, Enum):
    COMMONLY_RELATED = "commonly_related"
    PREREQUISITE_OF = "prerequisite_of"
    DISCOVERED_BY = "discovered_by"
    DISPROVED_BY = "disproved_by"


class KnowledgeNode(BaseModel):
    """Redacted typed knowledge node with provenance references."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    node_id: str = Field(min_length=3, max_length=220)
    kind: KnowledgeNodeKind
    label: str = Field(min_length=1, max_length=320)
    target_id: str = Field(min_length=1, max_length=200)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    metadata: dict[str, str] = Field(default_factory=dict, max_length=24)

    @field_validator("label", "target_id")
    @classmethod
    def _redact_text(cls, value: str) -> str:
        clean, _ = redact_sensitive(value)
        return clean[:320]

    @field_validator("evidence_refs")
    @classmethod
    def _unique_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(str(value).strip()[:240] for value in values if str(value).strip())
        )

    @field_validator("metadata")
    @classmethod
    def _redact_metadata(cls, values: dict[str, str]) -> dict[str, str]:
        clean: dict[str, str] = {}
        for key, value in values.items():
            safe_key, _ = redact_sensitive(str(key))
            safe_value, _ = redact_sensitive(str(value))
            clean[safe_key[:80]] = safe_value[:240]
        return clean


class KnowledgeEdge(BaseModel):
    """A typed relationship between two knowledge nodes."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    edge_id: str = Field(min_length=3, max_length=240)
    kind: KnowledgeEdgeKind
    source_id: str = Field(min_length=3, max_length=220)
    target_id: str = Field(min_length=3, max_length=220)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(str(value).strip()[:240] for value in values if str(value).strip())
        )


class VulnerabilityKnowledgeGraph(BaseModel):
    """Immutable target-scoped graph used to improve hypothesis quality."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: str = "asros-vulnerability-knowledge-graph-v1"
    target_id: str = Field(min_length=1, max_length=200)
    nodes: tuple[KnowledgeNode, ...] = Field(default=(), max_length=2_000)
    edges: tuple[KnowledgeEdge, ...] = Field(default=(), max_length=4_000)
    authoritative: bool = False
    execution_capability: bool = False

    @model_validator(mode="after")
    def _consistent(self) -> VulnerabilityKnowledgeGraph:
        node_ids = {node.node_id for node in self.nodes}
        if len(node_ids) != len(self.nodes):
            raise ValueError("duplicate_knowledge_node_id")
        edge_ids = {edge.edge_id for edge in self.edges}
        if len(edge_ids) != len(self.edges):
            raise ValueError("duplicate_knowledge_edge_id")
        if any(
            edge.source_id not in node_ids or edge.target_id not in node_ids for edge in self.edges
        ):
            raise ValueError("knowledge_edge_endpoint_missing")
        if any(node.target_id != self.target_id for node in self.nodes):
            raise ValueError("knowledge_node_target_scope_mismatch")
        if self.authoritative or self.execution_capability:
            raise ValueError("knowledge_graph_cannot_grant_authority")
        return self

    def content_hash(self) -> str:
        encoded = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode()).hexdigest()

    def related_node_ids(
        self, node_id: str, *, relation: KnowledgeEdgeKind | None = None
    ) -> tuple[str, ...]:
        if node_id not in {node.node_id for node in self.nodes}:
            raise KeyError(node_id)
        links = [
            edge for edge in self.edges if edge.source_id == node_id or edge.target_id == node_id
        ]
        if relation is not None:
            links = [edge for edge in links if edge.kind == relation]
        return tuple(
            dict.fromkeys(
                edge.target_id if edge.source_id == node_id else edge.source_id for edge in links
            )
        )

    def candidate_validation_strategies(self, attack_pattern_id: str) -> tuple[KnowledgeNode, ...]:
        """Return validation strategies linked to a pattern through prerequisites."""
        pattern = next((node for node in self.nodes if node.node_id == attack_pattern_id), None)
        if pattern is None or pattern.kind != KnowledgeNodeKind.ATTACK_PATTERN:
            raise KeyError(attack_pattern_id)
        strategy_ids = {
            edge.target_id
            for edge in self.edges
            if edge.source_id == attack_pattern_id and edge.kind == KnowledgeEdgeKind.DISCOVERED_BY
        }
        return tuple(node for node in self.nodes if node.node_id in strategy_ids)

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


__all__ = [
    "KnowledgeEdge",
    "KnowledgeEdgeKind",
    "KnowledgeNode",
    "KnowledgeNodeKind",
    "VulnerabilityKnowledgeGraph",
]
