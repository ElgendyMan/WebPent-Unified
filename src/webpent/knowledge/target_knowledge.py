"""Engagement-scoped target knowledge contracts.

This module is deliberately additive.  It stores only bounded, evidence-linked
knowledge projections and never treats a model-generated hypothesis as proof.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class KnowledgeKind(str, Enum):
    """Closed set of knowledge entity kinds used by deterministic planners."""

    HOST = "host"
    ENDPOINT = "endpoint"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    IDENTITY = "identity"
    OBJECT = "object"
    WORKFLOW = "workflow"
    ROLE = "role"
    DATA_STORE = "data_store"


class KnowledgeNode(BaseModel):
    """An evidence-linked entity in the target knowledge model."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    node_id: str = Field(..., min_length=1)
    kind: KnowledgeKind
    canonical_key: str = Field(..., min_length=1)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    in_scope: bool | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_evidence_refs(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(ref for ref in values if ref))


class KnowledgeEdge(BaseModel):
    """A typed, evidence-linked relation between two knowledge nodes."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source_id: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    relation: str = Field(..., min_length=1)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(default_factory=list)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_evidence_refs(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(ref for ref in values if ref))


class WorkflowState(BaseModel):
    """A bounded workflow transition candidate, not an authorization proof."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    workflow_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    required_role: str | None = Field(
        default=None,
        description="Observed role requirement candidate; never an authorization proof.",
    )
    states: list[str] = Field(default_factory=list)
    transitions: list[dict[str, str]] = Field(default_factory=list)
    identity_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class AuthorizationProfile(BaseModel):
    """Observed identity/role context with explicit unknown handling."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    identity_id: str = Field(..., min_length=1)
    role_names: list[str] = Field(default_factory=list)
    observed_capabilities: list[str] = Field(default_factory=list)
    authorization_status: str = "unknown"
    evidence_refs: list[str] = Field(default_factory=list)


class DataFlow(BaseModel):
    """A bounded data-flow observation, never an inferred exfiltration claim."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source_id: str = Field(..., min_length=1)
    destination_id: str = Field(..., min_length=1)
    channel: str = Field(..., min_length=1)
    data_classes: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    observed: bool = False


class TargetKnowledgeModel(BaseModel):
    """Complete deterministic projection used by planning and coverage."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: int = 1
    engagement_id: str = Field(..., min_length=1)
    nodes: dict[str, KnowledgeNode] = Field(default_factory=dict)
    edges: list[KnowledgeEdge] = Field(default_factory=list)
    workflows: dict[str, WorkflowState] = Field(default_factory=dict)
    authorization_profiles: dict[str, AuthorizationProfile] = Field(default_factory=dict)
    data_flows: list[DataFlow] = Field(default_factory=list)
    source: str = "deterministic_projection"

    def add_node(self, node: KnowledgeNode) -> None:
        """Merge a node by stable ID without replacing stronger evidence."""
        current = self.nodes.get(node.node_id)
        if current is None or node.confidence >= current.confidence:
            self.nodes[node.node_id] = node
            return
        current.evidence_refs = list(dict.fromkeys(current.evidence_refs + node.evidence_refs))

    def add_edge(self, edge: KnowledgeEdge) -> None:
        """Add an edge once, merging evidence references on duplicates."""
        for current in self.edges:
            if (
                current.source_id == edge.source_id
                and current.target_id == edge.target_id
                and current.relation == edge.relation
            ):
                current.evidence_refs = list(
                    dict.fromkeys(current.evidence_refs + edge.evidence_refs)
                )
                current.confidence = max(current.confidence, edge.confidence)
                return
        self.edges.append(edge)

    def as_dict(self) -> dict[str, Any]:
        """Return a checkpoint/report-safe JSON-compatible projection."""
        return self.model_dump(mode="json")

    def to_dict(self) -> dict[str, Any]:
        """Backward-compatible serialization alias used by graph nodes."""
        return self.as_dict()


__all__ = [
    "AuthorizationProfile",
    "DataFlow",
    "KnowledgeEdge",
    "KnowledgeKind",
    "KnowledgeNode",
    "TargetKnowledgeModel",
    "WorkflowState",
]
