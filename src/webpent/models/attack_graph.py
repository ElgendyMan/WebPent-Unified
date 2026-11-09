"""Typed, redacted Attack Graph projections for adaptive WebPent planning.

The Attack Graph is an additive projection.  It does not replace the existing
Mental Model, findings, or relational-evidence contracts.  Node identifiers are
stable fingerprints where an input could contain a credential, object id, or
other sensitive value; edge evidence is represented by references only.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AttackGraphNodeKind(str, Enum):
    ASSET = "asset"
    IDENTITY = "identity"
    PERMISSION = "permission"
    PRIVILEGE = "privilege"
    STATE = "state"
    RESOURCE = "resource"
    ACTION = "action"
    IMPACT = "impact"
    OBJECT = "object"
    WORKFLOW = "workflow"
    ENDPOINT = "endpoint"
    FINDING = "finding"
    HYPOTHESIS = "hypothesis"


class AttackGraphNode(BaseModel):
    """A redacted graph node with deterministic identity and provenance."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    id: str = Field(min_length=3, max_length=200)
    kind: AttackGraphNodeKind
    label: str = Field(min_length=1, max_length=160)
    status: str = Field(default="observed", max_length=80)
    criticality: str = Field(default="medium", max_length=20)
    source_refs: list[str] = Field(default_factory=list, max_length=50)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackGraphEdge(BaseModel):
    """A typed relationship between graph nodes.

    ``evidence_refs`` must point to canonical observations or findings; raw
    request/response material is intentionally not part of this model.
    """

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    id: str = Field(min_length=3, max_length=220)
    kind: str = Field(min_length=1, max_length=80)
    source_id: str = Field(min_length=3, max_length=200)
    target_id: str = Field(min_length=3, max_length=200)
    confidence: str = Field(default="observed", max_length=40)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackGraph(BaseModel):
    """Serializable Attack Graph projection carried in optional state."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    version: str = "1"
    nodes: dict[str, AttackGraphNode] = Field(default_factory=dict)
    edges: list[AttackGraphEdge] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list, max_length=100)
    knowledge_gaps: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    runtime_capability_gaps: list[dict[str, Any]] = Field(
        default_factory=list, max_length=100
    )
    generated_from: list[str] = Field(default_factory=list, max_length=50)
    consistency_errors: list[str] = Field(default_factory=list, max_length=100)
    recommended_path_ids: list[str] = Field(default_factory=list, max_length=32)


__all__ = [
    "AttackGraph",
    "AttackGraphEdge",
    "AttackGraphNode",
    "AttackGraphNodeKind",
]
