"""Typed passive Surface Evidence Graph contracts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import redact_sensitive

SurfaceNodeType = Literal[
    "endpoint",
    "form",
    "xhr",
    "openapi_route",
    "graphql_operation",
    "multipart_field",
    "service_fingerprint",
    "browser_context",
    "workflow_ref",
]

SurfaceDisposition = Literal[
    "observed",
    "needs_validator",
    "blocked",
    "inconclusive",
    "not_observed",
]


class SurfaceNode(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    node_id: str = Field(..., min_length=8, max_length=160)
    node_type: SurfaceNodeType
    label: str = Field(..., min_length=1, max_length=240)
    method: str | None = Field(default=None, max_length=12)
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    provenance: list[str] = Field(default_factory=list, max_length=20)
    disposition: SurfaceDisposition = "observed"

    @field_validator("label", "metadata", "evidence_refs", "provenance", mode="before")
    @classmethod
    def _redact_values(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class SurfaceEdge(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    edge_id: str = Field(..., min_length=8, max_length=160)
    source_id: str = Field(..., min_length=8, max_length=160)
    target_id: str = Field(..., min_length=8, max_length=160)
    relation: str = Field(..., min_length=1, max_length=80)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    provenance: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("relation", "evidence_refs", "provenance", mode="before")
    @classmethod
    def _redact_values(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class SurfaceDispositionEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    node_id: str = Field(..., min_length=8, max_length=160)
    disposition: SurfaceDisposition
    required_capability: str = Field(..., min_length=1, max_length=100)
    reason: str = Field(..., min_length=1, max_length=500)
    validator_id: str | None = Field(default=None, max_length=120)
    provenance: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("reason", "validator_id", "provenance", mode="before")
    @classmethod
    def _redact_values(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class SurfaceEvidenceGraph(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    schema_version: str = "surface-evidence-graph-v1"
    nodes: list[SurfaceNode] = Field(default_factory=list, max_length=250)
    edges: list[SurfaceEdge] = Field(default_factory=list, max_length=500)
    disposition_queue: list[SurfaceDispositionEntry] = Field(default_factory=list, max_length=250)
    coverage_gaps: list[str] = Field(default_factory=list, max_length=100)
    coverage_blockers: list[dict[str, str]] = Field(default_factory=list, max_length=100)
    family_counts: dict[str, int] = Field(default_factory=dict)
    bounded: bool = True
    passive_only: bool = True

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


__all__ = [
    "SurfaceDisposition",
    "SurfaceDispositionEntry",
    "SurfaceEdge",
    "SurfaceEvidenceGraph",
    "SurfaceNode",
    "SurfaceNodeType",
]
