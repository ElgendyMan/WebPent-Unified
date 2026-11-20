"""Passive, redaction-safe application-intent and identity contracts.

These models describe evidence-backed intent signals only.  They do not execute
requests, authenticate identities, or promote observations to findings.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import redact_sensitive

IntentNodeType = Literal[
    "actor",
    "object",
    "field",
    "trust_boundary",
    "sink",
    "state_transition",
    "background_job",
    "service_dependency",
]

IdentityRole = Literal[
    "anonymous",
    "owner",
    "foreign_user",
    "tenant_admin",
    "global_admin",
]

IdentityDisposition = Literal["observed", "not_observed", "blocked", "inconclusive"]


class IntentNode(BaseModel):
    """A bounded application-intent entity backed by collected evidence."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    node_id: str = Field(..., min_length=8, max_length=160)
    node_type: IntentNodeType
    label: str = Field(..., min_length=1, max_length=160)
    attributes: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    provenance: list[str] = Field(default_factory=list, max_length=20)
    confidence: float = Field(default=0.3, ge=0.0, le=1.0)

    @field_validator("label", "attributes", "evidence_refs", "provenance", mode="before")
    @classmethod
    def _redact_values(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class IntentEdge(BaseModel):
    """A typed relation between two intent entities."""

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


class IdentityContext(BaseModel):
    """An identity-matrix row; observed does not imply authenticated execution."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    context_id: str = Field(..., min_length=8, max_length=160)
    role: IdentityRole
    disposition: IdentityDisposition = "not_observed"
    authenticated: bool = False
    tenant_ref: str | None = Field(default=None, max_length=160)
    session_health: Literal["unknown", "healthy", "stale", "invalid"] = "unknown"
    capability_refs: list[str] = Field(default_factory=list, max_length=12)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    provenance: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("tenant_ref", "capability_refs", "evidence_refs", "provenance", mode="before")
    @classmethod
    def _redact_values(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class ApplicationIntentModel(BaseModel):
    """Bounded application-intent projection derived from passive metadata."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    schema_version: str = "application-intent-v1"
    actors: list[IntentNode] = Field(default_factory=list, max_length=20)
    objects: list[IntentNode] = Field(default_factory=list, max_length=50)
    fields: list[IntentNode] = Field(default_factory=list, max_length=80)
    trust_boundaries: list[IntentNode] = Field(default_factory=list, max_length=20)
    sinks: list[IntentNode] = Field(default_factory=list, max_length=40)
    state_transitions: list[IntentNode] = Field(default_factory=list, max_length=60)
    background_jobs: list[IntentNode] = Field(default_factory=list, max_length=30)
    service_dependencies: list[IntentNode] = Field(default_factory=list, max_length=30)
    identities: list[IdentityContext] = Field(default_factory=list, max_length=5)
    edges: list[IntentEdge] = Field(default_factory=list, max_length=160)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)
    bounded: bool = True
    passive_only: bool = True

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


__all__ = [
    "ApplicationIntentModel",
    "IdentityContext",
    "IdentityDisposition",
    "IdentityRole",
    "IntentEdge",
    "IntentNode",
    "IntentNodeType",
]
