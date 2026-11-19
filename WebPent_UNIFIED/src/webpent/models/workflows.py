"""Typed workflow observations and bounded business-logic hypothesis contracts.

The models in this module are additive.  They describe evidence-backed workflow
signals without executing state-changing actions.  Values are redacted before
being persisted or passed downstream.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import redact_sensitive
from webpent.models.findings import VulnClass

WorkflowSignal = Literal[
    "form",
    "method_sequence",
    "redirect",
    "cookie_change",
    "csrf_change",
    "token_change",
    "response_state",
    "api_sequence",
    "object_reference",
    "identity_context",
    "role_boundary",
    "workflow_intent",
]


class WorkflowObservation(BaseModel):
    """A redacted, deterministic observation about a workflow transition."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    fingerprint: str = Field(..., min_length=8, max_length=128)
    workflow_key: str = Field(..., min_length=1, max_length=200)
    transition_key: str = Field(..., min_length=1, max_length=200)
    source_ref: str = Field(..., min_length=1, max_length=500)
    endpoint: str = Field(..., min_length=1, max_length=1000)
    method: str = Field(..., min_length=1, max_length=12)
    from_state: str = Field(default="unknown", max_length=120)
    to_state: str = Field(default="unknown", max_length=120)
    signals: list[WorkflowSignal] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list, max_length=12)
    identity_ref: str | None = Field(default=None, max_length=200)
    tenant_ref: str | None = Field(default=None, max_length=200)
    identity_context: list[str] = Field(default_factory=list, max_length=8)
    subject_refs: list[str] = Field(default_factory=list, max_length=20)
    authorization_boundary: Literal[
        "unknown",
        "same_identity",
        "cross_identity",
        "role_scoped",
        "object_scoped",
    ] = "unknown"
    intent_tags: list[str] = Field(default_factory=list, max_length=8)
    object_refs: list[str] = Field(default_factory=list, max_length=20)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    scope_decision: Literal["allowed", "denied", "unknown"] = "unknown"
    destructive: bool = False

    @field_validator(
        "workflow_key",
        "transition_key",
        "source_ref",
        "endpoint",
        "from_state",
        "to_state",
        "identity_ref",
        "tenant_ref",
        "identity_context",
        "subject_refs",
        "intent_tags",
        "prerequisites",
        "object_refs",
        "evidence_refs",
        mode="before",
    )
    @classmethod
    def _redact_strings(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class BusinessLogicHypothesisSpec(BaseModel):
    """A bounded proposal for a safe or approval-gated investigation."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    fingerprint: str = Field(..., min_length=8, max_length=128)
    target_url: str = Field(..., min_length=1, max_length=1000)
    statement: str = Field(..., min_length=3, max_length=500)
    vuln_class: VulnClass = VulnClass.UNKNOWN
    prerequisite: list[str] = Field(default_factory=list, max_length=12)
    expected_behavior: str = Field(..., min_length=3, max_length=500)
    action_type: Literal["read_only_replay", "read_only_compare", "approval_required"] = (
        "read_only_compare"
    )
    evidence_needed: list[str] = Field(default_factory=list, max_length=12)
    evidence_contract: dict[str, Any] | None = Field(
        default=None,
        description="Generic proof contract derived from evidence_needed labels.",
    )
    hint_provenance: list[str] = Field(
        default_factory=list,
        max_length=8,
        description="Reasoning-method provenance for later trust learning.",
    )
    maximum_attempts: int = Field(default=1, ge=0, le=5)
    request_budget: int = Field(default=2, ge=0, le=10)
    risk_level: Literal["low", "medium", "high"] = "low"
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    origin_detail: str = Field(default="workflow_understanding", max_length=300)
    confidence_score: float = Field(default=0.3, ge=0.0, le=1.0)

    @field_validator(
        "target_url",
        "statement",
        "prerequisite",
        "expected_behavior",
        "evidence_needed",
        "evidence_refs",
        "origin_detail",
        mode="before",
    )
    @classmethod
    def _redact_fields(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


__all__ = ["BusinessLogicHypothesisSpec", "WorkflowObservation", "WorkflowSignal"]
