"""Typed, checkpoint-safe contracts for bounded autonomous research.

These models are advisory planning records. They never authorize transport,
confirm a finding, or replace the existing proof/validator boundary.
"""

from __future__ import annotations

import hashlib
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import canonical_json, redact_sensitive


def _redact(value: Any) -> Any:
    clean, _ = redact_sensitive(value)
    return clean


class ResearchContext(BaseModel):
    """Serializable investigation context that can safely cross checkpoints."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    version: int = Field(default=1, ge=1, le=10)
    session_id: str = Field(min_length=3, max_length=128)
    engagement_id: str = Field(min_length=3, max_length=128)
    client_id: str = Field(min_length=3, max_length=128)
    target_ref: str = Field(default="", max_length=500)
    objective: str = Field(default="bounded autonomous research", max_length=500)
    current_theory: str = Field(default="", max_length=500)
    known_facts: list[str] = Field(default_factory=list, max_length=100)
    unknowns: list[str] = Field(default_factory=list, max_length=100)
    open_gap_ids: list[str] = Field(default_factory=list, max_length=100)
    current_action_id: str | None = Field(default=None, max_length=160)
    attempted_action_fingerprints: list[str] = Field(default_factory=list, max_length=200)
    budget_remaining: float = Field(default=0.0, ge=0.0, le=100000.0)
    max_depth: int = Field(default=3, ge=0, le=10)
    depth: int = Field(default=0, ge=0, le=10)
    checkpoint_safe: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "session_id",
        "engagement_id",
        "client_id",
        "target_ref",
        "objective",
        "current_theory",
        "known_facts",
        "unknowns",
        "open_gap_ids",
        "current_action_id",
        "attempted_action_fingerprints",
        "metadata",
        mode="before",
    )
    @classmethod
    def _redact_fields(cls, value: Any) -> Any:
        return _redact(value)

    @classmethod
    def from_state(cls, state: dict[str, Any]) -> ResearchContext:
        """Build a safe context from legacy or current LangGraph state."""
        existing = state.get("research_context")
        source = dict(existing) if isinstance(existing, dict) else {}
        engagement_id = str(
            source.get("engagement_id") or state.get("engagement_id") or "engagement:unknown"
        )
        client_id = str(
            source.get("client_id") or state.get("client_id") or "client:unknown"
        )
        session_id = str(
            source.get("session_id")
            or state.get("thread_id")
            or f"session:{engagement_id}"
        )
        gaps = state.get("knowledge_gaps") or []
        gap_ids = [
            str(item.get("gap_id"))
            for item in gaps
            if isinstance(item, dict) and item.get("gap_id")
        ]
        source.setdefault("session_id", session_id)
        source.setdefault("engagement_id", engagement_id)
        source.setdefault("client_id", client_id)
        source.setdefault("open_gap_ids", gap_ids[:100])
        source.setdefault("target_ref", str(state.get("target_url") or ""))
        return cls.model_validate(source)

    def as_dict(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload["checkpoint_safe"] = True
        clean, _ = redact_sensitive(payload)
        return clean


class InformationObservation(BaseModel):
    """Bounded observation returned by an injected policy-approved handler."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    version: int = Field(default=1, ge=1, le=10)
    observation_id: str = Field(min_length=3, max_length=160)
    action_id: str = Field(min_length=3, max_length=160)
    action_fingerprint: str = Field(min_length=8, max_length=80)
    status: Literal["positive", "negative", "inconclusive", "blocked", "infrastructure_failure"]
    evidence_refs: list[str] = Field(default_factory=list, max_length=30)
    new_facts: list[str] = Field(default_factory=list, max_length=30)
    contradictions: list[str] = Field(default_factory=list, max_length=30)
    reason: str = Field(default="", max_length=500)
    control_complete: bool = False
    causal_signal: bool = False
    proof_bundle_sealed: bool = False
    revisit_conditions: list[str] = Field(default_factory=list, max_length=20)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "observation_id",
        "action_id",
        "action_fingerprint",
        "evidence_refs",
        "new_facts",
        "contradictions",
        "reason",
        "revisit_conditions",
        "metadata",
        mode="before",
    )
    @classmethod
    def _redact_fields(cls, value: Any) -> Any:
        return _redact(value)


class NovelBehaviorObservation(BaseModel):
    """Redacted behavior delta used to seed hypotheses, never findings."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    observation_id: str = Field(min_length=3, max_length=160)
    baseline_ref: str = Field(default="", max_length=160)
    current_ref: str = Field(default="", max_length=160)
    behavior_kind: Literal[
        "status_change",
        "authorization_differential",
        "workflow_transition",
        "response_shape_change",
        "timing_change",
        "unknown",
    ] = "unknown"
    changed_dimensions: list[str] = Field(default_factory=list, max_length=30)
    signal_strength: float = Field(default=0.0, ge=0.0, le=1.0)
    causal_signal: bool = False
    negative_control_complete: bool = False
    hypothesis_seed: str = Field(default="", max_length=500)
    evidence_refs: list[str] = Field(default_factory=list, max_length=30)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "observation_id",
        "baseline_ref",
        "current_ref",
        "changed_dimensions",
        "hypothesis_seed",
        "evidence_refs",
        "metadata",
        mode="before",
    )
    @classmethod
    def _redact_fields(cls, value: Any) -> Any:
        return _redact(value)

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(self.model_dump(mode="json"))
        return clean


class SurfaceCoverage(BaseModel):
    """Report-safe accounting for what a bounded research session covered."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    surface_id: str = Field(min_length=3, max_length=160)
    target_ref: str = Field(default="", max_length=500)
    surface_type: str = Field(default="endpoint", max_length=64)
    attempted_action_ids: list[str] = Field(default_factory=list, max_length=100)
    covered_action_classes: list[str] = Field(default_factory=list, max_length=100)
    uncovered_action_classes: list[str] = Field(default_factory=list, max_length=100)
    positive_observation_ids: list[str] = Field(default_factory=list, max_length=100)
    negative_observation_ids: list[str] = Field(default_factory=list, max_length=100)
    inconclusive_observation_ids: list[str] = Field(default_factory=list, max_length=100)
    coverage_score: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "surface_id",
        "target_ref",
        "surface_type",
        "attempted_action_ids",
        "covered_action_classes",
        "uncovered_action_classes",
        "positive_observation_ids",
        "negative_observation_ids",
        "inconclusive_observation_ids",
        "metadata",
        mode="before",
    )
    @classmethod
    def _redact_fields(cls, value: Any) -> Any:
        return _redact(value)

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(self.model_dump(mode="json"))
        return clean


class CandidateAction(BaseModel):
    """Schema-validated proposal for one bounded research action."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    version: int = Field(default=1, ge=1, le=10)
    action_id: str = Field(min_length=3, max_length=160)
    action_class: str = Field(min_length=2, max_length=64)
    objective: str = Field(min_length=3, max_length=500)
    target_ref: str = Field(default="", max_length=500)
    method: str = Field(default="GET", min_length=3, max_length=16)
    gap_id: str = Field(default="", max_length=160)
    hypothesis_id: str = Field(default="", max_length=160)
    identity_context: str = Field(default="anonymous", max_length=120)
    tenant_context: str = Field(default="unknown", max_length=120)
    workflow_state: str = Field(default="unknown", max_length=120)
    prerequisites: list[str] = Field(default_factory=list, max_length=20)
    required_capabilities: list[str] = Field(default_factory=list, max_length=12)
    policy_tags: list[str] = Field(default_factory=list, max_length=20)
    expected_information_gain: float = Field(default=0.0, ge=0.0, le=1.0)
    likelihood: float = Field(default=0.5, ge=0.0, le=1.0)
    impact: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_potential: float = Field(default=0.5, ge=0.0, le=1.0)
    novelty: float = Field(default=0.5, ge=0.0, le=1.0)
    coverage_value: float = Field(default=0.5, ge=0.0, le=1.0)
    cost: float = Field(default=1.0, ge=0.0, le=100000.0)
    failure_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    scope_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    rate_limit_cost: float = Field(default=0.0, ge=0.0, le=1.0)
    dependency_penalty: float = Field(default=0.0, ge=0.0, le=1.0)
    capability: str = Field(default="http_read", max_length=80)
    requires_approval: bool = False
    idempotency_key: str = Field(default="", max_length=200)
    justification: str = Field(default="", max_length=500)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("method", mode="before")
    @classmethod
    def _upper_method(cls, value: Any) -> str:
        return str(value or "GET").strip().upper()[:16]

    @field_validator(
        "action_id",
        "action_class",
        "objective",
        "target_ref",
        "gap_id",
        "hypothesis_id",
        "identity_context",
        "tenant_context",
        "workflow_state",
        "prerequisites",
        "required_capabilities",
        "policy_tags",
        "capability",
        "idempotency_key",
        "justification",
        "metadata",
        mode="before",
    )
    @classmethod
    def _redact_fields(cls, value: Any) -> Any:
        return _redact(value)

    def fingerprint(self) -> str:
        payload = {
            "action_class": self.action_class,
            "target_ref": self.target_ref,
            "method": self.method,
            "gap_id": self.gap_id,
            "hypothesis_id": self.hypothesis_id,
            "identity_context": self.identity_context,
            "tenant_context": self.tenant_context,
            "workflow_state": self.workflow_state,
            "capability": self.capability,
            "idempotency_key": self.idempotency_key,
        }
        return hashlib.sha256(canonical_json(payload).encode()).hexdigest()[:32]

    def as_dict(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload["fingerprint"] = self.fingerprint()
        clean, _ = redact_sensitive(payload)
        return clean


__all__ = [
    "CandidateAction",
    "InformationObservation",
    "NovelBehaviorObservation",
    "ResearchContext",
    "SurfaceCoverage",
]
