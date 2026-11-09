"""Approval-gated workflow replay and cleanup contracts."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import redact_sensitive

ReplayStatus = Literal["planned", "ready", "blocked", "completed", "inconclusive"]
SessionHealth = Literal["unknown", "healthy", "stale", "invalid"]
CleanupStatus = Literal["not_started", "required", "completed", "failed", "not_applicable"]


class ReplayStateSnapshot(BaseModel):
    """Redacted state evidence captured before or after a replay."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    state_ref: str = Field(default="unknown", min_length=1, max_length=160)
    fingerprint: str | None = Field(default=None, max_length=128)
    status: Literal["unknown", "observed", "changed", "unchanged", "inconclusive"] = "unknown"
    evidence_refs: list[str] = Field(default_factory=list, max_length=12)

    @field_validator("state_ref", "fingerprint", "evidence_refs", mode="before")
    @classmethod
    def _redact_values(cls, value):
        clean, _ = redact_sensitive(value)
        return clean


class ReplayIdentityContext(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    context_id: str = Field(..., min_length=8, max_length=160)
    role: str = Field(..., min_length=1, max_length=80)
    session_health: SessionHealth = "unknown"
    secret_ref: str | None = Field(default=None, max_length=200)
    capability_refs: list[str] = Field(default_factory=list, max_length=12)
    tenant_ref: str | None = Field(default=None, max_length=200)
    object_refs: list[str] = Field(default_factory=list, max_length=20)

    @field_validator(
        "role",
        "secret_ref",
        "capability_refs",
        "tenant_ref",
        "object_refs",
        mode="before",
    )
    @classmethod
    def _redact_values(cls, value):
        clean, _ = redact_sensitive(value)
        return clean


class ReplayStep(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    step_id: str = Field(..., min_length=8, max_length=160)
    endpoint_ref: str = Field(..., min_length=1, max_length=500)
    method: str = Field(default="GET", min_length=1, max_length=12)
    expected_state: str = Field(default="unknown", max_length=120)
    evidence_needed: list[str] = Field(default_factory=list, max_length=12)
    non_destructive: bool = True
    approval_required: bool = True
    request_fingerprint: str | None = Field(default=None, max_length=128)
    response_fingerprint: str | None = Field(default=None, max_length=128)
    pre_state: ReplayStateSnapshot = Field(default_factory=ReplayStateSnapshot)
    post_state: ReplayStateSnapshot = Field(default_factory=ReplayStateSnapshot)

    @field_validator(
        "endpoint_ref",
        "expected_state",
        "evidence_needed",
        "request_fingerprint",
        "response_fingerprint",
        mode="before",
    )
    @classmethod
    def _redact_values(cls, value):
        clean, _ = redact_sensitive(value)
        return clean


class CleanupAction(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    action_id: str = Field(..., min_length=8, max_length=160)
    description: str = Field(..., min_length=3, max_length=300)
    status: CleanupStatus = "required"
    evidence_refs: list[str] = Field(default_factory=list, max_length=12)

    @field_validator("description", "evidence_refs", mode="before")
    @classmethod
    def _redact_values(cls, value):
        clean, _ = redact_sensitive(value)
        return clean


class WorkflowReplayPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    plan_id: str = Field(..., min_length=8, max_length=160)
    workflow_fingerprint: str = Field(..., min_length=8, max_length=128)
    identity: ReplayIdentityContext
    tenant_ref: str | None = Field(default=None, max_length=200)
    object_refs: list[str] = Field(default_factory=list, max_length=20)
    steps: list[ReplayStep] = Field(default_factory=list, max_length=5)
    cleanup: list[CleanupAction] = Field(default_factory=list, max_length=8)
    scope_decision: Literal["allowed", "denied", "unknown"] = "unknown"
    status: ReplayStatus = "planned"
    approval_required: bool = True
    max_requests: int = Field(default=1, ge=0, le=5)
    executed: bool = False
    cleanup_status: CleanupStatus = "not_started"
    cleanup_evidence_refs: list[str] = Field(default_factory=list, max_length=12)

    @field_validator("tenant_ref", "object_refs", "cleanup_evidence_refs", mode="before")
    @classmethod
    def _redact_replay_refs(cls, value):
        clean, _ = redact_sensitive(value)
        return clean


__all__ = [
    "CleanupAction",
    "CleanupStatus",
    "ReplayIdentityContext",
    "ReplayStateSnapshot",
    "ReplayStatus",
    "ReplayStep",
    "SessionHealth",
    "WorkflowReplayPlan",
]
