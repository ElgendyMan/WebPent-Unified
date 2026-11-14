"""Typed contracts for bounded, evidence-driven autonomous proof planning."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import redact_sensitive, sha256_text


class ProofGapType(str, Enum):
    MISSING_SURFACE = "missing_surface"
    MISSING_IDENTITY = "missing_identity"
    MISSING_BODY_CONTENT_TYPE = "missing_body_content_type"
    MISSING_PRECONDITION = "missing_precondition"
    MISSING_NEGATIVE_CONTROL = "missing_negative_control"
    WEAK_ORACLE = "weak_oracle"
    POLICY_BLOCK = "policy_block"
    MISSING_VALIDATOR = "missing_validator"


class ProofActionStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVAL_REQUIRED = "approval_required"
    EXECUTED = "executed"
    INCONCLUSIVE = "inconclusive"
    TERMINAL = "terminal"


class ProofGapAssessment(BaseModel):
    """A reviewable gap found after a probe; it does not authorize execution."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    gap_id: str = Field(min_length=3, max_length=160)
    gap_type: ProofGapType
    campaign_key: str = Field(min_length=1, max_length=120)
    source_refs: list[str] = Field(default_factory=list, max_length=20)
    reason: str = Field(min_length=1, max_length=500)
    evidence_fingerprint: str = Field(min_length=3, max_length=120)
    resolved: bool = False
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("reason", "source_refs", "evidence_fingerprint", mode="before")
    @classmethod
    def _redact_fields(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class ProofActionProposal(BaseModel):
    """A bounded next action proposal; scope and approval remain external gates."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    action_id: str = Field(min_length=3, max_length=160)
    campaign_key: str = Field(min_length=1, max_length=120)
    gap_id: str = Field(min_length=3, max_length=160)
    action_type: str = Field(min_length=1, max_length=120)
    preconditions: list[str] = Field(default_factory=list, max_length=12)
    expected_evidence: list[str] = Field(default_factory=list, max_length=12)
    identity_refs: list[str] = Field(default_factory=list, max_length=12)
    payload_strategy: str = Field(default="evidence-minimal", max_length=200)
    negative_control: str = Field(default="required", max_length=120)
    exit_condition: str = Field(min_length=1, max_length=300)
    chain_state: dict[str, str] = Field(default_factory=dict)
    cleanup_steps: list[str] = Field(default_factory=list, max_length=12)
    cleanup_status: str = Field(default="pending", max_length=40)
    confidence_before: str = Field(default="candidate", max_length=40)
    confidence_after: str = Field(default="needs_human_review", max_length=40)
    budget_requests: int = Field(default=1, ge=1, le=20)
    budget_seconds: int = Field(default=60, ge=1, le=3600)
    status: ProofActionStatus = ProofActionStatus.APPROVAL_REQUIRED
    approval_required: bool = True
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    evidence_fingerprint: str = Field(min_length=3, max_length=120)
    parent_action_id: str | None = Field(default=None, max_length=160)

    @field_validator(
        "preconditions",
        "expected_evidence",
        "identity_refs",
        "payload_strategy",
        "negative_control",
        "exit_condition",
        "chain_state",
        "cleanup_steps",
        "cleanup_status",
        "confidence_before",
        "confidence_after",
        "evidence_refs",
        "evidence_fingerprint",
        mode="before",
    )
    @classmethod
    def _redact_fields(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class ProofOutcome(BaseModel):
    """Executor result consumed by proof planning; never a finding by itself."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    action_id: str = Field(min_length=3, max_length=160)
    status: str = Field(min_length=1, max_length=40)
    campaign_key: str | None = Field(default=None, max_length=120)
    vuln_class: str | None = Field(default=None, max_length=120)
    target: str | None = Field(default=None, max_length=1000)
    identity_ref: str | None = Field(default=None, max_length=160)
    request_metadata: dict[str, Any] = Field(default_factory=dict)
    response_metadata: dict[str, Any] = Field(default_factory=dict)
    baseline: dict[str, Any] = Field(default_factory=dict)
    negative_control: dict[str, Any] = Field(default_factory=dict)
    oracle: dict[str, Any] = Field(default_factory=dict)
    evidence_hashes: dict[str, str] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    evidence_complete: bool = False
    causal_signal: bool = False
    negative_control_observed: bool = False
    cleanup_status: str = Field(default="pending", max_length=40)
    confidence_after: str = Field(default="needs_human_review", max_length=40)
    latency_ms: int = Field(default=0, ge=0)
    requests_used: int = Field(default=0, ge=0)
    attempts: int = Field(default=1, ge=1)
    guard_failure: bool = False
    note: str = Field(default="", max_length=500)

    @field_validator(
        "campaign_key",
        "vuln_class",
        "target",
        "identity_ref",
        "request_metadata",
        "response_metadata",
        "baseline",
        "negative_control",
        "oracle",
        "evidence_hashes",
        "evidence_refs",
        "cleanup_status",
        "confidence_after",
        "note",
        mode="before",
    )
    @classmethod
    def _redact_fields(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class ProofObservabilitySnapshot(BaseModel):
    """Bounded counters used by reports and release gates."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    schema_version: int = 1
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    probes_considered: int = Field(default=0, ge=0)
    actions_proposed: int = Field(default=0, ge=0)
    actions_dropped_duplicate: int = Field(default=0, ge=0)
    confirmations: int = Field(default=0, ge=0)
    inconclusive: int = Field(default=0, ge=0)
    scope_blocks: int = Field(default=0, ge=0)
    policy_blocks: int = Field(default=0, ge=0)
    retries: int = Field(default=0, ge=0)
    budget_exhaustions: int = Field(default=0, ge=0)
    guard_failures: int = Field(default=0, ge=0)
    evidence_complete: int = Field(default=0, ge=0)
    evidence_incomplete: int = Field(default=0, ge=0)
    total_latency_ms: int = Field(default=0, ge=0)
    gap_counts: dict[str, int] = Field(default_factory=dict)


class ProofPlan(BaseModel):
    """Serializable proof-engine output; proposals are not execution commands."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    schema_version: int = 1
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    assessments: list[ProofGapAssessment] = Field(default_factory=list, max_length=200)
    actions: list[ProofActionProposal] = Field(default_factory=list, max_length=50)
    causal_edges: list[dict[str, str]] = Field(default_factory=list, max_length=200)
    observability: ProofObservabilitySnapshot = Field(default_factory=ProofObservabilitySnapshot)

    @property
    def plan_digest(self) -> str:
        return f"sha256:{sha256_text(self.model_dump(mode='json'))}"


__all__ = [
    "ProofActionProposal",
    "ProofActionStatus",
    "ProofGapAssessment",
    "ProofGapType",
    "ProofObservabilitySnapshot",
    "ProofOutcome",
    "ProofPlan",
]
