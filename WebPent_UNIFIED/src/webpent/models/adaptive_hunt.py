"""Typed models for bounded adaptive hunt scheduling.

The adaptive layer is deliberately a scheduler, not an executor.  It turns
new evidence into small, auditable revisit tasks that re-enter the existing
read-only/HITL-gated pipeline.  All scores are deterministic and explainable;
LLM output is never accepted as an authorization decision.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RevisitStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    CONFIRMED = "confirmed"
    DEAD_END = "dead_end"
    BLOCKED_BY_SCOPE = "blocked_by_scope"
    NEEDS_APPROVAL = "needs_approval"
    DIMINISHING_RETURNS = "diminishing_returns"
    BUDGET_EXHAUSTED = "budget_exhausted"
    SKIPPED = "skipped"


class RevisitSurface(str, Enum):
    ENDPOINT = "endpoint"
    AUTH_PATTERN = "auth_pattern"
    OBJECT_FAMILY = "object_family"
    WORKFLOW = "workflow"
    ROLE = "role"
    JS_ROUTE = "js_route"
    RELATION = "relation"


class BranchRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BranchBudget(BaseModel):
    """Per-task/branch resource budget; units are deterministic counters."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    max_attempts: int = Field(default=1, ge=1, le=20)
    attempts_used: int = Field(default=0, ge=0)
    max_requests: int = Field(default=3, ge=0, le=500)
    requests_used: int = Field(default=0, ge=0)
    max_concurrency: int = Field(default=1, ge=1, le=10)
    max_time_seconds: int = Field(default=60, ge=1, le=3600)
    time_seconds_used: int = Field(default=0, ge=0)
    max_llm_units: float = Field(default=0.0, ge=0.0, le=100.0)
    llm_units_used: float = Field(default=0.0, ge=0.0)
    risk_level: BranchRisk = BranchRisk.LOW

    @property
    def exhausted(self) -> bool:
        return (
            self.attempts_used >= self.max_attempts
            or self.requests_used >= self.max_requests
            or self.time_seconds_used >= self.max_time_seconds
            or self.llm_units_used >= self.max_llm_units
            if self.max_llm_units > 0
            else (
                self.attempts_used >= self.max_attempts
                or self.requests_used >= self.max_requests
                or self.time_seconds_used >= self.max_time_seconds
            )
        )


class AdaptiveLeadScore(BaseModel):
    """Explainable priority score in the closed interval [0, 1]."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    impact_potential: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_strength: float = Field(default=0.0, ge=0.0, le=1.0)
    exploitability: float = Field(default=0.0, ge=0.0, le=1.0)
    chain_potential: float = Field(default=0.0, ge=0.0, le=1.0)
    information_gain: float = Field(default=0.0, ge=0.0, le=1.0)
    novelty: float = Field(default=0.0, ge=0.0, le=1.0)
    repetition_penalty: float = Field(default=0.0, ge=0.0, le=1.0)
    cost_penalty: float = Field(default=0.0, ge=0.0, le=1.0)
    weak_evidence_penalty: float = Field(default=0.0, ge=0.0, le=1.0)
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    rule: str = Field(default="", max_length=500)


class RevisitTask(BaseModel):
    """A bounded, deduplicated task for a related surface."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    id: str = Field(default_factory=lambda: f"revisit-{uuid4().hex[:16]}", min_length=1)
    parent_task_id: str | None = None
    source_finding_id: str | None = None
    source_relation_id: str | None = None
    target_url: str = Field(..., min_length=1, max_length=2048)
    surface: RevisitSurface
    surface_key: str = Field(..., min_length=1, max_length=500)
    task_type: str = Field(..., min_length=1, max_length=100)
    reason: str = Field(..., min_length=1, max_length=500)
    evidence_refs: list[str] = Field(default_factory=list)
    auth_pattern: str | None = Field(default=None, max_length=200)
    object_family: str | None = Field(default=None, max_length=200)
    workflow_id: str | None = Field(default=None, max_length=200)
    role: str | None = Field(default=None, max_length=100)
    js_route: str | None = Field(default=None, max_length=500)
    signal_kind: str | None = Field(default=None, max_length=100)
    investigation_stage: str = Field(default="discovery", max_length=40)
    depth: int = Field(default=0, ge=0, le=20)
    status: RevisitStatus = RevisitStatus.PENDING
    score: AdaptiveLeadScore = Field(default_factory=AdaptiveLeadScore)
    budget: BranchBudget = Field(default_factory=BranchBudget)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    outcome_note: str = Field(default="", max_length=500)

    @field_validator("target_url", "surface_key", "task_type", "reason")
    @classmethod
    def _strip_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value must not be blank")
        return value


class RevisitOutcome(BaseModel):
    """Normalized outcome emitted by an existing executor/validator."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    task_id: str = Field(..., min_length=1)
    status: RevisitStatus
    note: str = Field(default="", max_length=500)
    requests_used: int = Field(default=0, ge=0)
    time_seconds_used: int = Field(default=0, ge=0)
    llm_units_used: float = Field(default=0.0, ge=0.0)
    evidence_refs: list[str] = Field(default_factory=list)
    new_signal: bool | None = None


__all__ = [
    "AdaptiveLeadScore",
    "BranchBudget",
    "BranchRisk",
    "RevisitOutcome",
    "RevisitStatus",
    "RevisitSurface",
    "RevisitTask",
]
