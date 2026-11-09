"""Typed planner/orchestrator decision proposals.

Phase 7 keeps the planner advisory. A proposal is data that must pass
policy, scope, budget, and tool-availability gates before any existing agent
may consider it. The LLM can suggest only values represented by these closed
schemas; it cannot provide shell commands, arbitrary URLs, or execution flags.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PlannerActionType(str, Enum):
    OBSERVE_TARGET = "observe_target"
    ENUMERATE_SURFACE = "enumerate_surface"
    RUN_READ_ONLY_TOOL = "run_read_only_tool"
    VALIDATE_HYPOTHESIS = "validate_hypothesis"
    REVISIT_SURFACE = "revisit_surface"
    NO_ACTION = "no_action"


class PlannerRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DESTRUCTIVE = "destructive"


class PlannerDecisionStatus(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    NEEDS_APPROVAL = "needs_approval"
    FALLBACK = "fallback"


class PlannerDecisionProposal(BaseModel):
    """LLM or deterministic proposal; never an executable command."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    id: UUID = Field(default_factory=uuid4)
    action_type: PlannerActionType
    target_ref: str = Field(min_length=1, max_length=256)
    hypothesis_ref: str | None = Field(default=None, max_length=128)
    required_identity: str | None = Field(default=None, max_length=128)
    expected_evidence: list[str] = Field(min_length=1, max_length=8)
    estimated_cost: float = Field(ge=0.0, le=100.0)
    risk_level: PlannerRiskLevel = PlannerRiskLevel.LOW
    rationale: str = Field(min_length=1, max_length=1000)
    source: str = Field(default="deterministic", max_length=32)

    @field_validator("target_ref", "hypothesis_ref", "required_identity")
    @classmethod
    def _reject_control_and_url_values(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if any(ord(ch) < 32 for ch in value):
            raise ValueError("planner references cannot contain control characters")
        lowered = value.lower()
        if "://" in lowered or lowered.startswith(("shell:", "cmd:", "exec:")):
            raise ValueError("planner references cannot contain URLs or execution schemes")
        return value

    @field_validator("expected_evidence")
    @classmethod
    def _validate_evidence_labels(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("expected_evidence labels must be non-empty strings")
            if any(ord(ch) < 32 for ch in value):
                raise ValueError("expected_evidence labels cannot contain control characters")
            cleaned.append(value.strip()[:160])
        return list(dict.fromkeys(cleaned))


class PlannerGateAudit(BaseModel):
    """Auditable result of deterministic planner gates."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    proposal_id: UUID
    status: PlannerDecisionStatus
    gates_passed: list[str] = Field(default_factory=list, max_length=8)
    gates_failed: list[str] = Field(default_factory=list, max_length=8)
    reason: str = Field(min_length=1, max_length=500)
    fallback_used: bool = False
    tool_categories: list[str] = Field(default_factory=list, max_length=8)
    llm_contribution: str = Field(default="", max_length=500)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_state(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
