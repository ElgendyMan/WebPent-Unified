"""Serializable state for an engagement-scoped research plan."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.research_engine.research_budget import BudgetUsage, ResearchBudget

_SECRET_KEYS = {
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "cookie",
    "authorization",
    "payload",
    "body",
}


class ResearchTask(BaseModel):
    """A proposed task; admission does not execute it."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    task_id: str = Field(min_length=1, max_length=160)
    engagement_id: str = Field(min_length=1, max_length=160)
    target_id: str = Field(min_length=1, max_length=160)
    objective: str = Field(min_length=1, max_length=240)
    reason: str = Field(default="", max_length=400)
    priority: float = Field(default=0.0, ge=0.0, le=1.0)
    risk: Literal["low", "medium", "high", "critical"] = "low"
    expected_information_gain: float = Field(default=0.0, ge=0.0, le=1.0)
    cost: float = Field(default=0.0, ge=0.0, le=1.0)
    required_capability: str = Field(default="http_read", min_length=1, max_length=120)
    required_evidence: tuple[str, ...] = Field(default=(), max_length=16)
    operation: Literal["observe", "plan", "validate"] = "observe"


class ResearchState(BaseModel):
    """Bounded state that can safely cross checkpoints."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: int = 1
    engagement_id: str = Field(min_length=1, max_length=160)
    target_id: str = Field(min_length=1, max_length=160)
    budget: ResearchBudget = Field(default_factory=ResearchBudget)
    usage: BudgetUsage = Field(default_factory=BudgetUsage)
    tasks: tuple[ResearchTask, ...] = Field(default=(), max_length=10_000)
    hypothesis_refs: tuple[str, ...] = Field(default=(), max_length=10_000)
    observation_refs: tuple[str, ...] = Field(default=(), max_length=10_000)
    stop_reason: str = Field(default="", max_length=240)

    @field_validator("tasks")
    @classmethod
    def _tasks_match_scope(cls, value: tuple[ResearchTask, ...]) -> tuple[ResearchTask, ...]:
        return value

    def admit_task(self, task: ResearchTask) -> ResearchState:
        if task.engagement_id != self.engagement_id or task.target_id != self.target_id:
            raise ValueError("research_task_scope_mismatch")
        if any(existing.task_id == task.task_id for existing in self.tasks):
            return self
        if len(self.tasks) >= self.budget.max_requests:
            return self.model_copy(update={"stop_reason": "task_budget_exhausted"})
        return self.model_copy(update={"tasks": (*self.tasks, task)})

    def add_hypothesis_ref(self, reference: str) -> ResearchState:
        clean = str(reference).strip()[:240]
        if not clean or any(key in clean.lower() for key in _SECRET_KEYS):
            raise ValueError("unsafe_hypothesis_reference")
        if clean in self.hypothesis_refs:
            return self
        if len(self.hypothesis_refs) >= self.budget.max_hypotheses:
            return self.model_copy(update={"stop_reason": "hypothesis_budget_exhausted"})
        return self.model_copy(update={"hypothesis_refs": (*self.hypothesis_refs, clean)})

    def add_observation_ref(self, reference: str) -> ResearchState:
        clean = str(reference).strip()[:240]
        if not clean or any(key in clean.lower() for key in _SECRET_KEYS):
            raise ValueError("unsafe_observation_reference")
        if clean in self.observation_refs:
            return self
        return self.model_copy(update={"observation_refs": (*self.observation_refs, clean)})

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


__all__ = ["ResearchState", "ResearchTask"]
