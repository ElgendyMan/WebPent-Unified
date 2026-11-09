"""Bounded, target-scoped research budget primitives.

The budget is a planning guard only. It never executes network or browser work.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ResearchBudget(BaseModel):
    """Hard upper bounds for one engagement-scoped research run."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    max_requests: int = Field(default=5000, ge=1, le=100_000)
    max_runtime_minutes: int = Field(default=120, ge=1, le=1_440)
    max_browser_actions: int = Field(default=1000, ge=0, le=50_000)
    max_depth: int = Field(default=5, ge=0, le=32)
    max_hypotheses: int = Field(default=500, ge=1, le=10_000)


class BudgetUsage(BaseModel):
    """Serializable counters associated with one budget."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    requests: int = Field(default=0, ge=0)
    browser_actions: int = Field(default=0, ge=0)
    hypotheses: int = Field(default=0, ge=0)
    depth: int = Field(default=0, ge=0)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="after")
    def _aware_start(self) -> BudgetUsage:
        if self.started_at.tzinfo is None:
            raise ValueError("started_at_must_be_timezone_aware")
        return self


class BudgetDecision(BaseModel):
    """Pure decision returned before a planned research task is admitted."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    allowed: bool
    reason: str = Field(max_length=240)
    remaining_requests: int = Field(ge=0)
    remaining_browser_actions: int = Field(ge=0)
    remaining_hypotheses: int = Field(ge=0)


def evaluate_budget(budget: ResearchBudget, usage: BudgetUsage) -> BudgetDecision:
    """Evaluate hard limits without mutating state or performing I/O."""
    request_left = max(0, budget.max_requests - usage.requests)
    browser_left = max(0, budget.max_browser_actions - usage.browser_actions)
    hypothesis_left = max(0, budget.max_hypotheses - usage.hypotheses)
    if usage.depth > budget.max_depth:
        return BudgetDecision(
            allowed=False,
            reason="research_depth_exhausted",
            remaining_requests=request_left,
            remaining_browser_actions=browser_left,
            remaining_hypotheses=hypothesis_left,
        )
    if request_left <= 0:
        return BudgetDecision(
            allowed=False,
            reason="request_budget_exhausted",
            remaining_requests=request_left,
            remaining_browser_actions=browser_left,
            remaining_hypotheses=hypothesis_left,
        )
    if hypothesis_left <= 0:
        return BudgetDecision(
            allowed=False,
            reason="hypothesis_budget_exhausted",
            remaining_requests=request_left,
            remaining_browser_actions=browser_left,
            remaining_hypotheses=hypothesis_left,
        )
    return BudgetDecision(
        allowed=True,
        reason="budget_available",
        remaining_requests=request_left,
        remaining_browser_actions=browser_left,
        remaining_hypotheses=hypothesis_left,
    )


__all__ = ["BudgetDecision", "BudgetUsage", "ResearchBudget", "evaluate_budget"]
