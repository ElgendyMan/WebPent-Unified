"""Deterministic priority scoring for bounded research tasks."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PrioritySignals(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    impact: float = Field(default=0.0, ge=0.0, le=1.0)
    exploitability: float = Field(default=0.0, ge=0.0, le=1.0)
    novelty: float = Field(default=0.0, ge=0.0, le=1.0)
    knowledge_gap: float = Field(default=0.0, ge=0.0, le=1.0)
    estimated_cost: float = Field(default=0.5, gt=0.0, le=1.0)


def priority_score(signals: PrioritySignals) -> float:
    """Return a bounded triage score; it is not an authorization decision."""
    value = (
        0.30 * signals.impact
        + 0.25 * signals.exploitability
        + 0.20 * signals.novelty
        + 0.25 * signals.knowledge_gap
    )
    return round(max(0.0, min(1.0, value / max(0.25, signals.estimated_cost))), 4)


__all__ = ["PrioritySignals", "priority_score"]
