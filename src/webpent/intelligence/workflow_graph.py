"""Bounded workflow graph for application-understanding research."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


class WorkflowStep(BaseModel):
    """A report-safe workflow step identified by a stable observation key."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    step_id: str = Field(..., min_length=1, max_length=160)
    label: str = Field(..., min_length=1, max_length=200)
    endpoint_key: str | None = Field(default=None, max_length=500)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_refs(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))


class WorkflowTransition(BaseModel):
    """Observed transition between two workflow steps."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    source_step_id: str = Field(..., min_length=1, max_length=160)
    target_step_id: str = Field(..., min_length=1, max_length=160)
    transition: str = Field(..., min_length=1, max_length=160)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_refs(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))


class WorkflowGraph(BaseModel):
    """One target-scoped graph of observed workflow transitions."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: int = 1
    engagement_id: str = Field(..., min_length=1, max_length=200)
    target_id: str = Field(..., min_length=1, max_length=200)
    steps: dict[str, WorkflowStep] = Field(default_factory=dict)
    transitions: list[WorkflowTransition] = Field(default_factory=list, max_length=256)

    def add_step(self, step: WorkflowStep) -> None:
        self.steps[step.step_id] = step

    def add_transition(self, transition: WorkflowTransition) -> None:
        if (
            transition.source_step_id not in self.steps
            or transition.target_step_id not in self.steps
        ):
            raise ValueError("workflow_transition_requires_known_steps")
        if transition not in self.transitions:
            self.transitions.append(transition)

    def entry_steps(self) -> list[str]:
        """Return steps without observed predecessors in stable order."""
        targets = {transition.target_step_id for transition in self.transitions}
        return sorted(set(self.steps) - targets)

    def evidence_refs(self) -> list[str]:
        return sorted(
            {ref for step in self.steps.values() for ref in step.evidence_refs}
            | {ref for transition in self.transitions for ref in transition.evidence_refs}
        )[:64]


__all__ = ["WorkflowGraph", "WorkflowStep", "WorkflowTransition"]
