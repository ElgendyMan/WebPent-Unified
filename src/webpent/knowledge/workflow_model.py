"""Workflow knowledge facade with explicit non-proof semantics."""

from __future__ import annotations

from webpent.knowledge.target_knowledge import TargetKnowledgeModel, WorkflowState


class WorkflowModel:
    """Read-only view of observed workflow states and transitions."""

    def __init__(self, workflows: dict[str, WorkflowState]) -> None:
        self.workflows = dict(workflows)

    @classmethod
    def from_target_knowledge(cls, model: TargetKnowledgeModel) -> WorkflowModel:
        return cls(model.workflows)

    def get(self, workflow_id: str) -> WorkflowState | None:
        return self.workflows.get(workflow_id)

    def transition_candidates(self, workflow_id: str) -> tuple[dict[str, str], ...]:
        workflow = self.get(workflow_id)
        return tuple(workflow.transitions) if workflow else ()

    def as_dict(self) -> dict[str, dict[str, object]]:
        return {key: value.model_dump(mode="json") for key, value in self.workflows.items()}


__all__ = ["WorkflowModel"]
