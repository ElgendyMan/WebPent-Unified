"""Observed data-flow facade for planning and coverage only."""

from __future__ import annotations

from webpent.knowledge.target_knowledge import DataFlow, TargetKnowledgeModel


class DataFlowModel:
    """Read-only data-flow observations with explicit observed filtering."""

    def __init__(self, flows: list[DataFlow]) -> None:
        self.flows = list(flows)

    @classmethod
    def from_target_knowledge(cls, model: TargetKnowledgeModel) -> DataFlowModel:
        return cls(model.data_flows)

    def observed(self) -> tuple[DataFlow, ...]:
        return tuple(flow for flow in self.flows if flow.observed)

    def between(self, source_id: str, destination_id: str) -> tuple[DataFlow, ...]:
        return tuple(
            flow
            for flow in self.observed()
            if flow.source_id == source_id and flow.destination_id == destination_id
        )

    def as_dict(self) -> list[dict[str, object]]:
        return [flow.model_dump(mode="json") for flow in self.flows]


__all__ = ["DataFlowModel"]
