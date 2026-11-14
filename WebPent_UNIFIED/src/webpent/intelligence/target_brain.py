"""Deterministic Target Brain projection for bounded planning.

The Target Brain is an advisory view over observations already admitted by the
WebPent kernel.  It never performs I/O, resolves scope, creates credentials, or
promotes an inference to a finding.  All identifiers are supplied by the
caller and all output is bounded for checkpoint/report use.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from webpent.intelligence.contracts import ApplicationKnowledgeGraph, EndpointIntelligence
from webpent.knowledge.target_knowledge import KnowledgeKind, TargetKnowledgeModel


class TargetBrainSnapshot(BaseModel):
    """Safe, serializable summary of the target's observed application model."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: int = 1
    engagement_id: str = Field(..., min_length=1, max_length=200)
    knowledge: TargetKnowledgeModel
    endpoint_count: int = Field(default=0, ge=0)
    host_count: int = Field(default=0, ge=0)
    identity_count: int = Field(default=0, ge=0)
    object_count: int = Field(default=0, ge=0)
    workflow_count: int = Field(default=0, ge=0)
    coverage_gaps: list[str] = Field(default_factory=list, max_length=32)
    knowledge_gaps: list[str] = Field(default_factory=list, max_length=32)
    evidence_refs: list[str] = Field(default_factory=list, max_length=64)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    def as_dict(self) -> dict[str, Any]:
        """Return a report-safe JSON projection."""
        return self.model_dump(mode="json")


def build_target_brain(
    *,
    engagement_id: str,
    knowledge: TargetKnowledgeModel,
    endpoints: Iterable[EndpointIntelligence] = (),
) -> TargetBrainSnapshot:
    """Build a deterministic Target Brain from already-admitted observations.

    Endpoint metadata is folded into an ``ApplicationKnowledgeGraph`` only to
    provide stable coverage and evidence references.  It is not converted into
    requests, payloads, findings, or execution authority.
    """

    if knowledge.engagement_id != engagement_id:
        raise ValueError("knowledge engagement_id does not match requested engagement")

    graph = ApplicationKnowledgeGraph(engagement_id=engagement_id, knowledge=knowledge)
    for endpoint in endpoints:
        graph.add_endpoint(endpoint)

    endpoint_paths = {endpoint.path for endpoint in graph.endpoints.values()}
    coverage_gaps: list[str] = []
    if not endpoint_paths:
        coverage_gaps.append("no_endpoint_observations")
    if not knowledge.authorization_profiles:
        coverage_gaps.append("no_authorization_profiles")
    if not knowledge.workflows:
        coverage_gaps.append("no_workflow_observations")
    if not knowledge.data_flows:
        coverage_gaps.append("no_data_flow_observations")

    knowledge_gaps: list[str] = []
    if not any(node.kind == KnowledgeKind.HOST for node in knowledge.nodes.values()):
        knowledge_gaps.append("host_identity_unknown")
    if not any(node.kind == KnowledgeKind.OBJECT for node in knowledge.nodes.values()):
        knowledge_gaps.append("object_model_unknown")
    if not any(node.kind == KnowledgeKind.ROLE for node in knowledge.nodes.values()):
        knowledge_gaps.append("role_model_unknown")

    evidence_refs = sorted(
        {
            reference
            for node in knowledge.nodes.values()
            for reference in node.evidence_refs
        }
        | {
            reference
            for edge in knowledge.edges
            for reference in edge.evidence_refs
        }
        | {
            reference
            for endpoint in graph.endpoints.values()
            for reference in endpoint.evidence_refs
        }
        | {
            reference
            for profile in knowledge.authorization_profiles.values()
            for reference in profile.evidence_refs
        }
        | {
            reference
            for workflow in knowledge.workflows.values()
            for reference in workflow.evidence_refs
        }
        | {
            reference
            for data_flow in knowledge.data_flows
            for reference in data_flow.evidence_refs
        }
    )[:64]

    observed_dimensions = sum(
        bool(value)
        for value in (
            endpoint_paths,
            knowledge.authorization_profiles,
            knowledge.workflows,
            knowledge.data_flows,
        )
    )
    confidence = round(observed_dimensions / 4, 3)

    counts = {
        kind: sum(node.kind == kind for node in knowledge.nodes.values())
        for kind in KnowledgeKind
    }
    return TargetBrainSnapshot(
        engagement_id=engagement_id,
        knowledge=knowledge,
        endpoint_count=len(graph.endpoints),
        host_count=counts[KnowledgeKind.HOST],
        identity_count=counts[KnowledgeKind.IDENTITY],
        object_count=counts[KnowledgeKind.OBJECT],
        workflow_count=len(knowledge.workflows),
        coverage_gaps=coverage_gaps,
        knowledge_gaps=knowledge_gaps,
        evidence_refs=evidence_refs,
        confidence=confidence,
    )


__all__ = ["TargetBrainSnapshot", "build_target_brain"]
