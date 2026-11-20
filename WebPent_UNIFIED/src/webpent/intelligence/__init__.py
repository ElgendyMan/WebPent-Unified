"""Additive, report-safe intelligence projections for WebPent."""

from webpent.intelligence.application_model import ApplicationAsset, ApplicationModel
from webpent.intelligence.contracts import (
    ApplicationKnowledgeGraph,
    EndpointIntelligence,
    IntelligenceRisk,
    ResearchHypothesis,
    build_endpoint_hypotheses,
)
from webpent.intelligence.entity_graph import EntityGraph, EntityNode, EntityRelation
from webpent.intelligence.permission_graph import PermissionGraph, PermissionObservation
from webpent.intelligence.state_model import StateModel, StateSnapshot, StateTransition
from webpent.intelligence.workflow_graph import WorkflowGraph, WorkflowStep, WorkflowTransition

__all__ = [
    "ApplicationAsset",
    "ApplicationModel",
    "EntityGraph",
    "EntityNode",
    "EntityRelation",
    "PermissionGraph",
    "PermissionObservation",
    "StateModel",
    "StateSnapshot",
    "StateTransition",
    "WorkflowGraph",
    "WorkflowStep",
    "WorkflowTransition",
    "ApplicationKnowledgeGraph",
    "EndpointIntelligence",
    "IntelligenceRisk",
    "ResearchHypothesis",
    "build_endpoint_hypotheses",
]
