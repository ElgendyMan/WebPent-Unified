"""Target Knowledge Model package — v62 additive layer."""

from webpent.knowledge.auth_model import AuthorizationModel
from webpent.knowledge.builder import KnowledgeBuilder
from webpent.knowledge.data_flow_model import DataFlowModel
from webpent.knowledge.entity_graph import EntityGraph
from webpent.knowledge.model_v2 import (
    KnowledgeEntity,
    KnowledgeEntityKind,
    KnowledgeLifecycle,
    KnowledgeObservation,
    KnowledgeRelation,
    TargetKnowledgeV2,
    build_target_knowledge_v2,
    upgrade_legacy_knowledge,
)
from webpent.knowledge.target_knowledge import TargetKnowledgeModel
from webpent.knowledge.target_model import build_target_model
from webpent.knowledge.workflow_model import WorkflowModel

__all__ = [
    "AuthorizationModel",
    "DataFlowModel",
    "EntityGraph",
    "KnowledgeBuilder",
    "TargetKnowledgeModel",
    "KnowledgeEntity",
    "KnowledgeEntityKind",
    "KnowledgeLifecycle",
    "KnowledgeObservation",
    "KnowledgeRelation",
    "TargetKnowledgeV2",
    "build_target_knowledge_v2",
    "upgrade_legacy_knowledge",
    "WorkflowModel",
    "build_target_model",
]
