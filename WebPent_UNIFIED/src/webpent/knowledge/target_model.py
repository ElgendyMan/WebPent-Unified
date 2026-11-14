"""Compatibility facade for the engagement-scoped target knowledge model.

The canonical contracts remain in :mod:`target_knowledge`; this module exists
so planners can import a semantic target-model boundary without creating a
second source of truth.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from webpent.knowledge.builder import KnowledgeBuilder
from webpent.knowledge.target_knowledge import (
    AuthorizationProfile,
    DataFlow,
    KnowledgeEdge,
    KnowledgeKind,
    KnowledgeNode,
    TargetKnowledgeModel,
    WorkflowState,
)


def build_target_model(state: Mapping[str, Any]) -> TargetKnowledgeModel:
    """Build a deterministic, engagement-scoped projection from state."""

    return KnowledgeBuilder.from_state(state).build()


__all__ = [
    "AuthorizationProfile",
    "DataFlow",
    "KnowledgeEdge",
    "KnowledgeKind",
    "KnowledgeNode",
    "TargetKnowledgeModel",
    "WorkflowState",
    "build_target_model",
]
