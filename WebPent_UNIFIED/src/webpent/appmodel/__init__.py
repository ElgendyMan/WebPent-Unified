"""webpent.appmodel package init — M3 UM-DR-17 / UM-DR-46 Phase A."""
from webpent.appmodel.builder import build_application_model, merge_appmodel_into_attack_graph
from webpent.appmodel.models import (
    ApplicationModel,
    AppModelEntity,
    AppModelEntityKind,
    AppModelRelation,
    AppModelRelationKind,
    DiscoveryProvenance,
    provenance_confidence,
)
from webpent.appmodel.skg import build_security_knowledge_graph, build_skg_research_hints
from webpent.appmodel.skg_queries import (
    get_all_paths_to,
    ownership_changers,
    reads_without_authz_marker,
    summarize_skg,
    ui_vs_api_permission_diff,
    workflow_skip_candidates,
)

__all__ = [
    "AppModelEntity",
    "AppModelEntityKind",
    "AppModelRelation",
    "AppModelRelationKind",
    "ApplicationModel",
    "DiscoveryProvenance",
    "build_application_model",
    "build_security_knowledge_graph",
    "build_skg_research_hints",
    "get_all_paths_to",
    "merge_appmodel_into_attack_graph",
    "ownership_changers",
    "provenance_confidence",
    "reads_without_authz_marker",
    "summarize_skg",
    "ui_vs_api_permission_diff",
    "workflow_skip_candidates",
]
