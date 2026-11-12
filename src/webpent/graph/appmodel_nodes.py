"""UM-DR-36.2 — Application Semantic Model production wiring.

One graph node (``appmodel``) that:

  1. builds/updates the Application Semantic Model from REAL campaign
     state channels (recon/crawled endpoints, identity profiles, workflow
     observations, object-identity registry, multi-identity reasoning);
  2. merges the model's valid projection into the existing
     intelligence/attack-graph channel (additive, never replacing);
  3. exposes model coverage gaps as ordering-only research hints so
     hypothesis generation can see underexplored parts of the application;
  4. records honest telemetry (entity/relation counts, kinds materialized,
     coverage gaps).

Architecture rules (UM-DR-36 §36.9):
  * NO second planner — the model feeds the EXISTING hypothesis pool and
    research-hint channels only.
  * NO confirmation authority — the model is semantic context; CausalGuard
    remains the sole confirmation authority.
  * Fail-closed: any construction error emits a coverage gap, never a
    crash, and never fabricated entities.
  * Flag-gated (enable_application_semantic_model, default on — wired
    production integration, not a decorative import).
"""
from __future__ import annotations

import logging
from typing import Any

from webpent.appmodel.builder import build_application_model

logger = logging.getLogger(__name__)

APPMODEL_NODE_NAME = "appmodel"
APPMODEL_CHANNEL = "application_model"


def application_semantic_model_enabled() -> bool:
    """Fail-closed settings read (the UM-DR-32 wiring precedent)."""
    try:
        from webpent.config.settings import get_settings
        return bool(getattr(get_settings(), "enable_application_semantic_model", False))
    except (AttributeError, ImportError, RuntimeError, TypeError, ValueError):
        return False


def appmodel_node(state: Any) -> dict[str, Any]:
    """Build + merge the Application Semantic Model from campaign state."""
    if not application_semantic_model_enabled():
        return {"appmodel": {"enabled": False, "reason": "flag_off"}}
    try:
        model = build_application_model(state)
    except (AttributeError, KeyError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("appmodel construction failed (fail-closed, gap recorded): %s", exc)
        return {
            "appmodel": {
                "enabled": True,
                "constructed": False,
                "reason": f"construction_error:{type(exc).__name__}",
            },
        }

    projection = model.to_attack_graph_projection()
    update: dict[str, Any] = {
        APPMODEL_CHANNEL: {
            "engagement_id": model.engagement_id,
            "entity_count": len(model.entities),
            "relation_count": len(model.relations),
            "entity_kinds": sorted({str(e.kind) for e in model.entities.values()}),
            "relation_kinds": sorted({str(r.kind) for r in model.relations}),
            "coverage_gaps": list(model.coverage_gaps),
            "projection": projection,
        },
        "appmodel": {
            "enabled": True,
            "constructed": True,
            "entity_count": len(model.entities),
            "relation_count": len(model.relations),
            "coverage_gap_count": len(model.coverage_gaps),
        },
    }

    # Merge into the EXISTING attack-graph channel when present (additive).
    attack_graph = None
    if hasattr(state, "attack_graph"):
        attack_graph = getattr(state, "attack_graph", None)
    elif isinstance(state, dict):
        attack_graph = state.get("attack_graph")
    if isinstance(attack_graph, dict) and attack_graph.get("nodes"):
        try:
            from webpent.appmodel.builder import merge_appmodel_into_attack_graph
            merged = merge_appmodel_into_attack_graph(dict(attack_graph), model)
            update["attack_graph"] = merged
        except (AttributeError, KeyError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning("appmodel attack-graph merge failed (skipped): %s", exc)

    # Ordering-only research hints: coverage gaps of the semantic model are
    # exactly "underexplored parts of the application" (UM-DR-36.3/36.5).
    hints = [
        {
            "hint": f"appmodel_coverage_gap:{gap}",
            "priority": 0.35,
            "source": "appmodel",
            "ordering_only": True,
        }
        for gap in model.coverage_gaps[:16]
    ]
    if hints:
        update["appmodel_research_hints"] = hints
    return update


def wire_appmodel(graph: Any) -> None:
    """Register the appmodel node into the compiled graph wiring phase.

    The builder calls this between the intelligence/attack-graph phase and
    the strategist (hypothesis) phase: model facts must exist BEFORE
    hypothesis generation so the semantic context can inform it.
    """
    graph.add_node(APPMODEL_NODE_NAME, appmodel_node)
