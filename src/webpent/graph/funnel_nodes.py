"""UM-DR-36.3 — Discovery Funnel production wiring.

One graph node (``discovery_funnel``), inserted between the reporter and
reflection (the coverage_gap_report precedent), that:

  1. REFRESHES the Application Semantic Model from the COMPLETE final
     campaign state (workflow observations, registry, principals —
     channels that materialize during the campaign, after the pre-hypothesis
     appmodel pass) so the campaign artifact records the full model
     ("construct or update", UM-DR-36.2 requirement 11);
  2. computes the 28-stage Discovery Funnel from REAL runtime state —
     every count derived from state channels, never hardcoded counters;
     missing telemetry stays NOT_MATERIALIZED, never a silent zero;
  3. persists both on declared state channels (``discovery_funnel``,
     ``application_model``) so the reporter, the campaign artifact, and
     downstream research can consume them.

Fail-closed: any error records an honest telemetry marker, never a crash,
never a fabricated count. The funnel is measurement + research context —
it holds no confirmation, admission, or scheduling authority.
"""
from __future__ import annotations

import logging
from typing import Any

from webpent.production.discovery_funnel import build_discovery_funnel

logger = logging.getLogger(__name__)

DISCOVERY_FUNNEL_NODE_NAME = "discovery_funnel"


def _state_get(state: Any, key: str) -> Any:
    if isinstance(state, dict):
        return state.get(key)
    return getattr(state, key, None)


def discovery_funnel_node(state: Any) -> dict[str, Any]:
    """Produce the Discovery Funnel + final Application Semantic Model."""
    try:
        from webpent.config.settings import get_settings
        enabled = bool(getattr(get_settings(), "enable_discovery_funnel", False))
    except (AttributeError, ImportError, RuntimeError, TypeError, ValueError):
        enabled = False
    if not enabled:
        return {"discovery_funnel": {"enabled": False, "reason": "flag_off"}}

    update: dict[str, Any] = {}
    # 1. Refresh the Application Semantic Model from the COMPLETE state
    # (the pre-hypothesis appmodel pass saw recon-stage channels only; the
    # campaign-time channels — workflow observations, registry, principals —
    # exist now). Honest update: never destroys prior valid observations;
    # the model is rebuilt deterministically from all current channels.
    try:
        from webpent.appmodel.builder import build_application_model

        final_model = build_application_model(state)
        update["application_model"] = {
            "engagement_id": final_model.engagement_id,
            "entity_count": len(final_model.entities),
            "relation_count": len(final_model.relations),
            "entity_kinds": sorted({str(e.kind) for e in final_model.entities.values()}),
            "relation_kinds": sorted({str(r.kind) for r in final_model.relations}),
            "coverage_gaps": list(final_model.coverage_gaps),
            "projection": final_model.to_attack_graph_projection(),
            "refreshed_at_stage": "discovery_funnel",
        }
    except (AttributeError, KeyError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("final appmodel refresh failed (kept pre-hypothesis model): %s", exc)

    # 2. Compute the funnel from the REAL runtime state.
    try:
        funnel = build_discovery_funnel(state)
    except (AttributeError, KeyError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("discovery funnel computation failed (fail-closed): %s", exc)
        funnel = {"enabled": True, "computed": False,
                  "reason": f"computation_error:{type(exc).__name__}"}
    else:
        funnel["enabled"] = True
        funnel["computed"] = True
    update["discovery_funnel"] = funnel
    return update


def wire_discovery_funnel(
    graph: Any,
    *,
    after_node: str = "reporter",
    before_node: str = "reflection",
) -> None:
    """Add the discovery_funnel node between reporter and reflection
    (the coverage_gap_report wiring precedent: additive, the existing
    edge stays, LangGraph super-step semantics order the fan-in)."""
    graph.add_node(DISCOVERY_FUNNEL_NODE_NAME, discovery_funnel_node)
    graph.add_edge(after_node, DISCOVERY_FUNNEL_NODE_NAME)
    graph.add_edge(DISCOVERY_FUNNEL_NODE_NAME, before_node)
