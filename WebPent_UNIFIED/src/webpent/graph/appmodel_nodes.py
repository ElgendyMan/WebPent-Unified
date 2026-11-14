"""UM-DR-36 corrective closure — the AppModel graph node.

This node is the production wiring that was previously missing entirely:
no graph node built the application semantic model, no state channel held
it, and no downstream consumer read it. The node now

1. builds the typed, evidence-carrying ``ApplicationModel`` from REAL
   runtime state channels (``crawled_data``, ``identity_profiles``,
   ``mental_model``, engagement context) — never from LLM narration;
2. derives advisory research hints (``build_appmodel_research_hints``)
   from the model's actual entities and relations and writes them to the
   ``appmodel_research_hints`` state channel;
3. emits an ``appmodel_summary`` telemetry block that records what was
   materialized, from which channels, with which provenance counts, and
   which coverage gaps remain — so "the model was built" is a measured
   fact, not an assertion.

Hard limits (UM-DR-36 §2.3): the model is advisory for research
prioritization only. This node performs NO network I/O, grants NO
authorization, expands NO scope, executes NO request, and can NEVER
confirm a vulnerability or bypass CausalGuard / ProofBundle / Replay.
"""
from __future__ import annotations

import logging
from typing import Any

from webpent.appmodel.builder import (
    build_appmodel_research_hints,
    build_application_model,
)
from webpent.appmodel.models import ApplicationModel

logger = logging.getLogger(__name__)

__all__ = ["appmodel_node", "NODE_APPMODEL_LABEL"]

NODE_APPMODEL_LABEL = "appmodel"


def appmodel_node(state: Any) -> dict[str, Any]:
    """Build the application semantic model from real state and emit hints."""
    try:
        model = build_application_model(state)
    except Exception as exc:  # noqa: BLE001 — advisory node, never fatal
        logger.warning("appmodel construction failed (advisory node): %s", exc)
        return {
            "appmodel": {},
            "appmodel_research_hints": {},
            "appmodel_summary": {
                "built": False,
                "error": str(exc)[:200],
                "advisory_only": True,
            },
        }

    hints = build_appmodel_research_hints(model)

    get = state.get if hasattr(state, "get") else (lambda k, d=None: d)
    crawled = get("crawled_data") or {}
    crawled_channels: list[str] = []
    if isinstance(crawled, dict):
        for key in ("openapi_routes", "surface_records", "shadow_endpoints", "endpoints"):
            value = crawled.get(key)
            if isinstance(value, (list, tuple)) and value:
                crawled_channels.append(f"crawled_data.{key}={len(value)}")

    kind_counts: dict[str, int] = {}
    provenance_counts: dict[str, int] = {}
    for entity in model.entities.values():
        kind_counts[str(entity.kind)] = kind_counts.get(str(entity.kind), 0) + 1
        provenance_counts[str(entity.provenance)] = (
            provenance_counts.get(str(entity.provenance), 0) + 1
        )
    relation_kind_counts: dict[str, int] = {}
    for relation in model.relations:
        relation_kind_counts[str(relation.kind)] = (
            relation_kind_counts.get(str(relation.kind), 0) + 1
        )

    summary = {
        "built": True,
        "advisory_only": True,
        "version": model.version,
        "engagement_id": model.engagement_id,
        "entity_count": len(model.entities),
        "relation_count": len(model.relations),
        "entity_kind_counts": kind_counts,
        "relation_kind_counts": relation_kind_counts,
        "provenance_counts": provenance_counts,
        "coverage_gaps": list(model.coverage_gaps),
        "research_hint_count": len(hints),
        "research_hint_kinds": sorted({
            str(hint.get("kind")) for hint in hints.values()
        }),
        "input_channels": {
            "engagement_id": bool(str(get("engagement_id") or "").strip()),
            "crawled_channels": crawled_channels,
            "identity_profiles": len(get("identity_profiles") or {}),
            "mental_model_nodes": len(getattr(get("mental_model"), "nodes", None) or {}),
        },
        "influence_contract": (
            "advisory for research prioritization only — never authorizes, "
            "never confirms, never bypasses CausalGuard/ProofBundle/Replay"
        ),
    }
    logger.info(
        "UM-DR-36 appmodel node: entities=%d relations=%d hints=%d gaps=%d",
        len(model.entities), len(model.relations), len(hints),
        len(model.coverage_gaps),
    )
    return {
        "appmodel": _model_to_channel(model),
        "appmodel_research_hints": hints,
        "appmodel_summary": summary,
    }


def _model_to_channel(model: ApplicationModel) -> dict[str, Any]:
    """Serialize the model into the state channel (JSON-safe, bounded)."""
    return {
        "version": model.version,
        "engagement_id": model.engagement_id,
        "entities": {
            entity_id: entity.model_dump(mode="json")
            for entity_id, entity in list(model.entities.items())[:2000]
        },
        "relations": [
            relation.model_dump(mode="json")
            for relation in model.relations[:4000]
        ],
        "coverage_gaps": list(model.coverage_gaps[:50]),
        "provenance_note": model.provenance_note,
    }
