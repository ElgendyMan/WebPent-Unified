"""UM-DR-46 Phase G — the SKG-coverage production node.

Projects the Security Knowledge Graph into (resource × principal ×
operation) coverage cells, each VERIFIED only when its evidence
intersects the state's guard-adjudicated observations; everything else
is honestly observed_unverified. Advisory telemetry only.
"""
from __future__ import annotations

import logging
from typing import Any

from webpent.appmodel.skg import build_security_knowledge_graph
from webpent.researcher.coverage_intel import skg_coverage_summary

logger = logging.getLogger(__name__)

__all__ = ["skg_coverage_node"]

_MAX_CHANNEL_CELLS = 64


def _verified_refs(state: Any) -> set[str]:
    get = state.get if isinstance(state, dict) else (
        lambda k, d=None: d)
    refs: set[str] = set()
    for record in get("authorization_observations") or []:
        if not isinstance(record, dict):
            continue
        verdict = str(record.get("guard_verdict") or "").lower()
        finding_id = str(record.get("finding_id") or "").strip()
        if verdict in {"confirmed", "falsified"} and finding_id:
            refs.add(f"authorization-observation:{finding_id}")
    return refs


def skg_coverage_node(state: Any) -> dict[str, Any]:
    """Project the SKG into advisory coverage cells."""
    try:
        model = build_security_knowledge_graph(state)
        verified = _verified_refs(state)
        from webpent.researcher.coverage_intel import skg_coverage_cells

        cells = skg_coverage_cells(model, verified)
        summary = skg_coverage_summary(model, verified)
    except Exception as exc:  # noqa: BLE001 — advisory node, never fatal
        logger.warning("skg coverage failed (advisory node): %s", exc)
        return {
            "skg_coverage": {
                "built": False,
                "error": str(exc)[:200],
                "advisory_only": True,
                "cell_count": 0,
            },
        }
    summary.update({
        "built": True,
        "cells": cells[:_MAX_CHANNEL_CELLS],
        "influence_contract": (
            "advisory coverage telemetry only — never a verdict, never a "
            "test result, never an authority"
        ),
    })
    return {"skg_coverage": summary}
