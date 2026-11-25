"""UM-DR-46 Phase E — the discovery-intel production node.

Wires the SKG-mined discovery targets (researcher/discovery_intel.py)
into the graph as an advisory channel: what the model itself says it
has NOT observed yet (unobserved transitions, parameter siblings,
single-path resources, unmarked state triggers). Mining produces no
requests and holds no authority — it only points researchers at
evidence-backed gaps.
"""
from __future__ import annotations

import logging
from typing import Any

from webpent.appmodel.skg import build_security_knowledge_graph
from webpent.researcher.discovery_intel import (
    discovery_intel_summary,
    mine_discovery_targets,
)

logger = logging.getLogger(__name__)

__all__ = ["discovery_intel_node"]

_MAX_CHANNEL_TARGETS = 64


def discovery_intel_node(state: Any) -> dict[str, Any]:
    """Mine the SKG for discovery targets (advisory channel only)."""
    try:
        model = build_security_knowledge_graph(state)
        targets = mine_discovery_targets(model)
        summary = discovery_intel_summary(model)
    except Exception as exc:  # noqa: BLE001 — advisory node, never fatal
        logger.warning("discovery intel failed (advisory node): %s", exc)
        return {
            "discovery_intel": {
                "built": False,
                "error": str(exc)[:200],
                "advisory_only": True,
                "target_count": 0,
            },
        }
    summary.update({
        "built": True,
        "targets": targets[:_MAX_CHANNEL_TARGETS],
        "influence_contract": (
            "advisory discovery guidance only — never authorizes a "
            "request, never expands scope, never bypasses "
            "CausalGuard/ProofBundle/Replay"
        ),
    })
    return {"discovery_intel": summary}
