"""UM-DR-46 Phase J — the protocol-depth production node.

Projects the SKG into protocol-depth targets (workflow sequences,
enumerable object-id spaces, cross-origin workflows). Advisory
targets only — no requests, no authority.
"""
from __future__ import annotations

import logging
from typing import Any

from webpent.appmodel.skg import build_security_knowledge_graph

logger = logging.getLogger(__name__)

__all__ = ["protocol_depth_node"]

_MAX_CHANNEL_TARGETS = 32


def protocol_depth_node(state: Any) -> dict[str, Any]:
    """Mine the SKG for protocol-depth targets (advisory channel)."""
    try:
        model = build_security_knowledge_graph(state)
        from webpent.researcher.protocol_depth import protocol_depth_targets

        targets = protocol_depth_targets(model)
    except Exception as exc:  # noqa: BLE001 — advisory node, never fatal
        logger.warning("protocol depth failed (advisory node): %s", exc)
        return {
            "protocol_depth": {
                "built": False,
                "error": str(exc)[:200],
                "advisory_only": True,
                "target_count": 0,
            },
        }
    kinds: dict[str, int] = {}
    for target in targets:
        kinds[str(target["kind"])] = kinds.get(str(target["kind"]), 0) + 1
    return {
        "protocol_depth": {
            "built": True,
            "advisory_only": True,
            "target_count": len(targets),
            "kinds": kinds,
            "targets": targets[:_MAX_CHANNEL_TARGETS],
            "influence_contract": (
                "advisory depth targets only — never a request, never an "
                "authorization, never a scope expansion"
            ),
        },
    }
