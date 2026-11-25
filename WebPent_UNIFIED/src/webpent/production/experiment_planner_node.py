"""UM-DR-46 Phase F — the experiment-planner production node.

Wires the SKG-driven experiment planner (researcher/experiment_planner
.py) into the graph: deterministic experiment plans bound to the
registry's experiment families, complete observed principal matrices
only. The planner PLANS ONLY — ResearchLoop remains the sole scheduler;
CausalGuard the sole authority; no plan executes here.
"""
from __future__ import annotations

import logging
from typing import Any

from webpent.appmodel.skg import build_security_knowledge_graph
from webpent.researcher.experiment_planner import (
    experiment_planner_summary,
    plan_experiments,
)

logger = logging.getLogger(__name__)

__all__ = ["experiment_planner_node"]

_MAX_CHANNEL_PLANS = 16


def experiment_planner_node(state: Any) -> dict[str, Any]:
    """Plan SKG-driven experiments (advisory channel only)."""
    try:
        model = build_security_knowledge_graph(state)
        plans = plan_experiments(model)
        summary = experiment_planner_summary(model)
    except Exception as exc:  # noqa: BLE001 — advisory node, never fatal
        logger.warning("experiment planner failed (advisory node): %s", exc)
        return {
            "experiment_planner": {
                "built": False,
                "error": str(exc)[:200],
                "advisory_only": True,
                "plan_count": 0,
                "scheduler_authority": "research_loop_only",
            },
            "experiment_plans": [],
        }
    summary.update({
        "built": True,
        "plans": plans[:_MAX_CHANNEL_PLANS],
        "influence_contract": (
            "advisory experiment PLANS only — the ResearchLoop is the sole "
            "scheduler, execution stays inside ModernOrchestrator "
            "(ScopeLaw + ToolBoundary), CausalGuard adjudicates every leg; "
            "this node never executes, authorizes, or confirms"
        ),
    })
    return {
        "experiment_planner": summary,
        "experiment_plans": plans[:_MAX_CHANNEL_PLANS],
    }
