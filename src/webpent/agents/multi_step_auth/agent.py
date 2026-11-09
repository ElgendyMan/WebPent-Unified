"""Multi-step auth-bypass hunter agent (optional layer).

Wraps the passive ``webpent.multi_step_auth`` analyzer. Step-replay
execution is delegated to the deterministic validator behind scope policy.
"""
from __future__ import annotations

from typing import Any

from webpent.multi_step_auth import AuthStateMachineAnalyzer, MULTI_STEP_AUTH_SCENARIOS


class MultiStepAuthHunter:
    """LangGraph-compatible node: emits multi-step auth-bypass candidates."""

    agent_name = "multi_step_auth_hunter"
    vuln_classes = ("multi_step_auth_bypass",)

    def run(self, state: dict[str, Any]) -> dict[str, Any]:
        target_id = str(state.get("target_id", "unknown"))
        engagement_id = str(state.get("engagement_id", "unknown"))
        flows = state.get("auth_flows", []) or []
        analysis = AuthStateMachineAnalyzer().analyze(
            flows, target_id=target_id, engagement_id=engagement_id,
        )
        return {
            "multi_step_auth_candidates": [c.model_dump() for c in analysis.candidates],
            "multi_step_auth_coverage_gaps": analysis.coverage_gaps,
            "multi_step_auth_scenarios": [s.scenario_id for s in MULTI_STEP_AUTH_SCENARIOS],
        }


__all__ = ["MultiStepAuthHunter"]
