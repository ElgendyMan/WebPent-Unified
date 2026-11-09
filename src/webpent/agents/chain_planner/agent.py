"""Chain-planner agent (optional layer).

Consumes confirmed findings, builds the precondition graph, and emits
composed-chain candidates. The composed replay is delegated to the
deterministic validator behind scope policy.
"""
from __future__ import annotations

from typing import Any

from webpent.chained_exploits import (
    ChainImpactAmplifier,
    CHAIN_SCENARIOS,
    PreconditionGraphBuilder,
)


class ChainPlanner:
    """LangGraph-compatible node: emits exploit-chain candidates."""

    agent_name = "chain_planner"
    vuln_classes = ("exploit_chain",)

    def run(self, state: dict[str, Any]) -> dict[str, Any]:
        target_id = str(state.get("target_id", "unknown"))
        engagement_id = str(state.get("engagement_id", "unknown"))
        findings = state.get("confirmed_findings", []) or []
        analysis = PreconditionGraphBuilder().analyze(
            findings, target_id=target_id, engagement_id=engagement_id,
        )
        amplifier = ChainImpactAmplifier()
        amplified = [amplifier.amplify(c) for c in analysis.candidates]
        return {
            "exploit_chain_candidates": [c.model_dump() for c in analysis.candidates],
            "exploit_chain_amplified_impact": amplified,
            "exploit_chain_coverage_gaps": analysis.coverage_gaps,
            "exploit_chain_scenarios": [s.scenario_id for s in CHAIN_SCENARIOS],
        }


__all__ = ["ChainPlanner"]
