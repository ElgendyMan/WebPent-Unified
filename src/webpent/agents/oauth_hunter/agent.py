"""OAuth hunter agent (optional layer).

Wraps the passive ``webpent.oauth`` analyzer. Flow replay is delegated to
the deterministic validator behind scope policy.
"""
from __future__ import annotations

from typing import Any

from webpent.oauth import OAuthSurfaceDetector, OAUTH_SCENARIOS


class OAuthHunter:
    """LangGraph-compatible node: emits OAuth/OIDC candidates."""

    agent_name = "oauth_hunter"
    vuln_classes = ("oauth",)

    def run(self, state: dict[str, Any]) -> dict[str, Any]:
        target_id = str(state.get("target_id", "unknown"))
        engagement_id = str(state.get("engagement_id", "unknown"))
        inventory = state.get("endpoint_inventory", []) or []
        analysis = OAuthSurfaceDetector().analyze(
            inventory, target_id=target_id, engagement_id=engagement_id,
        )
        return {
            "oauth_candidates": [c.model_dump() for c in analysis.candidates],
            "oauth_coverage_gaps": analysis.coverage_gaps,
            "oauth_scenarios": [s.scenario_id for s in OAUTH_SCENARIOS],
        }


__all__ = ["OAuthHunter"]
