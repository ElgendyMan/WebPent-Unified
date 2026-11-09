"""Passive multi-step auth-bypass analyzers.

Emits candidates and evidence requirements only. Step-replay execution
lives in the deterministic validator behind scope policy.
"""
from __future__ import annotations

import uuid
from typing import Any

from webpent.families.base import (
    CandidateConfidence,
    FamilyAnalysis,
    FamilyAnalyzer,
    FamilyCandidate,
    FamilyId,
)
from webpent.multi_step_auth.scenarios import MULTI_STEP_AUTH_SCENARIOS


def _cid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class AuthStateMachineAnalyzer(FamilyAnalyzer):
    """Reconstructs multi-step auth flows and marks reachable bypass points."""

    family = FamilyId.MULTI_STEP_AUTH_BYPASS
    scenarios = MULTI_STEP_AUTH_SCENARIOS

    def analyze(
        self,
        auth_flows: list[dict[str, Any]],
        *,
        target_id: str,
        engagement_id: str,
    ) -> FamilyAnalysis:
        if not target_id.strip() or not engagement_id.strip():
            raise ValueError("target_and_engagement_context_required")
        observed: set[str] = set()
        multi_step_flows: list[dict[str, Any]] = []
        for flow in auth_flows:
            steps = flow.get("steps", [])
            if len(steps) >= 2:
                observed.add("multi_step_auth_flow")
                multi_step_flows.append(flow)
            if flow.get("client_state_token"):
                observed.add("client_side_state_token")
            if flow.get("partial_session"):
                observed.add("partial_session_issued")
            if flow.get("stateful_sequence"):
                observed.add("stateful_step_sequence")
            if any(s.get("type") == "mfa" for s in steps):
                observed.add("mfa_step")
            if flow.get("kind") == "password_reset":
                observed.add("password_reset_flow")
                observed.add("multi_step")

        applicable = self.applicable_scenarios(observed)
        candidates: list[FamilyCandidate] = []
        for flow in multi_step_flows[:16]:
            for scenario in applicable:
                candidates.append(
                    FamilyCandidate(
                        candidate_id=_cid("MSAUTH"),
                        family=FamilyId.MULTI_STEP_AUTH_BYPASS,
                        vuln_class="multi_step_auth_bypass",
                        scenario_id=scenario.scenario_id,
                        affected_endpoint=str(flow.get("final_step", "")),
                        hypothesis=(
                            f"{scenario.name} in flow '{flow.get('name','auth')}' "
                            f"({len(flow.get('steps', []))} steps)."
                        ),
                        confidence=CandidateConfidence.SPECULATIVE,
                    )
                )
        return FamilyAnalysis(
            target_id=target_id.strip()[:200],
            engagement_id=engagement_id.strip()[:200],
            family=FamilyId.MULTI_STEP_AUTH_BYPASS,
            candidates=candidates,
            applicable_scenarios=[s.scenario_id for s in applicable],
            coverage_gaps=self.coverage_gaps_for(observed, candidates),
        )


__all__ = ["AuthStateMachineAnalyzer"]
