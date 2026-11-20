"""Tenant-isolation hunter agent (optional layer).

Wraps the passive ``webpent.tenant_isolation`` analyzers and emits
candidates. Execution of the cross-tenant replay matrix is delegated to
the deterministic validator behind scope policy; this agent never issues
HTTP and never promotes a finding.
"""
from __future__ import annotations

from typing import Any

from webpent.tenant_isolation import (
    CrossTenantAccessMatrix,
    TenantBoundaryDetector,
    TENANT_SCENARIOS,
)


class TenantIsolationHunter:
    """LangGraph-compatible node: emits tenant-isolation candidates."""

    agent_name = "tenant_isolation_hunter"
    vuln_classes = ("tenant_isolation",)

    def run(
        self,
        state: dict[str, Any],
    ) -> dict[str, Any]:
        target_id = str(state.get("target_id", "unknown"))
        engagement_id = str(state.get("engagement_id", "unknown"))
        inventory = state.get("endpoint_inventory", []) or []
        multi_tenant = bool(state.get("multi_tenant", False))
        analysis = TenantBoundaryDetector().analyze(
            inventory, target_id=target_id, engagement_id=engagement_id,
            multi_tenant=multi_tenant,
        )
        matrix = CrossTenantAccessMatrix().build_matrix(
            state.get("tenant_resources", []) or [],
            state.get("actor_tenants", []) or [],
        )
        return {
            "tenant_isolation_candidates": [c.model_dump() for c in analysis.candidates],
            "tenant_isolation_coverage_gaps": analysis.coverage_gaps,
            "cross_tenant_replay_matrix": matrix,
            "tenant_isolation_scenarios": [s.scenario_id for s in TENANT_SCENARIOS],
        }


__all__ = ["TenantIsolationHunter"]
