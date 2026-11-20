"""Passive tenant-isolation analyzers.

Emits candidates and evidence requirements only. The cross-tenant replay
matrix is executed by the deterministic validator behind scope policy.
"""
from __future__ import annotations

import re
import uuid
from typing import Any

from webpent.families.base import (
    CandidateConfidence,
    FamilyAnalysis,
    FamilyAnalyzer,
    FamilyCandidate,
    FamilyId,
)
from webpent.tenant_isolation.scenarios import TENANT_SCENARIOS

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)


def _cid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _looks_like_object_ref(segment: str) -> bool:
    """A path segment is an object reference iff pure integer or UUID.
    A hyphen alone (e.g. 'user-profile') is deliberately NOT sufficient."""
    if not segment:
        return False
    if segment.isdigit():
        return True
    if _UUID_RE.match(segment):
        return True
    try:
        uuid.UUID(segment)
        return True
    except (ValueError, AttributeError):
        return False


class TenantBoundaryDetector(FamilyAnalyzer):
    """Surfaces endpoints where a tenant boundary is plausibly reachable."""

    family = FamilyId.TENANT_ISOLATION
    scenarios = TENANT_SCENARIOS

    def analyze(
        self,
        endpoint_inventory: list[dict[str, Any]],
        *,
        target_id: str,
        engagement_id: str,
        multi_tenant: bool = False,
    ) -> FamilyAnalysis:
        if not target_id.strip() or not engagement_id.strip():
            raise ValueError("target_and_engagement_context_required")
        observed: set[str] = set()
        if multi_tenant:
            observed.add("multi_tenant")
        object_ref_endpoints: list[str] = []
        for ep in endpoint_inventory:
            path = str(ep.get("path", ""))
            headers = {str(k).lower(): v for k, v in ep.get("headers", {}).items()}
            params = set(str(p).lower() for p in ep.get("params", []))
            endpoint_label = f"{ep.get('method','GET')} {path}"
            if any(k in path for k in ("/invite", "/share", "/transfer", "/accept")) or "invite" in params:
                observed.add("invite_or_share_token")
            if any(h in headers for h in ("x-tenant-id", "x-workspace-id", "x-organization-id", "tenant-id")):
                observed.add("tenant_context_header_or_param")
            if any(p in params for p in ("tenant", "tenant_id", "workspace", "org", "organization")):
                observed.add("tenant_context_header_or_param")
            if ep.get("hostname_routed"):
                observed.add("hostname_based_routing")
            if any(k in path for k in ("/search", "/feed", "/export", "/logs", "/webhook", "/global")):
                observed.add("shared_or_global_endpoint")
            if ep.get("roles") and "tenant_admin" in ep.get("roles", []):
                observed.add("tenant_admin_role")
            if any(k in path for k in ("/admin", "/platform", "/tenants", "/users", "/feature-flags")):
                observed.add("platform_admin_endpoints")
            last_seg = path.strip("/").rsplit("/", 1)[-1] if "/" in path.strip("/") else ""
            if ep.get("object_reference") or (last_seg and _looks_like_object_ref(last_seg)):
                observed.add("object_reference_in_url_or_body")
                object_ref_endpoints.append(endpoint_label)

        applicable = self.applicable_scenarios(observed)
        candidates: list[FamilyCandidate] = []
        for scenario in applicable:
            endpoints = object_ref_endpoints[:8] if scenario.scenario_id == "TENANT-001-cross-tenant-object-idor" else [""]
            for ep_label in endpoints:
                candidates.append(
                    FamilyCandidate(
                        candidate_id=_cid("TENANT"),
                        family=FamilyId.TENANT_ISOLATION,
                        vuln_class="tenant_isolation",
                        scenario_id=scenario.scenario_id,
                        affected_endpoint=ep_label,
                        hypothesis=(
                            f"{scenario.name}: tenant boundary may be reachable via "
                            "observed tenant-context surface; requires cross-actor replay."
                        ),
                        confidence=CandidateConfidence.SPECULATIVE,
                    )
                )
        candidates = self.dedupe(candidates)
        gaps = self.coverage_gaps_for(observed, candidates)
        if not multi_tenant:
            gaps.append("multi_tenant_not_confirmed")
        return FamilyAnalysis(
            target_id=target_id.strip()[:200],
            engagement_id=engagement_id.strip()[:200],
            family=FamilyId.TENANT_ISOLATION,
            candidates=candidates,
            applicable_scenarios=[s.scenario_id for s in applicable],
            coverage_gaps=sorted(gaps),
        )


class CrossTenantAccessMatrix(FamilyAnalyzer):
    """Builds the actor × resource matrix the validator must replay.

    The matrix itself is evidence-requirements output; no request is sent.
    """

    family = FamilyId.TENANT_ISOLATION
    scenarios = TENANT_SCENARIOS

    def build_matrix(
        self,
        tenant_resources: list[dict[str, Any]],
        actor_tenants: list[str],
    ) -> list[dict[str, str]]:
        matrix: list[dict[str, str]] = []
        for resource in tenant_resources[:64]:
            for actor in actor_tenants[:8]:
                matrix.append(
                    {
                        "actor_tenant": actor,
                        "resource_tenant": str(resource.get("tenant", "")),
                        "resource_ref": str(resource.get("ref", "")),
                        "expected": "reject" if actor != resource.get("tenant") else "allow",
                    }
                )
        return matrix


__all__ = ["CrossTenantAccessMatrix", "TenantBoundaryDetector", "_looks_like_object_ref"]
