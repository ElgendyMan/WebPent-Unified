"""Passive OAuth / OIDC analyzers.

Emits candidates and evidence requirements only. The actual OAuth flow
replay (authorize → callback → token) is executed by the deterministic
validator behind scope policy.
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
from webpent.oauth.scenarios import OAUTH_SCENARIOS


def _cid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class OAuthSurfaceDetector(FamilyAnalyzer):
    """Detects OAuth/OIDC endpoints and marks which scenarios are reachable."""

    family = FamilyId.OAUTH
    scenarios = OAUTH_SCENARIOS

    def analyze(
        self,
        endpoint_inventory: list[dict[str, Any]],
        *,
        target_id: str,
        engagement_id: str,
    ) -> FamilyAnalysis:
        if not target_id.strip() or not engagement_id.strip():
            raise ValueError("target_and_engagement_context_required")
        observed: set[str] = set()
        authorize_endpoints: list[str] = []
        for ep in endpoint_inventory:
            path = str(ep.get("path", ""))
            params = set(str(p).lower() for p in ep.get("params", []))
            if any(k in path for k in ("/authorize", "/oauth", "/oidc", "/auth")):
                observed.add("oauth_authorize_endpoint")
                authorize_endpoints.append(path)
            if "redirect_uri" in params or "redirect_url" in params:
                observed.add("redirect_uri_param")
            if "response_type" in params:
                observed.add("response_type_param")
            if "scope" in params:
                observed.add("scope_param")
            if any(k in path for k in ("/token", "/oauth/token", "/access_token")):
                observed.add("oauth_token_endpoint")
                observed.add("authorization_code_flow")
            if ep.get("public_client") or ep.get("js_app") or ep.get("mobile_app"):
                observed.add("public_client_or_js_app")
                observed.add("public_client_or_authorization_code_flow")
            if ep.get("callback_page"):
                observed.add("oauth_callback_page")
                observed.add("third_party_links_on_callback")
            if ep.get("account_linking"):
                observed.add("account_linking_on_email")
            if ep.get("id_token"):
                observed.add("oidc_id_token")

        applicable = self.applicable_scenarios(observed)
        candidates: list[FamilyCandidate] = []
        for scenario in applicable:
            for ep in authorize_endpoints[:4] or [""]:
                candidates.append(
                    FamilyCandidate(
                        candidate_id=_cid("OAUTH"),
                        family=FamilyId.OAUTH,
                        vuln_class="oauth",
                        scenario_id=scenario.scenario_id,
                        affected_endpoint=ep if ep != "" else "oauth-surface",
                        hypothesis=f"{scenario.name}: reachable via observed OAuth surface.",
                        confidence=CandidateConfidence.SPECULATIVE,
                    )
                )
        candidates = self.dedupe(candidates)
        gaps = self.coverage_gaps_for(observed, candidates)
        if not authorize_endpoints:
            gaps.append("no_oauth_authorize_endpoint_observed")
        return FamilyAnalysis(
            target_id=target_id.strip()[:200],
            engagement_id=engagement_id.strip()[:200],
            family=FamilyId.OAUTH,
            candidates=candidates,
            applicable_scenarios=[s.scenario_id for s in applicable],
            coverage_gaps=sorted(gaps),
        )


__all__ = ["OAuthSurfaceDetector"]
