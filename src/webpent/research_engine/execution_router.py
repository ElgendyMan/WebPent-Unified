"""Fail-closed routing for bounded autonomous research tasks.

The router is advisory and policy-aware. It never performs transport; execution,
when allowed, remains the responsibility of the existing ActionAuthority and
CampaignExecutor contracts.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from webpent.shared.campaign_executor import CampaignTask


class RouteStatus(str):
    ALLOWED = "allowed"
    BLOCKED = "blocked"


class RouteDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    task_id: str = Field(min_length=1, max_length=160)
    status: Literal["allowed", "blocked"]
    capability: str = Field(min_length=1, max_length=120)
    route: Literal["observation", "analysis", "proof", "none"]
    reasons: tuple[str, ...] = Field(default=(), max_length=16)

    @property
    def allowed(self) -> bool:
        return self.status == RouteStatus.ALLOWED


class CapabilityAwareRouter:
    """Map safe research tasks to bounded routes without granting authority."""

    _ROUTES = {
        "http_read": "observation",
        "offline_analysis": "analysis",
        "proof_verify": "proof",
    }
    _DENIED_CAPABILITIES = {
        "external_network",
        "credential_use",
        "auth_bypass",
        "state_mutation",
        "destructive_action",
        "callback",
        "shell_execution",
    }

    def route(
        self,
        task: CampaignTask,
        *,
        available_capabilities: set[str] | frozenset[str],
        scope_authorized: bool,
        authority_available: bool,
    ) -> RouteDecision:
        reasons: list[str] = []
        route = self._ROUTES.get(task.capability, "none")
        if not scope_authorized:
            reasons.append("scope_not_authorized")
        if not authority_available:
            reasons.append("action_authority_unavailable")
        if task.capability in self._DENIED_CAPABILITIES:
            reasons.append("capability_forbidden")
        if task.capability not in available_capabilities:
            reasons.append("capability_unavailable")
        if task.method.upper() not in {"GET", "HEAD"}:
            reasons.append("method_not_read_only")
        if task.body_schema != "none" or task.content_type:
            reasons.append("request_body_not_allowed")
        if task.risk_tier.value not in {"read_only", "passive"}:
            reasons.append("risk_tier_not_bounded")
        if task.capability == "http_read" and not task.target_url:
            reasons.append("target_url_required")
        elif task.target_url and not task.target_url.startswith("http://127.0.0.1:"):
            reasons.append("target_origin_not_loopback")
        status = RouteStatus.ALLOWED if not reasons else RouteStatus.BLOCKED
        return RouteDecision(
            task_id=task.task_id,
            status=status,
            capability=task.capability,
            route=route if status == RouteStatus.ALLOWED else "none",
            reasons=tuple(reasons),
        )


__all__ = ["CapabilityAwareRouter", "RouteDecision", "RouteStatus"]
