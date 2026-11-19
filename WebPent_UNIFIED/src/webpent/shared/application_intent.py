"""Safe application-intent projection for business-logic exploration."""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

_ALLOWED_ASSUMPTIONS = {
    "tenant_isolation",
    "object_ownership",
    "workflow_transition_integrity",
    "rate_limiting",
    "authenticated_boundary",
    "role_separation",
    "resource_exposure",
}


def _deterministic_assumptions(
    *,
    auth_signals: list[str],
    identities: list[dict[str, Any]],
    objects: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    endpoint_details: list[dict[str, Any]],
) -> list[str]:
    assumptions: set[str] = set()
    if auth_signals or identities:
        assumptions.add("authenticated_boundary")
    if len(identities) >= 2 or "multi-identity-context" in auth_signals:
        assumptions.update({"tenant_isolation", "role_separation"})
    if any(item.get("owner_identity") is not None for item in objects):
        assumptions.add("object_ownership")
    if workflows:
        assumptions.add("workflow_transition_integrity")
    parameter_names = {
        str(name).lower()
        for detail in endpoint_details
        for name in detail.get("parameter_names", [])
    }
    if parameter_names & {
        "tenant",
        "tenant_id",
        "org",
        "org_id",
        "workspace",
        "account",
        "context",
    }:
        assumptions.add("tenant_isolation")
    if parameter_names & {"limit", "offset", "page", "cursor", "per_page"}:
        assumptions.add("rate_limiting")
    if objects:
        assumptions.add("resource_exposure")
    return sorted(assumptions)


def _llm_assumptions(
    *,
    target_url: str | None,
    summary: dict[str, Any],
    deterministic: list[str],
) -> tuple[str, list[str], str] | None:
    """Ask one bounded question when an LLM is available; fail closed."""
    try:
        from langchain_core.messages import HumanMessage, SystemMessage

        from webpent.shared.llm import (
            TaskType,
            get_safety_system_instruction,
            safe_prompt_format,
            try_get_llm,
        )

        llm = try_get_llm(TaskType.ANALYSIS)
        if llm is None:
            return None
        system = (
            "Infer the application's defensive business purpose for a scoped "
            "security assessment. Return JSON only with keys application_goal "
            "and policy_assumptions. policy_assumptions must be selected only "
            "from: tenant_isolation, object_ownership, "
            "workflow_transition_integrity, rate_limiting, "
            "authenticated_boundary, role_separation, resource_exposure. "
            "Do not invent vulnerabilities, endpoints, credentials, or payloads."
        )
        prompt = safe_prompt_format(
            "Target: {target}\nStructured summary: {summary}\n"
            "Deterministic assumptions already observed: {deterministic}\n"
            "What is this application most likely trying to prevent?",
            target=(target_url or "unknown")[:200],
            summary=json.dumps(summary, sort_keys=True)[:3000],
            deterministic=", ".join(deterministic),
        )
        response = llm.invoke([
            SystemMessage(content=get_safety_system_instruction()),
            SystemMessage(content=system),
            HumanMessage(content=prompt),
        ])
        raw = response.content if isinstance(response.content, str) else str(response.content)
        parsed = json.loads(raw.strip())
        goal = str(parsed.get("application_goal") or "").strip()[:500]
        assumptions = [
            value for value in parsed.get("policy_assumptions", [])
            if isinstance(value, str) and value in _ALLOWED_ASSUMPTIONS
        ][:7]
        if not goal and not assumptions:
            return None
        merged = sorted(set(deterministic) | set(assumptions))
        return (
            goal or "Protect authenticated resources and workflow boundaries.",
            merged,
            "llm_intent",
        )
    except Exception as exc:
        logger.debug("Application intent LLM projection unavailable: %s", exc)
        return None


def infer_application_intent(
    *,
    target_url: str | None,
    auth_signals: list[str],
    identities: list[dict[str, Any]],
    objects: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    endpoint_details: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return a redacted, bounded intent projection for downstream agents."""
    deterministic = _deterministic_assumptions(
        auth_signals=auth_signals,
        identities=identities,
        objects=objects,
        workflows=workflows,
        endpoint_details=endpoint_details,
    )
    summary = {
        "identity_count": len(identities),
        "object_count": len(objects),
        "workflow_count": len(workflows),
        "endpoint_count": len(endpoint_details),
        "auth_signals": auth_signals[:20],
    }
    llm_result = _llm_assumptions(
        target_url=target_url,
        summary=summary,
        deterministic=deterministic,
    )
    if llm_result:
        goal, assumptions, source = llm_result
    else:
        assumptions = deterministic
        goal = (
            "Protect authenticated resources, ownership boundaries, and valid workflow "
            "transitions."
        )
        source = "deterministic_projection"
    return {
        "schema_version": 1,
        "application_goal": goal[:500],
        "policy_assumptions": assumptions[:7],
        "source": source,
        "evidence_refs": ["obs://target-understanding/intent"],
    }


__all__ = ["infer_application_intent"]
