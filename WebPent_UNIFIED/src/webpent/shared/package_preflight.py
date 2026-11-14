"""Canonical offline preflight for package-backed engagements."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from webpent.shared.package_capabilities import intersect_capabilities
from webpent.shared.package_scope import ScopeCompiler, ScopeDecisionStatus


def _gap(gap_id: str, status: str, unknown: str, *, blocking: bool = True) -> dict[str, Any]:
    return {
        "gap_id": gap_id,
        "kind": "target_package_preflight",
        "status": status,
        "unknown": unknown,
        "blocking": blocking,
        "source": "target_package_preflight",
    }


def target_package_preflight_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Validate persisted package binding before any planner/discovery work."""
    status = str(state.get("target_package_status") or "not_provided")
    if status in {"", "not_provided", "legacy"} and not state.get("target_package"):
        return {"target_package_preflight_status": "not_provided"}

    projection = state.get("target_package")
    if not isinstance(projection, Mapping):
        return {
            "target_package_preflight_status": "blocked",
            "target_package_knowledge_gaps": [
                _gap(
                    "target-package:projection-missing",
                    "blocked",
                    "package_projection_missing",
                )
            ],
            "target_package_blocked_tasks": [
                {"task": "engagement", "reason": "package_projection_missing"}
            ],
        }
    if status != "ready" or str(projection.get("status") or "") != "ready":
        reason = f"package_status_not_ready:{status or projection.get('status') or 'missing'}"
        return {
            "target_package_preflight_status": "blocked",
            "target_package_knowledge_gaps": [
                _gap("target-package:status", "blocked", reason)
            ],
            "target_package_blocked_tasks": [
                {"task": "engagement", "reason": reason}
            ],
        }
    if str(projection.get("signature_state") or "") != "verified":
        reason = "detached_signature_not_verified"
        return {
            "target_package_preflight_status": "blocked",
            "target_package_knowledge_gaps": [
                _gap("target-package:signature", "blocked", reason)
            ],
            "target_package_blocked_tasks": [
                {"task": "engagement", "reason": reason}
            ],
        }

    compiler = ScopeCompiler.from_projection(dict(projection))
    target = state.get("target")
    target_url = ""
    if isinstance(target, Mapping):
        target_url = str(target.get("url") or target.get("target_url") or "")
    else:
        target_url = str(getattr(target, "url", None) or getattr(target, "target_url", None) or "")
    target_decision = compiler.decide(target_url) if target_url else None
    if target_decision is None or not target_decision.allowed:
        decision_status = (
            target_decision.status.value
            if target_decision
            else ScopeDecisionStatus.DENY_AMBIGUOUS.value
        )
        reason = target_decision.reason if target_decision else "target_url_missing"
        gap = _gap("target-package:target-scope", decision_status, reason)
        return {
            "target_package_preflight_status": "blocked",
            "target_package_capability_matrix": {},
            "target_package_knowledge_gaps": [gap],
            "target_package_blocked_tasks": [{"task": "engagement", "reason": reason}],
        }

    matrix, gaps = intersect_capabilities(
        projection.get("capability_profile"),
        state.get("capability_manifest"),
        projection.get("policy_constraints"),
    )
    blocked_tasks = [
        {
            "task": gap.get("capability", "capability-dependent-work"),
            "reason": gap.get("unknown", "capability_gap"),
        }
        for gap in gaps
    ]
    return {
        "target_package_preflight_status": "partial" if gaps else "passed",
        "target_package_capability_matrix": matrix,
        "target_package_knowledge_gaps": gaps,
        "target_package_blocked_tasks": blocked_tasks,
    }


__all__ = ["target_package_preflight_node"]
