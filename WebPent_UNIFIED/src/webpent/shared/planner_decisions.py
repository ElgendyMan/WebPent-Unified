"""Phase 7 planner decision proposals and deterministic policy gates.

This module is deliberately execution-free. It parses a bounded proposal,
checks it against engagement state and policy, and returns an auditable result.
No proposal is converted into a shell command or an arbitrary network request.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import ValidationError

from webpent.config.settings import Settings, get_settings
from webpent.models.planner import (
    PlannerActionType,
    PlannerDecisionProposal,
    PlannerDecisionStatus,
    PlannerGateAudit,
    PlannerRiskLevel,
)
from webpent.shared.poc_policy import evaluate_poc_risk
from webpent.tools.registry import get_all_categories

logger = logging.getLogger(__name__)

_ALLOWED_TARGET_REF = "engagement_target"
_SENSITIVE_QUERY_KEY = re.compile(
    r"(?:token|secret|password|passwd|authorization|cookie|session|jwt|api[_-]?key|key)$",
    re.IGNORECASE,
)
_ACTION_CATEGORIES: dict[str, tuple[str, ...]] = {
    PlannerActionType.OBSERVE_TARGET.value: (),
    PlannerActionType.ENUMERATE_SURFACE.value: ("recon", "discovery"),
    PlannerActionType.RUN_READ_ONLY_TOOL.value: ("recon", "analysis", "validation"),
    PlannerActionType.VALIDATE_HYPOTHESIS.value: ("validation", "exploitation"),
    PlannerActionType.REVISIT_SURFACE.value: ("recon", "validation", "analysis"),
    PlannerActionType.NO_ACTION.value: (),
}


def redact_prompt_target(url: str) -> str:
    """Return a prompt-safe target label without credentials or secret values."""
    raw = str(url or "").strip()
    if not raw:
        return "(unknown target)"
    try:
        parts = urlsplit(raw)
        if not parts.hostname:
            return raw[:256]
        host = parts.hostname
        if parts.port:
            host = f"{host}:{parts.port}"
        pairs = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            pairs.append((key, "[REDACTED]" if _SENSITIVE_QUERY_KEY.search(key) else value[:64]))
        query = urlencode(pairs)
        return urlunsplit((parts.scheme.lower(), host, parts.path[:256], query, ""))[:512]
    except Exception:
        return "(target-redacted)"


def _get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)


def _enum_value(value: Any) -> str:
    raw = getattr(value, "value", value)
    return str(raw)


def _known_target_refs(state: dict[str, Any]) -> set[str]:
    refs = {_ALLOWED_TARGET_REF}
    mental_model = state.get("mental_model") or {}
    nodes = mental_model.get("nodes", {}) if isinstance(mental_model, dict) else {}
    if isinstance(nodes, dict):
        for node_id, node in nodes.items():
            kind = str(_get(node, "kind", ""))
            if kind in {"endpoint", "host", "service"}:
                refs.add(f"node:{node_id}")
    return refs


def _known_hypothesis_refs(state: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for hypothesis in state.get("hypotheses") or []:
        identifier = _get(hypothesis, "id")
        if identifier:
            result.add(str(identifier))
    return result


def _proof_replan_proposal(state: dict[str, Any]) -> PlannerDecisionProposal | None:
    """Turn an inconclusive proof oracle into one bounded evidence-seeking action."""
    oracle_results = state.get("proof_oracle_results") or state.get("proof_outcomes") or []
    if isinstance(oracle_results, dict):
        oracle_results = [oracle_results]
    for result in oracle_results:
        if not isinstance(result, dict):
            continue
        status = str(result.get("status") or result.get("disposition") or "")
        if status not in {"inconclusive", "needs_review"}:
            continue
        missing = [str(item) for item in result.get("missing", []) if item]
        if not missing:
            continue
        target_ref = str(result.get("target_ref") or _ALLOWED_TARGET_REF)
        if target_ref not in _known_target_refs(state):
            target_ref = _ALLOWED_TARGET_REF
        campaign_key = str(result.get("campaign_key") or "")
        missing_text = ", ".join(sorted(set(missing + ["negative_control"])))
        return PlannerDecisionProposal(
            action_type=PlannerActionType.VALIDATE_HYPOTHESIS,
            target_ref=target_ref,
            hypothesis_ref=str(result.get("hypothesis_ref"))
            if result.get("hypothesis_ref")
            else None,
            expected_evidence=sorted(set(missing + ["negative_control"])),
            estimated_cost=3.0,
            risk_level=PlannerRiskLevel.MEDIUM,
            rationale=(
                "Proof-driven replan: collect missing oracle evidence "
                f"({missing_text}) before repeating confirmation for "
                f"{campaign_key or 'the current hypothesis'}."
            ),
            source="proof-driven",
        )
    return None


def _deterministic_proposal(state: dict[str, Any]) -> PlannerDecisionProposal:
    """Choose a safe, bounded next action from state only."""
    proof_replan = _proof_replan_proposal(state)
    if proof_replan is not None:
        return proof_replan
    hypotheses = state.get("hypotheses") or []
    mental_model = state.get("mental_model") or {}
    nodes = mental_model.get("nodes", {}) if isinstance(mental_model, dict) else {}
    endpoint_nodes = []
    if isinstance(nodes, dict):
        endpoint_nodes = [
            str(node_id) for node_id, node in nodes.items()
            if str(_get(node, "kind", "")) == "endpoint"
        ]

    if hypotheses:
        first = hypotheses[0]
        hypothesis_id = str(_get(first, "id", ""))
        return PlannerDecisionProposal(
            action_type=PlannerActionType.VALIDATE_HYPOTHESIS,
            target_ref=f"node:{endpoint_nodes[0]}" if endpoint_nodes else _ALLOWED_TARGET_REF,
            hypothesis_ref=hypothesis_id or None,
            expected_evidence=["reproducible_request", "response_delta", "scope_check"],
            estimated_cost=3.0,
            risk_level=PlannerRiskLevel.MEDIUM,
            rationale=(
                "A bounded hypothesis exists; validate it through the existing "
                "evidence pipeline."
            ),
            source="deterministic",
        )
    if endpoint_nodes:
        return PlannerDecisionProposal(
            action_type=PlannerActionType.REVISIT_SURFACE,
            target_ref=f"node:{endpoint_nodes[0]}",
            expected_evidence=["endpoint_observation", "method_and_parameter_inventory"],
            estimated_cost=1.0,
            risk_level=PlannerRiskLevel.LOW,
            rationale=(
                "Known endpoint surface should be revisited with a bounded "
                "read-only observation."
            ),
            source="deterministic",
        )
    return PlannerDecisionProposal(
        action_type=PlannerActionType.OBSERVE_TARGET,
        target_ref=_ALLOWED_TARGET_REF,
        expected_evidence=["target_identity", "scope_decision"],
        estimated_cost=0.5,
        risk_level=PlannerRiskLevel.LOW,
        rationale=(
            "No structured surface is available yet; establish target identity "
            "and scope first."
        ),
        source="deterministic",
    )


def parse_proposal(raw: Any) -> PlannerDecisionProposal:
    """Parse strict JSON output and reject markdown, extra keys, and garbage."""
    content = raw
    if hasattr(raw, "content"):
        content = raw.content
    if not isinstance(content, str):
        raise ValueError("planner response must contain a JSON string")
    text = content.strip()
    if text.startswith("```"):
        raise ValueError("markdown-wrapped planner JSON is rejected")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("planner JSON must be an object")
    proposal = PlannerDecisionProposal.model_validate({**data, "source": "llm"})
    return proposal


def evaluate_proposal(
    proposal: PlannerDecisionProposal,
    state: dict[str, Any],
    *,
    settings: Settings | None = None,
    fallback_used: bool = False,
    llm_contribution: str = "",
    human_approved: bool = False,
) -> PlannerGateAudit:
    """Run policy, scope, budget, and tool-availability gates in order."""
    settings = settings or get_settings()
    passed: list[str] = []
    failed: list[str] = []
    categories = _ACTION_CATEGORIES.get(_enum_value(proposal.action_type), ())

    if _enum_value(proposal.action_type) not in _ACTION_CATEGORIES:
        failed.append("policy:action_allowlist")
    else:
        passed.append("policy:action_allowlist")

    known_targets = _known_target_refs(state)
    if proposal.target_ref in known_targets:
        passed.append("scope:target_reference")
    else:
        failed.append("scope:target_reference")

    hypothesis_refs = _known_hypothesis_refs(state)
    action = _enum_value(proposal.action_type)
    if action == PlannerActionType.VALIDATE_HYPOTHESIS.value:
        if proposal.hypothesis_ref and proposal.hypothesis_ref in hypothesis_refs:
            passed.append("scope:hypothesis_reference")
        else:
            failed.append("scope:hypothesis_reference")
    elif proposal.hypothesis_ref and proposal.hypothesis_ref not in hypothesis_refs:
        failed.append("scope:hypothesis_reference")
    else:
        passed.append("scope:hypothesis_reference")

    max_cost = float(getattr(settings, "max_planner_decision_cost", 10.0))
    if proposal.estimated_cost <= max_cost:
        passed.append("budget:estimated_cost")
    else:
        failed.append("budget:estimated_cost")

    available = set(get_all_categories()) | set(state.get("available_tool_categories") or [])
    missing_categories = [category for category in categories if category not in available]
    if not categories or not missing_categories:
        passed.append("tools:availability")
    else:
        failed.append("tools:availability")

    risk = _enum_value(proposal.risk_level)
    poc_decision = evaluate_poc_risk(risk, human_approved=human_approved)
    if poc_decision.status == "rejected":
        failed.append(
            "policy:destructive_action"
            if risk == PlannerRiskLevel.DESTRUCTIVE.value
            else "policy:invalid_poc_risk"
        )
    elif poc_decision.status == "needs_approval":
        failed.append("risk:human_approval_required")
    else:
        passed.append("policy:poc_safety")

    if failed:
        status = (
            PlannerDecisionStatus.NEEDS_APPROVAL
            if "risk:human_approval_required" in failed and len(failed) == 1
            else PlannerDecisionStatus.REJECTED
        )
        reason = "Decision rejected by deterministic gates: " + ", ".join(failed)
    else:
        status = PlannerDecisionStatus.FALLBACK if fallback_used else PlannerDecisionStatus.ACCEPTED
        reason = "All deterministic planner gates passed."

    return PlannerGateAudit(
        proposal_id=proposal.id,
        status=status,
        gates_passed=passed,
        gates_failed=failed,
        reason=reason,
        fallback_used=fallback_used,
        tool_categories=list(categories),
        llm_contribution=llm_contribution[:500],
        metadata={"target_ref": proposal.target_ref, "action_type": action},
    )


def build_planner_decision(
    state: dict[str, Any],
    *,
    raw_llm_response: Any = None,
    settings: Settings | None = None,
) -> tuple[PlannerDecisionProposal, PlannerGateAudit]:
    """Parse LLM output when valid, otherwise use safe deterministic fallback."""
    settings = settings or get_settings()
    fallback_used = False
    llm_contribution = ""
    if raw_llm_response is not None:
        try:
            proposal = parse_proposal(raw_llm_response)
            llm_contribution = "validated_structured_proposal"
        except (ValueError, TypeError, json.JSONDecodeError, ValidationError) as exc:
            logger.warning("Planner LLM proposal rejected: %s", exc)
            proposal = _deterministic_proposal(state)
            fallback_used = True
            llm_contribution = "malformed_or_unsafe_output_rejected"
    else:
        proposal = _deterministic_proposal(state)
        fallback_used = True
        llm_contribution = "llm_unavailable_or_disabled"

    audit = evaluate_proposal(
        proposal,
        state,
        settings=settings,
        fallback_used=fallback_used,
        llm_contribution=llm_contribution,
    )
    return proposal, audit
