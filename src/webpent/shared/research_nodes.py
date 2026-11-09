"""Graph-owned research planning nodes.

These nodes are deliberately advisory. They derive typed research context,
rank bounded information actions, and persist a report-safe session projection.
They never perform transport, authorize execution, or confirm findings.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from webpent.models.research import CandidateAction, ResearchContext
from webpent.shared.research_contracts import researcher_metadata_for_action
from webpent.shared.research_intelligence import (
    InformationAction,
    KnowledgeGapEngine,
    ResearchSession,
    SmartNextBestActionEngine,
)
from webpent.shared.runtime import RuntimeContext


def _bounded_items(values: list[dict[str, Any]], limit: int = 100) -> list[dict[str, Any]]:
    """Return deterministic, redaction-safe list data with a hard bound."""
    return values[:limit]


def knowledge_gap_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Derive explicit gaps from observed state and publish typed candidates."""
    gaps = KnowledgeGapEngine(max_gaps=24).derive(state)
    gap_payloads = _bounded_items([gap.as_dict() for gap in gaps], 24)
    context = ResearchContext.from_state(dict(state))
    context = context.model_copy(
        update={
            "unknowns": [gap.unknown for gap in gaps][:100],
            "open_gap_ids": [gap.gap_id for gap in gaps][:100],
            "checkpoint_safe": True,
        }
    )
    actions = [
        action.as_dict()
        for gap in gaps
        for action in gap.candidate_actions
    ][:100]
    candidate_actions: list[dict[str, Any]] = []
    for gap in gaps:
        for action in gap.candidate_actions:
            try:
                action_payload = {
                    key: value
                    for key, value in action.as_dict().items()
                    if key != "fingerprint"
                }
                candidate = CandidateAction.model_validate(
                    {
                        **action_payload,
                        "gap_id": gap.gap_id,
                        "hypothesis_id": f"research:{gap.gap_id}",
                        "evidence_potential": min(1.0, action.expected_information_gain),
                        "coverage_value": min(1.0, action.expected_information_gain),
                        "required_capabilities": [action.capability],
                        "policy_tags": ["advisory_research"],
                        "metadata": {
                            **researcher_metadata_for_action(action.action_class),
                            **dict(action.metadata),
                        },
                    }
                )
            except (TypeError, ValueError):
                continue
            candidate_actions.append(candidate.as_dict())
    return {
        "knowledge_gaps": gap_payloads,
        "smart_information_actions": _bounded_items(actions, 100),
        "research_candidate_actions": _bounded_items(candidate_actions, 100),
        "research_context": context.as_dict(),
        "research_unified_decision_trace": [
            {
                "stage": "knowledge_gap_discovery",
                "status": "completed",
                "gap_count": len(gap_payloads),
                "action_count": len(actions),
                "advisory_only": True,
            }
        ],
    }


def _candidate_to_information_action(raw: Mapping[str, Any]) -> InformationAction | None:
    """Convert a serialized action only when its enum/schema is valid."""
    try:
        action_class = raw.get("action_class")
        if not hasattr(action_class, "value"):
            from webpent.shared.research_intelligence import ActionClass

            action_class = ActionClass(str(action_class))
        return InformationAction(
            action_id=str(raw.get("action_id") or "")[:160],
            action_class=action_class,
            objective=str(raw.get("objective") or "")[:500],
            target_ref=str(raw.get("target_ref") or "")[:500],
            method=str(raw.get("method") or "GET")[:16].upper(),
            identity_context=str(raw.get("identity_context") or "anonymous")[:120],
            tenant_context=str(raw.get("tenant_context") or "unknown")[:120],
            workflow_state=str(raw.get("workflow_state") or "unknown")[:120],
            expected_information_gain=float(raw.get("expected_information_gain", 0.0)),
            cost=float(raw.get("cost", 1.0)),
            failure_probability=float(raw.get("failure_probability", 0.0)),
            scope_risk=float(raw.get("scope_risk", 0.0)),
            rate_limit_cost=float(raw.get("rate_limit_cost", 0.0)),
            dependency_penalty=float(raw.get("dependency_penalty", 0.0)),
            capability=str(raw.get("capability") or "http_read")[:80],
            requires_approval=bool(raw.get("requires_approval", False)),
            idempotency_key=str(raw.get("idempotency_key") or "")[:160],
            justification=str(raw.get("justification") or "")[:500],
            metadata=raw.get("metadata") if isinstance(raw.get("metadata"), Mapping) else {},
        )
    except (TypeError, ValueError, KeyError):
        return None


def next_best_action_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Rank only serialized, bounded research actions; never execute them."""
    actions: list[InformationAction] = []
    for raw in (state.get("smart_information_actions") or [])[:100]:
        if isinstance(raw, Mapping):
            action = _candidate_to_information_action(raw)
            if action is not None and action.action_id and action.target_ref:
                actions.append(action)
    context = ResearchContext.from_state(dict(state))
    attempted = tuple(context.attempted_action_fingerprints)
    runtime_context = state.get("runtime_context")
    ranker = (
        runtime_context.next_best_action_engine
        if isinstance(runtime_context, RuntimeContext)
        and runtime_context.valid
        else SmartNextBestActionEngine()
    )
    ranked = ranker.rank(
        actions,
        attempted_fingerprints=attempted,
        new_evidence=bool(state.get("novel_behavior_observations")),
    )[:50]
    payloads = [item.as_dict() for item in ranked]
    ranked_candidates: list[dict[str, Any]] = []
    for item in ranked:
        action = item.action
        try:
            action_payload = {
                key: value
                for key, value in action.as_dict().items()
                if key != "fingerprint"
            }
            candidate = CandidateAction.model_validate(
                {
                    **action_payload,
                    "hypothesis_id": f"research:{action.action_id}",
                    "evidence_potential": min(1.0, action.expected_information_gain),
                    "coverage_value": min(1.0, action.expected_information_gain),
                    "required_capabilities": [action.capability],
                    "policy_tags": ["advisory_research"],
                    "metadata": {
                        **researcher_metadata_for_action(action.action_class),
                        **dict(action.metadata),
                        "ranking_score": item.score,
                        "ranking_reasons": list(item.reasons),
                        "utility_trace": dict(item.utility_trace),
                    },
                }
            )
        except (TypeError, ValueError):
            continue
        ranked_candidates.append(candidate.as_dict())
    return {
        "smart_next_actions": payloads,
        "research_candidate_actions": _bounded_items(ranked_candidates, 100),
        "research_decision_trace": [
            {
                "stage": "next_best_action",
                "status": "completed",
                "ranked_count": len(payloads),
                "attempted_count": len(attempted),
                "advisory_only": True,
            }
        ],
        "research_unified_decision_trace": [
            {
                "stage": "next_best_action",
                "status": "completed",
                "ranked_count": len(payloads),
                "advisory_only": True,
            }
        ],
    }


def research_session_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Persist a bounded report-safe ResearchSession projection."""
    session = ResearchSession.from_state(state)
    gaps = [item for item in (state.get("knowledge_gaps") or []) if isinstance(item, Mapping)]
    session.coverage_gaps = [str(item.get("gap_id"))[:128] for item in gaps if item.get("gap_id")]
    session.next_best_actions = [
        dict(item)
        for item in (state.get("smart_next_actions") or [])[:100]
        if isinstance(item, Mapping)
    ]
    context = ResearchContext.from_state(dict(state))
    session.open_questions = context.unknowns[:100]
    session.updated_at = session.updated_at
    return {
        "research_session": session.as_dict(),
        "research_context": context.as_dict(),
        "research_unified_decision_trace": [
            {
                "stage": "research_session_persistence",
                "status": "completed",
                "coverage_gap_count": len(session.coverage_gaps),
                "next_best_action_count": len(session.next_best_actions),
                "advisory_only": True,
            }
        ],
    }


__all__ = [
    "knowledge_gap_node",
    "next_best_action_node",
    "research_session_node",
]
