"""Bounded adaptive scheduling and targeted revisit planning.

This module deliberately emits *tasks*, not HTTP requests.  An existing
executor/validator remains the only component allowed to perform actions, so
HITL, scope enforcement, evidence capture, and reporting contracts are
preserved.  The scheduler is deterministic and safe to run repeatedly after a
checkpoint restore.
"""

# Existing scheduler messages are intentionally kept verbatim for report compatibility.
# ruff: noqa: E501

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from webpent.models.adaptive_hunt import (
    AdaptiveLeadScore,
    BranchBudget,
    BranchRisk,
    RevisitOutcome,
    RevisitStatus,
    RevisitSurface,
    RevisitTask,
)
from webpent.models.findings import EXPLOITABLE_CLASSES
from webpent.shared.cognitive_components import estimate_action_cost
from webpent.shared.proof_engine import build_proof_engine_update

logger = logging.getLogger(__name__)

_MAX_TASKS_PER_PASS = 10
_MAX_REVISIT_DEPTH = 3

_TERMINAL_STATUSES = frozenset({
    RevisitStatus.CONFIRMED.value,
    RevisitStatus.DEAD_END.value,
    RevisitStatus.BLOCKED_BY_SCOPE.value,
    RevisitStatus.NEEDS_APPROVAL.value,
    RevisitStatus.DIMINISHING_RETURNS.value,
    RevisitStatus.BUDGET_EXHAUSTED.value,
    RevisitStatus.SKIPPED.value,
})

# Cost, impact, evidence, and novelty remain explicit constants so a report
# can explain why a task outranked another task without an LLM decision.
_SCORE_WEIGHTS = {
    "impact": 0.22,
    "evidence": 0.20,
    "exploitability": 0.16,
    "chain": 0.16,
    "information_gain": 0.12,
    "novelty": 0.14,
}
_PENALTY_WEIGHTS = {
    "repetition": 0.12,
    "cost": 0.10,
    "weak_evidence": 0.08,
}


def _get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _enum_value(value: Any) -> str:
    raw = getattr(value, "value", value)
    return raw.strip() if isinstance(raw, str) else str(raw)


def _normalise_url(url: str) -> str:
    """Canonicalize a URL for task identity while retaining its query."""
    raw = _text(url)
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
        if not parts.scheme or not parts.netloc:
            return raw.rstrip("/")
        host = (parts.hostname or "").lower()
        netloc = host
        if parts.port:
            default = (parts.scheme.lower() == "http" and parts.port == 80) or (
                parts.scheme.lower() == "https" and parts.port == 443
            )
            if not default:
                netloc = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme.lower(), netloc, parts.path.rstrip("/"), parts.query, ""))
    except Exception:
        return raw.rstrip("/")


def _stable_key(*parts: Any) -> str:
    canonical = "|".join(_text(p).lower() for p in parts if _text(p))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def _investigation_stage(depth: int) -> str:
    """Map bounded investigation depth to the roadmap's named stages."""
    stages = ("discovery", "validation", "exploitation_reasoning", "business_impact")
    return stages[min(max(0, int(depth)), len(stages) - 1)]


def _safe_context_value(value: Any) -> str | None:
    """Keep labels useful while avoiding credential/token material in state."""
    text = _text(value)
    if not text:
        return None
    lowered = text.lower()
    sensitive_markers = ("token", "secret", "password", "cookie", "authorization", "bearer")
    if any(marker in lowered for marker in sensitive_markers):
        return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]}"
    return text[:200]


def _evidence_dict(finding: Any) -> dict[str, Any]:
    evidence = _get(finding, "evidence")
    return evidence if isinstance(evidence, dict) else {}


def _finding_context(finding: Any) -> dict[str, Any]:
    evidence = _evidence_dict(finding)
    return {
        "id": _text(_get(finding, "id")),
        "url": _text(_get(finding, "url")),
        "severity": _text(_get(finding, "severity")),
        "vuln_class": _text(_get(finding, "vuln_class")),
        "confidence_level": _text(_get(finding, "confidence_level")),
        "confidence": _confidence_number(_get(finding, "confidence", 0.0)),
        "evidence": evidence,
        "evidence_refs": list(_get(finding, "evidence_refs", []) or []),
    }


def _confidence_number(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value or 0.0)))
    except (TypeError, ValueError):
        return 1.0 if _enum_value(value).lower() in {"confirmed", "tool-confirmed"} else 0.0


def _first_context_value(context: dict[str, Any], *keys: str) -> str | None:
    evidence = context.get("evidence") or {}
    for key in keys:
        value = _safe_context_value(evidence.get(key))
        if value:
            return value
    return None


def _budget_for(task_type: str) -> BranchBudget:
    specs: dict[str, dict[str, Any]] = {
        "endpoint_revalidation": {"requests": 3, "time": 60, "risk": BranchRisk.LOW.value},
        "auth_pattern_revisit": {"requests": 8, "time": 120, "risk": BranchRisk.MEDIUM.value},
        "object_family_revisit": {"requests": 8, "time": 120, "risk": BranchRisk.MEDIUM.value},
        "workflow_transition_revisit": {
            "requests": 10,
            "time": 180,
            "risk": BranchRisk.MEDIUM.value,
        },
        "js_route_revisit": {"requests": 4, "time": 90, "risk": BranchRisk.LOW.value},
        "relation_revalidation": {"requests": 6, "time": 120, "risk": BranchRisk.MEDIUM.value},
    }
    spec = specs.get(task_type, {"requests": 3, "time": 60, "risk": BranchRisk.LOW.value})
    return BranchBudget(
        max_attempts=1,
        max_requests=int(spec["requests"]),
        max_time_seconds=int(spec["time"]),
        max_concurrency=1,
        max_llm_units=0.0,
        risk_level=spec["risk"],
    )


def _candidate(
    *,
    context: dict[str, Any],
    surface: RevisitSurface,
    surface_key: str,
    task_type: str,
    reason: str,
    depth: int = 0,
    parent_task_id: str | None = None,
    relation_id: str | None = None,
    auth_pattern: str | None = None,
    object_family: str | None = None,
    workflow_id: str | None = None,
    role: str | None = None,
    js_route: str | None = None,
    signal_kind: str | None = None,
) -> RevisitTask | None:
    url = _normalise_url(context.get("url", ""))
    finding_id = context.get("id") or None
    if not url or not finding_id:
        return None
    refs = [str(finding_id)]
    refs.extend(str(ref) for ref in context.get("evidence_refs", []) if ref)
    return RevisitTask(
        parent_task_id=parent_task_id,
        source_finding_id=str(finding_id),
        source_relation_id=relation_id,
        target_url=url,
        surface=surface.value,
        surface_key=surface_key,
        task_type=task_type,
        reason=reason,
        evidence_refs=list(dict.fromkeys(refs)),
        auth_pattern=auth_pattern,
        object_family=object_family,
        workflow_id=workflow_id,
        role=role,
        js_route=js_route,
        signal_kind=signal_kind,
        investigation_stage=_investigation_stage(depth),
        depth=depth,
        budget=_budget_for(task_type),
    )


def build_targeted_revisit_tasks(
    *,
    findings: Iterable[Any] | None = None,
    relational_evidence: Iterable[Any] | None = None,
    workflow_observations: Iterable[Any] | None = None,
    interesting_signals: Iterable[Any] | None = None,
    existing_tasks: Any = None,
    max_depth: int = _MAX_REVISIT_DEPTH,
) -> list[RevisitTask]:
    """Create only related-surface tasks from new findings/relations.

    The function never schedules a full recon.  It requires a finding URL and
    uses explicit evidence keys for auth, object, workflow, role, and JS-route
    relationships.  Unknown or malformed records are ignored fail-closed.
    """
    contexts = [_finding_context(f) for f in (findings or [])]
    by_id = {c["id"]: c for c in contexts if c["id"]}
    prior_keys: set[str] = set()
    if isinstance(existing_tasks, dict):
        values = existing_tasks.values()
    elif isinstance(existing_tasks, list):
        values = existing_tasks
    else:
        values = []
    for raw in values:
        task_key = _text(_get(raw, "surface_key"))
        if task_key:
            prior_keys.add(task_key)

    candidates: list[RevisitTask] = []
    seen: set[str] = set(prior_keys)

    def add(task: RevisitTask | None) -> None:
        if task is None or task.depth > max_depth or task.surface_key in seen:
            return
        seen.add(task.surface_key)
        candidates.append(task)

    for context in contexts:
        url = _normalise_url(context["url"])
        if not url:
            continue
        # Every finding gets one bounded same-endpoint revalidation task. This
        # catches not-scanned follow-ups without reopening the whole target.
        add(_candidate(
            context=context,
            surface=RevisitSurface.ENDPOINT,
            surface_key=_stable_key("endpoint", url),
            task_type="endpoint_revalidation",
            reason="New finding evidence warrants a bounded revalidation of the same endpoint.",
        ))

        auth = _first_context_value(context, "auth_pattern", "auth_context", "identity_pattern")
        if auth:
            add(_candidate(
                context=context,
                surface=RevisitSurface.AUTH_PATTERN,
                surface_key=_stable_key("auth", url, auth),
                task_type="auth_pattern_revisit",
                reason=(
                    "The finding carries an explicit authentication context; compare the same "
                    "pattern on the related surface."
                ),
                auth_pattern=auth,
            ))

        obj = _first_context_value(context, "object_family", "object_type", "object_class")
        if obj:
            add(_candidate(
                context=context,
                surface=RevisitSurface.OBJECT_FAMILY,
                surface_key=_stable_key("object", url, obj),
                task_type="object_family_revisit",
                reason="The finding identifies an object family; test sibling references through the existing authorization path.",
                object_family=obj,
            ))

        workflow = _first_context_value(context, "workflow_id", "workflow", "flow_id")
        if workflow:
            add(_candidate(
                context=context,
                surface=RevisitSurface.WORKFLOW,
                surface_key=_stable_key("workflow", url, workflow),
                task_type="workflow_transition_revisit",
                reason="The finding is tied to an explicit workflow; revisit adjacent transitions only.",
                workflow_id=workflow,
            ))

        role = _first_context_value(context, "role", "identity_role", "actor_role")
        if role and auth:
            add(_candidate(
                context=context,
                surface=RevisitSurface.ROLE,
                surface_key=_stable_key("role", url, auth, role),
                task_type="auth_pattern_revisit",
                reason="A role-specific authentication context was observed; revisit the same authorization boundary.",
                auth_pattern=auth,
                role=role,
            ))

        js_route = _first_context_value(context, "js_route", "frontend_route", "source_route")
        if js_route:
            add(_candidate(
                context=context,
                surface=RevisitSurface.JS_ROUTE,
                surface_key=_stable_key("js", url, js_route),
                task_type="js_route_revisit",
                reason="The finding references a JavaScript route; review and revalidate that route only.",
                js_route=js_route,
            ))

    # Interesting signals are explicit, target-backed prompts for deeper
    # investigation. Unknown signal/surface values are ignored fail-closed;
    # this never becomes a target-wide crawl or an execution instruction.
    signal_specs = {
        "endpoint": (RevisitSurface.ENDPOINT, "endpoint_revalidation"),
        "auth_pattern": (RevisitSurface.AUTH_PATTERN, "auth_pattern_revisit"),
        "object_family": (RevisitSurface.OBJECT_FAMILY, "object_family_revisit"),
        "workflow": (RevisitSurface.WORKFLOW, "workflow_transition_revisit"),
        "role": (RevisitSurface.ROLE, "auth_pattern_revisit"),
        "js_route": (RevisitSurface.JS_ROUTE, "js_route_revisit"),
        "relation": (RevisitSurface.RELATION, "relation_revalidation"),
    }
    for signal in interesting_signals or []:
        signal_id = _text(_get(signal, "id"))
        signal_kind = _safe_context_value(
            _get(signal, "signal_type") or _get(signal, "kind")
        )
        next_surface = _text(_get(signal, "next_surface"))
        spec = signal_specs.get(next_surface)
        if not signal_id or not signal_kind or spec is None:
            continue
        source_id = _text(_get(signal, "finding_id"))
        context = by_id.get(source_id)
        if context is None:
            continue
        target_url = _text(_get(signal, "target_url")) or context["url"]
        try:
            signal_depth = max(0, int(_get(signal, "depth", 0)))
        except (TypeError, ValueError):
            signal_depth = 0
        if signal_depth > max_depth:
            continue
        signal_refs = [
            str(ref) for ref in (_get(signal, "evidence_refs") or []) if ref
        ]
        signal_context = {
            **context,
            "url": target_url,
            "evidence_refs": list(dict.fromkeys([
                *context.get("evidence_refs", []),
                *signal_refs,
            ])),
        }
        surface, task_type = spec
        add(_candidate(
            context=signal_context,
            surface=surface,
            surface_key=_stable_key(
                "signal", signal_id, signal_kind, next_surface,
                _normalise_url(target_url),
            ),
            task_type=task_type,
            reason=(
                f"Explicit signal {signal_kind} warrants a bounded "
                f"{next_surface} investigation."
            ),
            depth=signal_depth,
            signal_kind=signal_kind,
        ))

    # Relations and workflow observations are explicit sources of additional
    # tasks; they do not cause a target-wide crawl.
    for relation in relational_evidence or []:
        relation_id = _text(_get(relation, "id")) or _stable_key(
            _get(relation, "source_id"), _get(relation, "target_id"), _get(relation, "relation_type")
        )
        source_id = _text(_get(relation, "source_finding_id")) or _text(_get(relation, "finding_id"))
        context = by_id.get(source_id)
        if context is None and contexts:
            context = contexts[0]
        if context is None:
            continue
        relation_type = _safe_context_value(_get(relation, "relation_type")) or "related"
        target_url = _text(_get(relation, "target_url"))
        if target_url:
            context = {**context, "url": target_url}
        add(_candidate(
            context=context,
            surface=RevisitSurface.RELATION,
            surface_key=_stable_key("relation", relation_id, relation_type, _normalise_url(context["url"])),
            task_type="relation_revalidation",
            reason=f"Relational evidence {relation_type} links a new surface to an existing finding.",
            relation_id=relation_id,
        ))

    for observation in workflow_observations or []:
        context = by_id.get(_text(_get(observation, "finding_id")))
        if context is None:
            endpoint = _text(_get(observation, "target_url")) or _text(_get(observation, "endpoint"))
            if endpoint and contexts:
                context = {**contexts[0], "url": endpoint}
        if context is None:
            continue
        workflow_id = _safe_context_value(_get(observation, "workflow_id")) or _safe_context_value(_get(observation, "workflow"))
        if not workflow_id:
            continue
        add(_candidate(
            context=context,
            surface=RevisitSurface.WORKFLOW,
            surface_key=_stable_key("workflow-observation", workflow_id, context["url"]),
            task_type="workflow_transition_revisit",
            reason="A workflow observation exposes an adjacent transition for targeted revisit.",
            workflow_id=workflow_id,
        ))

    return candidates


def _severity_score(context: dict[str, Any]) -> float:
    rank = {"info": 0.0, "low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
    severity = context.get("severity", "").lower()
    return rank.get(severity, 0.5 if context.get("vuln_class") else 0.25)


def _evidence_score(context: dict[str, Any]) -> float:
    level = context.get("confidence_level", "").lower()
    score = {"tool-confirmed": 1.0, "ai-assessed": 0.65, "needs human review": 0.4, "pending": 0.25}.get(level, 0.25)
    evidence = context.get("evidence") or {}
    if evidence:
        score += 0.15
    if context.get("evidence_refs"):
        score += 0.10
    return min(1.0, score)


def score_revisit_task(
    task: RevisitTask,
    *,
    finding: Any = None,
    prior_surface_counts: dict[str, int] | None = None,
) -> RevisitTask:
    """Score one task with deterministic impact/evidence/chain/information terms."""
    context = _finding_context(finding) if finding is not None else {}
    impact = _severity_score(context)
    evidence = _evidence_score(context)
    vuln_class = context.get("vuln_class", "")
    exploitability = 1.0 if vuln_class in EXPLOITABLE_CLASSES else 0.35
    surface_name = _enum_value(task.surface)
    chain = 0.85 if surface_name in {
        RevisitSurface.AUTH_PATTERN.value,
        RevisitSurface.OBJECT_FAMILY.value,
        RevisitSurface.WORKFLOW.value,
        RevisitSurface.ROLE.value,
        RevisitSurface.RELATION.value,
    } else 0.35
    counts = prior_surface_counts or {}
    repetition_count = max(0, int(counts.get(task.surface_key, 0)))
    repetition = min(1.0, repetition_count / 3.0)
    information_gain = 1.0 if repetition_count == 0 else max(0.15, 1.0 - repetition)
    novelty = max(0.0, 1.0 - repetition)
    cost = min(1.0, estimate_action_cost(task.task_type) / 10.0)
    weak_evidence = 1.0 - evidence
    weighted = (
        _SCORE_WEIGHTS["impact"] * impact
        + _SCORE_WEIGHTS["evidence"] * evidence
        + _SCORE_WEIGHTS["exploitability"] * exploitability
        + _SCORE_WEIGHTS["chain"] * chain
        + _SCORE_WEIGHTS["information_gain"] * information_gain
        + _SCORE_WEIGHTS["novelty"] * novelty
        - _PENALTY_WEIGHTS["repetition"] * repetition
        - _PENALTY_WEIGHTS["cost"] * cost
        - _PENALTY_WEIGHTS["weak_evidence"] * weak_evidence
    )
    score = max(0.0, min(1.0, weighted))
    rule = (
        f"impact={impact:.2f}; evidence={evidence:.2f}; exploitability={exploitability:.2f}; "
        f"chain={chain:.2f}; information_gain={information_gain:.2f}; novelty={novelty:.2f}; "
        f"penalties(repetition={repetition:.2f}, cost={cost:.2f}, weak_evidence={weak_evidence:.2f})"
    )
    scored = AdaptiveLeadScore(
        impact_potential=impact,
        evidence_strength=evidence,
        exploitability=exploitability,
        chain_potential=chain,
        information_gain=information_gain,
        novelty=novelty,
        repetition_penalty=repetition,
        cost_penalty=cost,
        weak_evidence_penalty=weak_evidence,
        score=score,
        rule=rule,
    )
    return task.model_copy(update={"score": scored})


def prioritize_revisit_tasks(
    tasks: Iterable[RevisitTask],
    *,
    findings: Iterable[Any] | None = None,
    existing_tasks: Any = None,
    max_tasks: int = _MAX_TASKS_PER_PASS,
    max_depth: int = _MAX_REVISIT_DEPTH,
) -> list[RevisitTask]:
    """Return bounded, deterministic ordering of open tasks."""
    contexts = {_text(_get(f, "id")): f for f in (findings or [])}
    counts: dict[str, int] = {}
    if isinstance(existing_tasks, dict):
        values = existing_tasks.values()
    elif isinstance(existing_tasks, list):
        values = existing_tasks
    else:
        values = []
    for raw in values:
        key = _text(_get(raw, "surface_key"))
        if key:
            counts[key] = counts.get(key, 0) + 1

    scored: list[RevisitTask] = []
    seen: set[str] = set()
    for task in tasks:
        if not isinstance(task, RevisitTask):
            try:
                task = RevisitTask.model_validate(task)
            except Exception:
                continue
        if task.depth > max_depth or _enum_value(task.status) in _TERMINAL_STATUSES:
            continue
        if task.surface_key in seen:
            continue
        seen.add(task.surface_key)
        scored.append(score_revisit_task(task, finding=contexts.get(task.source_finding_id), prior_surface_counts=counts))
    scored.sort(key=lambda task: (-task.score.score, task.depth, task.created_at.isoformat(), task.id))
    return scored[: max(0, int(max_tasks))]


def apply_revisit_outcome(task: RevisitTask, outcome: RevisitOutcome) -> RevisitTask:
    """Apply an executor result and close the branch deterministically."""
    if outcome.task_id != task.id:
        raise ValueError("outcome.task_id does not match task.id")
    budget = task.budget.model_copy(update={
        "attempts_used": task.budget.attempts_used + 1,
        "requests_used": task.budget.requests_used + outcome.requests_used,
        "time_seconds_used": task.budget.time_seconds_used + outcome.time_seconds_used,
        "llm_units_used": task.budget.llm_units_used + outcome.llm_units_used,
    })
    status = _enum_value(outcome.status)
    if (
        outcome.new_signal is False
        and task.depth >= 1
        and status not in {
            RevisitStatus.CONFIRMED.value,
            RevisitStatus.NEEDS_APPROVAL.value,
        }
    ):
        status = RevisitStatus.DIMINISHING_RETURNS.value
    if status not in _TERMINAL_STATUSES and budget.exhausted:
        status = RevisitStatus.BUDGET_EXHAUSTED.value
    return task.model_copy(update={
        "status": status,
        "budget": budget,
        "evidence_refs": list(dict.fromkeys([*task.evidence_refs, *outcome.evidence_refs])),
        "investigation_stage": _investigation_stage(task.depth),
        "outcome_note": outcome.note[:500],
        "updated_at": datetime.now(timezone.utc),
    })


def adaptive_hunt_enabled() -> bool:
    """Read the additive feature flag fail-closed."""
    try:
        from webpent.config.settings import get_settings
        return bool(get_settings().enable_adaptive_hunt)
    except Exception:
        return False


def build_adaptive_hunt_update(state: Any) -> dict[str, Any]:
    """Build a state update; returns an empty update when flag is disabled."""
    if not adaptive_hunt_enabled():
        return {}
    policy_depth = _MAX_REVISIT_DEPTH
    try:
        from webpent.config.policies import RabbitHolePolicy
        policy = RabbitHolePolicy()
        policy_depth = min(_MAX_REVISIT_DEPTH, int(getattr(policy, "max_revisit_depth", policy_depth)))
        max_tasks = min(_MAX_TASKS_PER_PASS, int(getattr(policy, "max_revisit_tasks", _MAX_TASKS_PER_PASS)))
    except Exception:
        max_tasks = _MAX_TASKS_PER_PASS

    findings = state.get("findings") or []
    existing = state.get("adaptive_revisit_tasks") or {}
    tasks = build_targeted_revisit_tasks(
        findings=findings,
        relational_evidence=state.get("relational_evidence") or [],
        workflow_observations=state.get("workflow_observations") or [],
        interesting_signals=state.get("interesting_signals") or [],
        existing_tasks=existing,
        max_depth=policy_depth,
    )
    selected = prioritize_revisit_tasks(
        tasks,
        findings=findings,
        existing_tasks=existing,
        max_tasks=max_tasks,
        max_depth=policy_depth,
    )
    proof_update = build_proof_engine_update(state)
    if not selected:
        return {
            "adaptive_hunt": {
                "last_pass": "no_targeted_revisits",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
            **proof_update,
        }

    task_updates = {task.id: task.model_dump(mode="json") for task in selected}
    ledger_updates = {
        task.surface_key: {
            "task_id": task.id,
            "status": _enum_value(task.status),
            "score": task.score.score,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        for task in selected
    }
    now = datetime.now(timezone.utc).isoformat()
    decision_log = [{
        "id": str(uuid4()),
        "timestamp": now,
        "decision_type": "adaptive_revisit_scheduled",
        "rule_fired": task.score.rule,
        "outcome": "scheduled",
        "llm_contribution": "",
        "entity_refs": [task.id, *task.evidence_refs],
        "branch_id": task.parent_task_id,
        "metadata": {
            "surface": _enum_value(task.surface),
            "surface_key": task.surface_key,
            "depth": task.depth,
            "investigation_stage": task.investigation_stage,
            "signal_kind": task.signal_kind,
            "budget": task.budget.model_dump(mode="json"),
        },
    } for task in selected]
    return {
        "adaptive_revisit_tasks": task_updates,
        "adaptive_revisit_ledger": ledger_updates,
        "adaptive_hunt": {
            "last_pass": "scheduled",
            "selected_count": len(selected),
            "updated_at": now,
        },
        "decision_log": decision_log,
        **proof_update,
    }


__all__ = [
    "adaptive_hunt_enabled",
    "apply_revisit_outcome",
    "build_adaptive_hunt_update",
    "build_targeted_revisit_tasks",
    "prioritize_revisit_tasks",
    "score_revisit_task",
]
