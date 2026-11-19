"""Bounded campaign orchestration over existing planning and proof contracts.

This module is a projection/planning layer only.  It never authorizes a task,
executes transport, or promotes a finding.  Path decisions are derived from
explicit scoped outcomes; a candidate, hypothesis, or attempted task is not a
causal signal.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from webpent.models.evidence import redact_sensitive

_MAX_PATHS = 64
_MAX_OUTCOMES_PER_PATH = 16
_MAX_ATTEMPTS_FOR_STOP = 2
_MIN_DEEPEN_MULTIPLIER = 1.1
_MAX_DEEPEN_MULTIPLIER = 1.5


def _text(value: Any, limit: int = 160) -> str:
    clean, _ = redact_sensitive(str(value or ""))
    return clean.strip()[:limit]


def _bounded_bool(value: Any) -> bool:
    return value is True


def _task_value(task: Any, key: str, default: Any = None) -> Any:
    if isinstance(task, Mapping):
        return task.get(key, default)
    return getattr(task, key, default)


def _path_key(task: Any) -> str:
    return _text(
        _task_value(task, "campaign_key")
        or _task_value(task, "campaign_id")
        or _task_value(task, "vulnerability_class")
        or _task_value(task, "task_id")
    ).lower()


def _outcome_is_scoped(outcome: Mapping[str, Any], engagement_id: str) -> bool:
    raw_engagement = _text(outcome.get("engagement_id"))
    return not raw_engagement or raw_engagement == engagement_id


def _has_causal_signal(outcome: Mapping[str, Any]) -> bool:
    """Accept only an explicit target-backed causal signal with controls."""
    if not _bounded_bool(outcome.get("causal_signal")):
        return False
    negative_control = outcome.get("negative_control")
    if not isinstance(negative_control, Mapping):
        return False
    if not _bounded_bool(negative_control.get("passed")):
        return False
    proof = outcome.get("proof_bundle")
    if not isinstance(proof, Mapping):
        return False
    return _bounded_bool(proof.get("sealed")) and _bounded_bool(proof.get("replayable"))


def _attempted(outcome: Mapping[str, Any]) -> bool:
    status = _text(outcome.get("status")).lower()
    return bool(
        _text(outcome.get("attempt_id"))
        or status
        in {
            "candidate",
            "confirmed",
            "tool_confirmed",
            "clean",
            "negative",
            "inconclusive",
            "executed",
            "blocked_by_precondition",
            "infrastructure_failure",
        }
    )


class CampaignManager:
    """Allocate bounded campaign attention from explicit proof-aware outcomes."""

    def __init__(
        self,
        *,
        max_paths: int = _MAX_PATHS,
        max_outcomes_per_path: int = _MAX_OUTCOMES_PER_PATH,
        stop_after_attempts: int = _MAX_ATTEMPTS_FOR_STOP,
    ) -> None:
        self.max_paths = max(1, min(_MAX_PATHS, int(max_paths)))
        self.max_outcomes_per_path = max(1, min(_MAX_OUTCOMES_PER_PATH, int(max_outcomes_per_path)))
        self.stop_after_attempts = max(1, min(10, int(stop_after_attempts)))

    def plan(self, tasks: Iterable[Any], state: Mapping[str, Any]) -> dict[str, Any]:
        """Return report-safe path decisions; never returns an executable action."""
        engagement_id = _text(state.get("engagement_id"))
        if not engagement_id:
            return {
                "status": "blocked",
                "reason": "missing_engagement_scope",
                "engagement_id": None,
                "decisions": {},
                "execution_required": False,
            }

        task_paths: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        task_count = 0
        for task in tasks:
            if task_count >= self.max_paths:
                break
            path = _path_key(task)
            if not path or path in task_paths:
                continue
            task_paths[path] = []
            task_count += 1

        raw_outcomes = state.get("campaign_task_outcomes") or []
        raw_outcomes = list(raw_outcomes) if isinstance(raw_outcomes, Iterable) else []
        outcomes_by_path: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for raw in raw_outcomes:
            if not isinstance(raw, Mapping) or not _outcome_is_scoped(raw, engagement_id):
                continue
            path = _text(
                raw.get("campaign_key")
                or raw.get("campaign_id")
                or raw.get("vulnerability_class")
            ).lower()
            if path in task_paths and len(outcomes_by_path[path]) < self.max_outcomes_per_path:
                outcomes_by_path[path].append(raw)

        decisions: dict[str, dict[str, Any]] = {}
        for path in task_paths:
            outcomes = outcomes_by_path.get(path, [])
            attempts = sum(1 for outcome in outcomes if _attempted(outcome))
            causal_signal = any(_has_causal_signal(outcome) for outcome in outcomes)
            proof_confirmed = any(
                _has_causal_signal(outcome)
                and _text(outcome.get("status")).lower() in {"confirmed", "tool_confirmed"}
                for outcome in outcomes
            )
            evidence_complete = any(
                _bounded_bool(outcome.get("evidence_complete")) for outcome in outcomes
            )
            if causal_signal:
                action = "deepen"
                reason = "causal_signal_with_replayable_proof"
                multiplier = _MAX_DEEPEN_MULTIPLIER if proof_confirmed else _MIN_DEEPEN_MULTIPLIER
            elif attempts >= self.stop_after_attempts:
                action = "stop"
                reason = "diminishing_returns"
                multiplier = 0.0
            else:
                action = "continue"
                reason = "insufficient_signal"
                multiplier = 1.0
            decisions[path] = {
                "action": action,
                "reason": reason,
                "attempts": min(attempts, 1000),
                "causal_signal": causal_signal,
                "proof_confirmed": proof_confirmed,
                "evidence_complete": evidence_complete,
                "budget_multiplier": multiplier,
            }

        remaining = state.get("action_budget", {})
        remaining_cost = 0.0
        if isinstance(remaining, Mapping):
            try:
                remaining_cost = max(
                    0.0,
                    min(1_000_000.0, float(remaining.get("remaining_cost", 0.0) or 0.0)),
                )
            except (TypeError, ValueError):
                remaining_cost = 0.0
        return {
            "status": "planned",
            "reason": "proof_aware_path_allocation",
            "engagement_id": engagement_id,
            "decisions": decisions,
            "remaining_cost": remaining_cost,
            "execution_required": True,
            "authority": "campaign_executor_action_authority",
        }
