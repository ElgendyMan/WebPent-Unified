"""Fail-closed decision loop for proposal-only autonomous research planning.

This module decides what the research system should propose next.  It never
executes a request, mutates target state, creates a finding, or grants
qualification.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from webpent.research.planner import ResearchQueue


class DecisionLoopStatus(StrEnum):
    """Machine-readable outcome of one bounded planning step."""

    CONTINUE = "continue"
    REPLAN = "replan"
    STOP = "stop"
    BLOCKED = "blocked"


class DecisionLoopContext(BaseModel):
    """Recorded state used to make one deterministic proposal-only decision."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    scope_verified: bool = False
    policy_allows_proposal: bool = True
    remaining_budget: int = Field(default=0, ge=0)
    attempted_task_ids: frozenset[str] = frozenset()
    available_evidence: frozenset[str] = frozenset()
    required_evidence: frozenset[str] = frozenset()
    negative_control_complete: bool = False
    replay_verified: bool = False
    max_steps: int = Field(default=1, ge=1, le=100)
    completed_steps: int = Field(default=0, ge=0, le=100)


class DecisionLoopResult(BaseModel):
    """Auditable result of a decision step; execution is permanently disabled."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    status: DecisionLoopStatus
    stage: Literal["plan", "validate", "evidence", "replay", "stop"]
    selected_task_id: str | None = None
    queue_size: int = Field(default=0, ge=0)
    admissible_count: int = Field(default=0, ge=0)
    missing_evidence: tuple[str, ...] = ()
    rationale: tuple[str, ...] = ()
    execution_allowed: bool = False
    mutation_allowed: bool = False
    qualification_effect: bool = False


def decide_next_step(
    queue: ResearchQueue,
    context: DecisionLoopContext,
) -> DecisionLoopResult:
    """Choose one proposal-only step from a planner queue.

    The order of checks is deliberate: governance and scope fail closed before
    any queue selection, and evidence/replay gaps take precedence over proposing
    another validation step.
    """
    if not context.policy_allows_proposal:
        return _blocked(
            queue,
            "policy_does_not_allow_proposal",
            "No planning proposal is admitted without an explicit policy boundary.",
        )
    if not context.scope_verified:
        return _blocked(
            queue,
            "scope_not_verified",
            "Scope must be verified before selecting a research proposal.",
        )

    missing = tuple(sorted(context.required_evidence - context.available_evidence))
    if context.available_evidence and missing:
        return DecisionLoopResult(
            status=DecisionLoopStatus.REPLAN,
            stage="evidence",
            queue_size=len(queue.tasks),
            missing_evidence=missing,
            rationale=(
                "replan_for_missing_evidence",
                "do_not_expand_attack_surface_until_required_evidence_exists",
            ),
        )
    if context.available_evidence and not context.negative_control_complete:
        return DecisionLoopResult(
            status=DecisionLoopStatus.REPLAN,
            stage="evidence",
            queue_size=len(queue.tasks),
            rationale=(
                "independent_negative_control_required",
                "do_not_treat_observation_only_as_confirmation",
            ),
        )
    if context.available_evidence and not context.replay_verified:
        return DecisionLoopResult(
            status=DecisionLoopStatus.REPLAN,
            stage="replay",
            queue_size=len(queue.tasks),
            rationale=(
                "replay_verification_required",
                "do_not_promote_unreplayed_evidence",
            ),
        )
    if context.remaining_budget <= 0:
        return _stopped(
            queue,
            "proposal_budget_exhausted",
            "No further proposal is selected after the bounded budget is exhausted.",
        )
    if context.completed_steps >= context.max_steps:
        return _stopped(
            queue,
            "bounded_step_limit_reached",
            "The bounded loop step limit has been reached.",
        )

    admissible = tuple(
        task
        for task in queue.ordered()
        if task.task_id not in context.attempted_task_ids and task.operation == "validate"
    )
    if not admissible:
        return _stopped(
            queue,
            "no_unattempted_validation_proposal",
            "The queue contains no unattempted validation proposal.",
        )
    selected = admissible[0]
    return DecisionLoopResult(
        status=DecisionLoopStatus.CONTINUE,
        stage="validate",
        selected_task_id=selected.task_id,
        queue_size=len(queue.tasks),
        admissible_count=len(admissible),
        rationale=(
            "selected_highest_utility_unattempted_validation",
            "selection_is_a_proposal_only",
            "execution_remains_disabled",
        ),
    )


def _blocked(
    queue: ResearchQueue,
    reason: str,
    explanation: str,
) -> DecisionLoopResult:
    return DecisionLoopResult(
        status=DecisionLoopStatus.BLOCKED,
        stage="stop",
        queue_size=len(queue.tasks),
        rationale=(reason, explanation),
    )


def _stopped(
    queue: ResearchQueue,
    reason: str,
    explanation: str,
) -> DecisionLoopResult:
    return DecisionLoopResult(
        status=DecisionLoopStatus.STOP,
        stage="stop",
        queue_size=len(queue.tasks),
        rationale=(reason, explanation),
    )


__all__ = [
    "DecisionLoopContext",
    "DecisionLoopResult",
    "DecisionLoopStatus",
    "decide_next_step",
]
