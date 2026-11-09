"""Deterministic review gates for proposals, plans, and finding promotion."""

from __future__ import annotations

from dataclasses import dataclass

from webpent.shared.governed_artifacts import ExperimentPlan, ValidationResult


@dataclass(frozen=True)
class PlanReviewDecision:
    approved: bool
    reasons: tuple[str, ...]
    reviewer: str = "deterministic_plan_reviewer-v1"


class PlanReviewer:
    def review(
        self,
        plan: ExperimentPlan,
        *,
        allowed_scope: bool,
        available_capabilities: tuple[str, ...],
        max_budget: float,
        stop_conditions: tuple[str, ...],
    ) -> PlanReviewDecision:
        reasons: list[str] = []
        if not allowed_scope:
            reasons.append("plan:scope_not_authorized")
        if plan.budget <= 0 or plan.budget > max_budget:
            reasons.append("plan:budget_exceeded_or_invalid")
        if not plan.action_ids:
            reasons.append("plan:actions_required")
        if not plan.proof_path:
            reasons.append("plan:proof_path_required")
        if not stop_conditions:
            reasons.append("plan:stop_conditions_required")
        if plan.mode == "confirmation" and not any(
            marker in {"causal_signal", "negative_control", "proof_bundle", "replay"}
            for marker in plan.proof_path
        ):
            reasons.append("plan:confirmation_requires_proof_path")
        for capability in available_capabilities:
            if not str(capability).strip():
                reasons.append("plan:empty_capability")
        return PlanReviewDecision(approved=not reasons, reasons=tuple(reasons))


@dataclass(frozen=True)
class FindingReviewDecision:
    promotion: str
    reasons: tuple[str, ...]
    reviewer: str = "deterministic_finding_reviewer-v1"

    @property
    def confirmed(self) -> bool:
        return self.promotion == "tool_confirmed"


class FindingReviewer:
    """Apply the non-negotiable evidence contract to a validation result."""

    def review(self, result: ValidationResult) -> FindingReviewDecision:
        reasons: list[str] = []
        if not result.target_backed:
            reasons.append("finding:target_backed_signal_required")
        if not result.causal_link:
            reasons.append("finding:causal_link_required")
        if not result.independent_negative_control:
            reasons.append("finding:independent_negative_control_required")
        if not result.reproducible:
            reasons.append("finding:replayable_reproduction_required")
        if not result.proof_bundle_ref.strip():
            reasons.append("finding:sealed_proof_bundle_required")
        if result.duplicate_similarity >= 0.9:
            reasons.append("finding:duplicate_or_near_duplicate")
        return FindingReviewDecision(
            promotion="tool_confirmed" if not reasons else "candidate_or_needs_human_review",
            reasons=tuple(reasons),
        )


@dataclass(frozen=True)
class ReflectionDecision:
    replan: bool
    reasons: tuple[str, ...]


def reflect_on_outcomes(
    *,
    failures: tuple[str, ...],
    new_unknowns: tuple[str, ...],
    proof_ready: bool,
    stop_requested: bool,
) -> ReflectionDecision:
    reasons: list[str] = []
    if stop_requested:
        reasons.append("stop_requested")
    if failures:
        reasons.append("runtime_failure_requires_bounded_replan")
    if new_unknowns:
        reasons.append("new_unknowns_require_gap_resolution")
    if proof_ready:
        reasons.append("proof_ready_no_confirmation_replan_needed")
    return ReflectionDecision(
        replan=bool((failures or new_unknowns) and not stop_requested and not proof_ready),
        reasons=tuple(reasons),
    )


__all__ = [
    "FindingReviewDecision",
    "FindingReviewer",
    "PlanReviewDecision",
    "PlanReviewer",
    "ReflectionDecision",
    "reflect_on_outcomes",
]
