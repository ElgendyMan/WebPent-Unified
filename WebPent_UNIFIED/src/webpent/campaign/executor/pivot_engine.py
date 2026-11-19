"""U-CAMPAIGN-5 — PivotEngine.

L-6: pivot at boundaries, not at frustration. Triggers are declared
UP FRONT in the phase (the operator approves them as part of the
plan); the engine's job is to evaluate them MECHANICALLY and to make
the follow-on decision honest: proceed, next phase, regenerate, or
abort — with the budget and the findings in view.

The engine never grades findings and never re-orders the plan: it
reads the declared triggers and the phase result and answers one
question — what now?
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any  # P1-09 (0.33.0): Any was used in 3
# annotations without import — latent NameError under get_type_hints().

from webpent.campaign.executor.budget_guard import BudgetSnapshot
from webpent.campaign.schemas import PhaseStatus, PivotAction

if TYPE_CHECKING:  # pragma: no cover
    from webpent.campaign.executor.phase_runner import PhaseResult
    from webpent.campaign.schemas import Phase, PivotTrigger


@dataclass(frozen=True)
class PivotDecision:
    """The engine's answer, with the reason the trace will record."""

    action: PivotAction
    reason: str
    trigger_id: str | None = None


class PivotEngine:
    """Mechanical evaluation of declared triggers + follow-on decisions."""

    def check(self, phase: "Phase",
              hypothesis_results: list[Any]) -> PivotDecision | None:
        """Fire the phase's declared triggers against the results so far.

        Returns the FIRST fired trigger's decision (triggers are
        evaluated in declaration order — deterministic), or None when
        no boundary has been reached.
        """
        streak = self._consecutive_failures(hypothesis_results)
        for trigger in phase.pivot_triggers:
            decision = self._trigger_fired(trigger, streak, hypothesis_results)
            if decision is not None:
                return decision
        return None

    def decide(self, phase: "Phase", result: "PhaseResult",
               remaining_budget: BudgetSnapshot) -> PivotDecision:
        """The follow-on decision when a phase ENDS (any ending).

        Priority order (documented, deterministic):
        1. Success → PROCEED to the next phase.
        2. A pivot decision already recorded on the result → follow it.
        3. Findings despite a non-success ending → PROCEED_CAUTION
           (findings change the calculus; aborting with findings in
           hand wastes them).
        4. No findings:
           - budget remains for another phase → NEXT_PHASE (or
             REGENERATE when the ending was budget exhaustion — new
             ammunition may succeed where the old was refuted);
           - no budget → ABORT.
        """
        if result.status == PhaseStatus.SUCCESS:
            return PivotDecision(
                action=PivotAction.PROCEED,
                reason="Phase confirmed its success indicator — proceed "
                       "to the next phase")
        if (result.status == PhaseStatus.PIVOTED
                and result.pivot_decision is not None):
            return result.pivot_decision
        if result.findings:
            return PivotDecision(
                action=PivotAction.PROCEED_CAUTION,
                reason="Findings present despite a non-success ending — "
                       "proceed with caution; do not waste them")
        if remaining_budget.has_room_for_more_phases():
            if result.status == PhaseStatus.EXHAUSTED:
                return PivotDecision(
                    action=PivotAction.REGENERATE,
                    reason="Budget exhausted without findings, but the "
                           "campaign has room for another phase — "
                           "regenerate hypotheses (L-6: new ammunition, "
                           "not more grinding)")
            return PivotDecision(
                action=PivotAction.NEXT_PHASE,
                reason="Phase failed without findings; budget remains — "
                       "move to the next phase")
        return PivotDecision(
            action=PivotAction.ABORT,
            reason="No budget remaining for another viable phase — abort "
                   "honestly rather than spend past the law (L-3)")

    # ------------------------------------------------------------------

    @staticmethod
    def _consecutive_failures(hypothesis_results: list[Any]) -> int:
        """The trailing streak of failed hypotheses (success resets)."""
        streak = 0
        for result in reversed(hypothesis_results):
            if result.success:
                break
            streak += 1
        return streak

    def _trigger_fired(self, trigger, streak: int,
                       hypothesis_results: list[Any]
                       ) -> PivotDecision | None:
        if trigger.condition_type == "consecutive_failures":
            if streak >= trigger.threshold:
                return PivotDecision(
                    action=trigger.action,
                    reason=trigger.reason,
                    trigger_id=trigger.trigger_id,
                )
            return None
        # Unknown condition types are ignored, never guessed at: an
        # unimplemented trigger silently passing is a bug; refusing to
        # invent semantics for it is the honest behavior. The planner
        # only emits known types.
        return None
