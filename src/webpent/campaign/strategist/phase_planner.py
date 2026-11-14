"""U-CAMPAIGN-2 — PhasePlanner.

Turns the thesis into a bounded plan: 2..5 phases, family phases
ranked by derivation score (ROI order), a closing chain phase that
turns confirmed findings into a demonstrable business-impact story.

Phases, not hypotheses (CAMPAIGN principle 2): the plan fixes the
SHAPES of exploration — the hypotheses inside each phase are
disposable ammunition, regenerated when a pivot trigger fires.

Budget discipline (L-3): the chain phase reserves CHAIN_PHASE_RATIO of
the campaign budget; family phases share the remainder proportional to
their scores. Phase budgets can never sum past the campaign caps —
_validate_phases refuses any plan that tries.

Determinism (L-9): phase ids, order, goals and budgets are pure
functions of the thesis and the campaign budget — two plans from the
same inputs are identical.
"""
from __future__ import annotations

from webpent.campaign.errors import CampaignError
from webpent.campaign.schemas import (
    CampaignBudget,
    Family,
    Hypothesis,
    Phase,
    PhaseBudget,
    PivotAction,
    PivotTrigger,
    TargetThesis,
)
from webpent.campaign.strategist.phase_templates import (
    TYPICAL_HYPOTHESIS_COUNT,
    patterns_for,
)
from webpent.campaign.strategist.validators import validate_phases

MAX_PHASES = 5
MIN_PHASES = 2
CHAIN_PHASE_RATIO = 0.15


class PhasePlanningError(CampaignError):
    """The plan the builder produced is not runnable — refuse, don't ship."""


class PhasePlanner:
    """Plans phases from a thesis (L-1 → plan, L-3 → budgets, L-6 → triggers)."""

    def plan(self, thesis: TargetThesis,
             total_budget: CampaignBudget) -> list[Phase]:
        ranked = thesis.likely_vuln_families
        if not ranked:
            raise PhasePlanningError(
                "thesis carries no likely families — nothing to plan (L-1)")

        # Leave room for the chain phase; cap at MAX_PHASES total.
        selected = ranked[: MAX_PHASES - 1]
        pool_ratio = 1.0 - CHAIN_PHASE_RATIO
        pool_requests = total_budget.max_requests * pool_ratio
        pool_time = total_budget.max_time_minutes * pool_ratio
        pool_llm = total_budget.max_llm_calls * pool_ratio
        weight_sum = sum(p for _, p in selected) or 1.0

        phases: list[Phase] = []
        order = 1
        for family, score in selected:
            share = score / weight_sum
            phase = self._build_family_phase(
                thesis, family, order,
                max_requests=max(1, int(pool_requests * share)),
                max_time_minutes=max(5, int(pool_time * share)),
                max_llm_calls=max(3, int(pool_llm * share)),
            )
            phases.append(phase)
            order += 1

        phases.append(self._build_chain_phase(
            order,
            max_requests=max(1, int(total_budget.max_requests
                                   * CHAIN_PHASE_RATIO)),
            max_time_minutes=max(5, int(total_budget.max_time_minutes
                                        * CHAIN_PHASE_RATIO)),
            max_llm_calls=max(3, int(total_budget.max_llm_calls
                                     * CHAIN_PHASE_RATIO)),
        ))

        errors = validate_phases(phases, total_budget)
        if errors:
            raise PhasePlanningError("; ".join(errors))
        return phases

    # ------------------------------------------------------------------
    # Phase construction (deterministic)
    # ------------------------------------------------------------------

    def _build_family_phase(self, thesis: TargetThesis, family: Family,
                            order: int, *, max_requests: int,
                            max_time_minutes: int,
                            max_llm_calls: int) -> Phase:
        phase_id = f"phase-{order:02d}-{family.value}"
        hypotheses = self._build_hypotheses(family, order)
        threshold = TYPICAL_HYPOTHESIS_COUNT
        trigger = PivotTrigger(
            trigger_id=f"pivot-{phase_id}-consecutive-failures",
            condition=f"{threshold} consecutive hypothesis failures",
            condition_type="consecutive_failures",
            threshold=threshold,
            action=PivotAction.NEXT_PHASE,
            reason=(f"Family {family.value} refuted beyond its declared "
                    "tolerance — pivot to the next phase instead of "
                    "grinding (L-6)"),
        )
        return Phase(
            phase_id=phase_id,
            order=order,
            goal=f"Confirm or refute {family.value} across the thesis's "
                 "likely entry points",
            thesis_alignment=(f"Tests {family.value} — derived from the "
                              f"thesis (v{thesis.version}) with "
                              f"confidence {thesis.confidence:.2f}"),
            hypotheses=hypotheses,
            budget=PhaseBudget(
                max_requests=max_requests,
                max_time_minutes=max_time_minutes,
                max_llm_calls=max_llm_calls,
            ),
            exit_criteria=[
                "At least one confirmed finding in this family",
                f"Or {threshold} consecutive hypothesis failures (pivot)",
            ],
            success_indicators=[f"A confirmed {family.value} finding"],
            failure_indicators=["All hypotheses refuted within budget"],
            pivot_triggers=[trigger],
            target_id=thesis.target_id,
        )

    def _build_hypotheses(self, family: Family, order: int
                          ) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []
        for i, pattern in enumerate(patterns_for(family), start=1):
            hypotheses.append(Hypothesis(
                hypothesis_id=f"hyp-{family.value}-{order:02d}-{i}",
                family=family,
                statement=pattern.statement,
                success_indicator=pattern.success_indicator,
                failure_indicator=pattern.failure_indicator,
                probe_strategy=pattern.probe_strategy,
                estimated_requests=pattern.estimated_requests,
                estimated_llm_calls=pattern.estimated_llm_calls,
                estimated_duration_seconds=pattern.estimated_duration_seconds,
                order=i,
            ))
        return hypotheses

    def _build_chain_phase(self, order: int, *, max_requests: int,
                           max_time_minutes: int,
                           max_llm_calls: int) -> Phase:
        return Phase(
            phase_id=f"phase-{order:02d}-chain",
            order=order,
            goal="Build the final attack chain",
            thesis_alignment=("Consolidates whatever the earlier phases "
                              "confirmed into one demonstrable "
                              "business-impact chain — the story the "
                              "operator submits"),
            hypotheses=[],
            budget=PhaseBudget(
                max_requests=max_requests,
                max_time_minutes=max_time_minutes,
                max_llm_calls=max_llm_calls,
            ),
            exit_criteria=[
                "Chain narrative drafted from confirmed findings",
            ],
            success_indicators=["A chained, demonstrable impact story"],
            failure_indicators=["No confirmed findings to chain"],
            pivot_triggers=[],
            entry_criteria=["At least one phase produced confirmed findings"],
        )

    def _validate_phases(self, phases: list[Phase],
                         total_budget: CampaignBudget) -> None:
        errors = validate_phases(phases, total_budget)
        if errors:
            raise ValueError("; ".join(errors))
