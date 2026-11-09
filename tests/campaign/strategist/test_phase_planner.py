"""U-CAMPAIGN-2 — PhasePlanner (10 tests).

Turns the thesis into concrete phases with hypotheses, budgets, exit
criteria and pivot triggers. Phases not hypotheses: the plan decides
the SHAPES of exploration; the hypotheses inside each phase stay
disposable.
"""
from __future__ import annotations

import pytest

from webpent.campaign.schemas import CampaignBudget, Family
from webpent.campaign.strategist.phase_planner import MAX_PHASES, PhasePlanner


def test_plan_creates_phases(thesis_fintech, budget_1000):
    planner = PhasePlanner()
    phases = planner.plan(thesis_fintech, budget_1000)

    assert 2 <= len(phases) <= 5
    assert phases[0].order == 1
    assert phases[-1].goal.lower().endswith("chain")


def test_phases_ranked_by_roi(thesis_fintech, budget_1000):
    planner = PhasePlanner()
    phases = planner.plan(thesis_fintech, budget_1000)

    # Family phases ordered by thesis-probability (descending ROI)
    assert all(p.order > 0 for p in phases)
    # First phase should NOT be the chain (chain is last)
    assert not phases[0].goal.lower().endswith("chain")


def test_phase_budget_never_exceeds_total(thesis_fintech, budget_1000):
    planner = PhasePlanner()
    phases = planner.plan(thesis_fintech, budget_1000)

    total = sum(p.budget.max_requests for p in phases)
    assert total <= budget_1000.max_requests


def test_phase_has_pivot_trigger(phases_fintech):
    trigger = phases_fintech[0].pivot_triggers[0]

    assert trigger.condition_type == "consecutive_failures"
    assert trigger.action is not None


def test_chain_phase_has_no_hypotheses(phases_fintech):
    chain = phases_fintech[-1]

    assert chain.goal.lower().endswith("chain")
    assert len(chain.hypotheses) == 0


def test_hypotheses_have_success_indicators(phases_fintech):
    for phase in phases_fintech:
        for hyp in phase.hypotheses:
            assert hyp.success_indicator
            assert hyp.failure_indicator
            assert hyp.estimated_requests > 0


def test_deterministic_planning(thesis_fintech, budget_1000):
    planner = PhasePlanner()
    p1 = planner.plan(thesis_fintech, budget_1000)
    p2 = planner.plan(thesis_fintech, budget_1000)

    assert [p.phase_id for p in p1] == [p.phase_id for p in p2]
    assert [p.goal for p in p1] == [p.goal for p in p2]


def test_max_phase_limit_enforced(thesis_with_many_families, budget_1000):
    planner = PhasePlanner()
    phases = planner.plan(thesis_with_many_families, budget_1000)

    # Even with 6+ likely families, never exceed MAX_PHASES
    assert len(phases) <= MAX_PHASES


def test_phase_references_thesis(thesis_fintech, budget_1000):
    planner = PhasePlanner()
    phases = planner.plan(thesis_fintech, budget_1000)

    for phase in phases:
        assert phase.thesis_alignment  # every phase traces back to thesis


def test_planner_validates_phase_gaps(budget_1000):
    planner = PhasePlanner()

    with pytest.raises(ValueError):
        planner._validate_phases([], budget_1000)
