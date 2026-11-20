"""U-CAMPAIGN-3 — OperatorHandoff (8 tests).

The operator is sovereign: before ANY traffic leaves the workshop, a
human reads the brief and approves, rejects or modifies it. The
machine NEVER self-approves.
"""
from __future__ import annotations

import pytest

from webpent.campaign.errors import (
    CampaignNotApprovedError,
    InvalidModificationError,
)
from webpent.campaign.executor.budget_guard import require_approved
from webpent.campaign.schemas import (
    CampaignBrief,
    Decision,
    Family,
    Phase,
    PhaseBudget,
)
from webpent.campaign.strategist.handoff import OperatorHandoff
from webpent.campaign.strategist.phase_planner import PhasePlanner


def test_present_returns_brief(thesis_fintech, budget_1000, store):
    phases = PhasePlanner().plan(thesis_fintech, budget_1000)
    handoff = OperatorHandoff(store)
    brief = handoff.present(thesis_fintech, phases, budget_1000)

    assert brief.decision == Decision.PENDING
    assert brief.campaign_id is not None
    assert brief.total_budget.max_requests == budget_1000.max_requests


def test_approve_sets_decision(thesis_fintech, budget_1000, store):
    phases = PhasePlanner().plan(thesis_fintech, budget_1000)
    handoff = OperatorHandoff(store)
    brief = handoff.present(thesis_fintech, phases, budget_1000)
    approved = handoff.approve(brief)

    assert approved.decision == Decision.APPROVED


def test_reject_sets_decision(thesis_fintech, budget_1000, store):
    phases = PhasePlanner().plan(thesis_fintech, budget_1000)
    handoff = OperatorHandoff(store)
    brief = handoff.present(thesis_fintech, phases, budget_1000)
    rejected = handoff.reject(brief)

    assert rejected.decision == Decision.REJECTED


def test_modify_skips_phases(thesis_fintech, budget_1000, store):
    phases = PhasePlanner().plan(thesis_fintech, budget_1000)
    handoff = OperatorHandoff(store)
    brief = handoff.present(thesis_fintech, phases, budget_1000)

    modified = handoff.modify(
        brief,
        modifications={"skip_phases": [phases[0].phase_id]},
    )

    assert modified.decision == Decision.MODIFIED
    assert phases[0].phase_id not in {p.phase_id for p in modified.phases}


def test_modify_invalid_phase_raises(thesis_fintech, budget_1000, store):
    phases = PhasePlanner().plan(thesis_fintech, budget_1000)
    handoff = OperatorHandoff(store)
    brief = handoff.present(thesis_fintech, phases, budget_1000)

    with pytest.raises(InvalidModificationError):
        handoff.modify(brief, modifications={"skip_phases": ["phase-does-not-exist"]})


def test_no_campaign_without_approval(thesis_fintech, budget_1000, store):
    phases = PhasePlanner().plan(thesis_fintech, budget_1000)
    handoff = OperatorHandoff(store)
    brief = handoff.present(thesis_fintech, phases, budget_1000)

    with pytest.raises(CampaignNotApprovedError):
        require_approved(brief)


def test_decision_immutable_once_set(thesis_fintech, budget_1000, store):
    phases = PhasePlanner().plan(thesis_fintech, budget_1000)
    handoff = OperatorHandoff(store)
    brief = handoff.present(thesis_fintech, phases, budget_1000)
    approved = handoff.approve(brief)

    with pytest.raises(ValueError):
        handoff.reject(approved)  # cannot change an already-decided brief


def test_pending_briefs_listed(thesis_fintech, budget_1000, store):
    phases = PhasePlanner().plan(thesis_fintech, budget_1000)
    handoff = OperatorHandoff(store)
    brief = handoff.present(thesis_fintech, phases, budget_1000)

    pending = handoff.get_pending()
    assert len(pending) == 1

    handoff.approve(brief)
    assert len(handoff.get_pending()) == 0
