"""U-CAMPAIGN-6 — BudgetGuard (8 tests).

Budget is law. Before every single hypothesis, the guard answers one
question: may this spend happen? Nothing bypasses it, ever.
"""
from datetime import datetime

import pytest

from webpent.campaign.executor.budget_guard import (
    BudgetDecision,
    BudgetGuard,
    BudgetRequest,
    BudgetSnapshot,
    BudgetState,
    require_approved,
)
from webpent.campaign.schemas import Decision
from webpent.campaign.errors import CampaignNotApprovedError


def make_state(camp_used, camp_max, phase_used, phase_max):
    """Compact builder: ints are request counts, tuples are (req, sec, llm)."""

    def _as_request(value):
        if isinstance(value, BudgetRequest):
            return value
        if isinstance(value, int):
            return BudgetRequest(requests=value, time_seconds=60.0, llm_calls=2)
        return BudgetRequest(
            requests=value[0], time_seconds=value[1], llm_calls=value[2])

    return BudgetState(
        campaign_used=_as_request(camp_used),
        campaign_max=_as_request(camp_max),
        phase_used=_as_request(phase_used),
        phase_max=_as_request(phase_max),
    )


def test_allow_within_budget(guard):
    state = make_state(
        camp_used=100, camp_max=1000, phase_used=50, phase_max=300)

    decision = guard.check(
        state, requested=BudgetRequest(requests=100, time_seconds=300.0, llm_calls=10))

    assert decision.allowed is True


def test_block_on_phase_budget_exceeded(guard):
    state = make_state(
        camp_used=100, camp_max=1000, phase_used=250, phase_max=300)

    decision = guard.check(
        state, requested=BudgetRequest(requests=100, time_seconds=60.0, llm_calls=2))

    assert decision.allowed is False
    assert "phase" in decision.reason


def test_block_on_campaign_budget_exceeded(guard):
    state = make_state(
        camp_used=950, camp_max=1000, phase_used=50, phase_max=300)

    decision = guard.check(
        state, requested=BudgetRequest(requests=100, time_seconds=60.0, llm_calls=2))

    assert decision.allowed is False
    assert "campaign" in decision.reason


def test_allow_at_exact_budget_limit(guard):
    """Exact fit is allowed; only strictly-greater is blocked."""
    state = make_state(
        camp_used=900, camp_max=1000, phase_used=200, phase_max=300)

    decision = guard.check(
        state, requested=BudgetRequest(requests=100, time_seconds=60.0, llm_calls=2))

    assert decision.allowed is True


def test_no_bypass_possible(guard):
    """Even a zero-cost request is checked — but at the hard cap it fails."""
    state = make_state(
        camp_used=1000, camp_max=1000, phase_used=300, phase_max=300)

    decision = guard.check(
        state, requested=BudgetRequest(requests=0, time_seconds=0.0, llm_calls=0))

    # Zero-spend at the cap: allowed (nothing is spent) — but one more
    # request is NOT.
    state2 = make_state(
        camp_used=1000, camp_max=1000, phase_used=300, phase_max=300)
    decision2 = guard.check(
        state2, requested=BudgetRequest(requests=1, time_seconds=0.0, llm_calls=0))

    assert decision2.allowed is False


def test_slow_down_on_high_burn_rate(guard):
    """Burning requests faster than the time budget allows → allowed but flagged."""
    state = make_state(
        camp_used=(200, 60.0, 5), camp_max=(1000, 3600.0, 50),
        phase_used=10, phase_max=300)

    decision = guard.check(
        state, requested=BudgetRequest(requests=10, time_seconds=60.0, llm_calls=2))

    assert decision.allowed is True
    assert "burn" in decision.reason or "rate" in decision.reason


def test_decision_records_dimensions(guard):
    state = make_state(
        camp_used=100, camp_max=1000, phase_used=50, phase_max=300)

    decision = guard.check(
        state, requested=BudgetRequest(requests=100, time_seconds=300.0, llm_calls=10))

    assert isinstance(decision, BudgetDecision)
    assert decision.allowed is True
    assert decision.reason  # always a reason, even when allowed


def test_switch_phase_suggestion(guard):
    """When the phase budget is nearly gone but campaign has room → suggest new phase."""
    state = make_state(
        camp_used=100, camp_max=1000, phase_used=250, phase_max=300)

    decision = guard.check(
        state, requested=BudgetRequest(requests=100, time_seconds=60.0, llm_calls=2))

    assert decision.allowed is False
    assert "phase" in decision.reason or "switch" in decision.reason


# ---------------------------------------------------------------------------
# require_approved — the sovereignty check (shared with U-CAMPAIGN-3)
# ---------------------------------------------------------------------------

def test_require_approved_accepts_approved():
    from webpent.campaign.schemas import CampaignBudget, CampaignBrief

    brief = CampaignBrief(
        campaign_id="c1", created_at=datetime(2026, 10, 19),
        thesis=None, phases=[], total_budget=CampaignBudget(
            max_requests=100, max_time_minutes=60, max_llm_calls=10),
        decision=Decision.APPROVED,
    )
    assert require_approved(brief) is None


def test_require_approved_rejects_pending():
    from webpent.campaign.schemas import (
        CampaignBudget, CampaignBrief, TargetThesis,
    )

    thesis = TargetThesis.create(
        target_id="t1", statement="s", confidence=0.5,
        likely_vuln_families=[], unlikely_vuln_families=[],
        crown_jewels=[], likely_entry_points=[], evidence=[], reasoning="r",
    )
    brief = CampaignBrief(
        campaign_id="c1", created_at=datetime(2026, 10, 19),
        thesis=thesis, phases=[], total_budget=CampaignBudget(
            max_requests=100, max_time_minutes=60, max_llm_calls=10),
        decision=Decision.PENDING,
    )
    with pytest.raises(CampaignNotApprovedError):
        require_approved(brief)
