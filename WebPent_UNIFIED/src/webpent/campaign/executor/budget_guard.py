"""U-CAMPAIGN-6 — BudgetGuard.

L-3: budget is law. Before every single hypothesis, the guard answers
one question: may this spend happen? The check is mechanical, typed
and total: phase caps, campaign caps, time and LLM dimensions, plus a
burn-rate advisory that lets the guard flag a sprint it cannot stop.

The guard can never be bypassed from inside the executor: the runner
asks it before each hypothesis and treats a refusal as law. There is
no "skip the check" path in this module.

``require_approved`` (L-2) lives here too: it is the sovereignty gate
the executor calls before its first spend, shared with the handoff
layer.
"""
from __future__ import annotations

from dataclasses import dataclass

from webpent.campaign.errors import CampaignNotApprovedError
from webpent.campaign.schemas import CampaignBrief, Decision


@dataclass(frozen=True)
class BudgetRequest:
    """A proposed spend, in all three dimensions."""

    requests: int
    time_seconds: float
    llm_calls: int


@dataclass(frozen=True)
class BudgetState:
    """The caps and accumulated usage the guard checks against."""

    campaign_used: BudgetRequest
    campaign_max: BudgetRequest
    phase_used: BudgetRequest
    phase_max: BudgetRequest


@dataclass(frozen=True)
class BudgetDecision:
    """The guard's ruling. Always carries a reason, even when allowed."""

    allowed: bool
    reason: str


@dataclass(frozen=True)
class BudgetSnapshot:
    """What is left of the campaign, for pivot decisions (L-6).

    ``has_room_for_more_phases`` encodes the smallest viable phase: a
    phase that cannot afford its minimum footprint is not a phase.
    """

    requests_remaining: int
    time_seconds_remaining: float
    llm_calls_remaining: int

    MIN_PHASE_REQUESTS = 50
    MIN_PHASE_TIME_SECONDS = 300.0
    MIN_PHASE_LLM_CALLS = 3

    def has_room_for_more_phases(self) -> bool:
        return (
            self.requests_remaining >= self.MIN_PHASE_REQUESTS
            and self.time_seconds_remaining >= self.MIN_PHASE_TIME_SECONDS
            and self.llm_calls_remaining >= self.MIN_PHASE_LLM_CALLS
        )


def require_approved(brief: CampaignBrief) -> None:
    """L-2 gate: raise unless the operator APPROVED this brief."""
    if brief.decision is not Decision.APPROVED:
        raise CampaignNotApprovedError(
            f"campaign {brief.campaign_id} is "
            f"'{brief.decision.value}' — no traffic may leave the "
            "workshop until the operator approves (L-2)")
    return None


class BudgetGuard:
    """The law before every spend (L-3)."""

    # Above this many requests per minute of campaign time, the guard
    # allows the spend but flags the pace (advisory — the cap is the law,
    # the pace is the operator's judgment call).
    HIGH_BURN_RATE_PER_MINUTE = 100.0

    def check(self, state: BudgetState, *,
              requested: BudgetRequest) -> BudgetDecision:
        """Ruling on a proposed spend.

        REQUESTS are the hard-capped law, in both scopes: the phase's
        own cap first, then the campaign's total. The time and LLM
        dimensions are tracked and flagged advisively — the guard
        never hides an overrun, it just does not rule by it (the
        clock and the LLM meter are estimates the brain reports; the
        request count is the spend the operator actually authorized).
        """
        # 1. Phase request cap — the phase's own law.
        phase_requests = state.phase_used.requests + requested.requests
        if phase_requests > state.phase_max.requests:
            return BudgetDecision(
                allowed=False,
                reason=(
                    f"phase_budget_exceeded: {phase_requests}/"
                    f"{state.phase_max.requests} requests — this phase is "
                    "spent; switch_phase to the next phase or close the "
                    "campaign"))

        # 2. Campaign request cap — the operator's total commitment.
        campaign_requests = state.campaign_used.requests + requested.requests
        if campaign_requests > state.campaign_max.requests:
            return BudgetDecision(
                allowed=False,
                reason=(f"campaign_budget_exceeded: {campaign_requests}/"
                        f"{state.campaign_max.requests} requests — the "
                        "campaign's total budget is law"))

        # 3. Advisory notes — recorded, never blocking.
        notes: list[str] = []
        if (state.phase_used.time_seconds + requested.time_seconds
                > state.phase_max.time_seconds):
            notes.append(
                f"phase_time_overrun: "
                f"{state.phase_used.time_seconds + requested.time_seconds:.0f}s"
                f"/{state.phase_max.time_seconds:.0f}s (advisory)")
        if (state.phase_used.llm_calls + requested.llm_calls
                > state.phase_max.llm_calls):
            notes.append(
                f"phase_llm_overrun: "
                f"{state.phase_used.llm_calls + requested.llm_calls}/"
                f"{state.phase_max.llm_calls} calls (advisory)")

        # 4. Burn-rate advisory (never blocks — the caps already ruled).
        minutes = max(state.campaign_used.time_seconds / 60.0, 1.0 / 60.0)
        rate = state.campaign_used.requests / minutes
        if rate > self.HIGH_BURN_RATE_PER_MINUTE:
            notes.append(
                f"high_burn_rate: {rate:.0f} requests/minute against "
                "the time budget — the pace is flagged for the operator")

        if notes:
            return BudgetDecision(allowed=True, reason="; ".join(notes))
        return BudgetDecision(allowed=True, reason="within budget")
