"""Strategist validators (supports U-CAMPAIGN-1 and U-CAMPAIGN-2).

Fail-closed checks shared by the ThesisBuilder and the PhasePlanner.
Each validator returns a list of human-readable failures — empty means
valid — so callers can report ALL failures at once instead of
stumbling over the first.
"""
from __future__ import annotations

from webpent.campaign.schemas import (
    CampaignBudget,
    Phase,
    TargetThesis,
)

# The proceeding floor: a thesis below any of these does not campaign.
MIN_CONFIDENCE_TO_PROCEED = 0.4
MIN_EVIDENCE_PIECES = 2
MIN_REASONING_CHARS = 50


def validate_thesis(thesis: TargetThesis) -> list[str]:
    """All the ways this thesis may not proceed (L-1)."""
    errors: list[str] = []
    if thesis.confidence < MIN_CONFIDENCE_TO_PROCEED:
        errors.append(
            f"confidence {thesis.confidence:.2f} below proceeding floor "
            f"{MIN_CONFIDENCE_TO_PROCEED:.2f}")
    if len(thesis.evidence) < MIN_EVIDENCE_PIECES:
        errors.append(
            f"only {len(thesis.evidence)} evidence piece(s); a thesis needs "
            f"at least {MIN_EVIDENCE_PIECES} (a lone Economist score never "
            "carries a campaign)")
    if not thesis.likely_vuln_families:
        errors.append("no likely vulnerability families — nothing to plan")
    if not thesis.crown_jewels:
        errors.append("no crown jewels identified — a campaign without a "
                      "target of value is wandering, not hunting")
    if len(thesis.reasoning.strip()) < MIN_REASONING_CHARS:
        errors.append(
            f"reasoning too thin ({len(thesis.reasoning.strip())} chars; "
            f"minimum {MIN_REASONING_CHARS}) — the operator will read this")
    return errors


def validate_phases(phases: list[Phase], total_budget: CampaignBudget) -> list[str]:
    """All the ways this plan may not run (L-3, L-6)."""
    errors: list[str] = []
    if not phases:
        errors.append("plan is empty — a campaign needs at least one phase")
        return errors
    orders = [p.order for p in phases]
    if orders != list(range(1, len(phases) + 1)):
        errors.append(f"phase orders not sequential 1..n: {orders}")
    total_requests = sum(p.budget.max_requests for p in phases)
    if total_requests > total_budget.max_requests:
        errors.append(
            f"phase budgets sum to {total_requests} requests, exceeding the "
            f"campaign cap {total_budget.max_requests}")
    total_llm = sum(p.budget.max_llm_calls for p in phases)
    if total_llm > total_budget.max_llm_calls:
        errors.append(
            f"phase LLM budgets sum to {total_llm}, exceeding the campaign "
            f"cap {total_budget.max_llm_calls}")
    for phase in phases:
        if not phase.thesis_alignment:
            errors.append(
                f"phase {phase.phase_id} does not trace back to the thesis")
    return errors
