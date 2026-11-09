"""U-CAMPAIGN-4 — PhaseRunner.

Executes ONE phase: its hypotheses, in order, through the injected
brain — the runner performs no network I/O of its own (transport is
always caller-injected, exactly like the verdict bridge's executor).

The laws it enforces mechanically:
- L-2: it never runs without the operator's approval already recorded
  (the orchestrator calls ``require_approved`` before the first phase;
  the runner itself trusts the caller for the gate and never spawns a
  campaign on its own).
- L-3: before EVERY hypothesis the budget guard rules; a refusal is
  law — the phase ends EXHAUSTED, never "one more won't hurt".
- L-6: after every hypothesis the pivot engine evaluates the phase's
  DECLARED triggers; a fired trigger ends the phase PIVOTED with the
  decision recorded.
- Findings short-circuit: the first hypothesis that yields findings
  ends the phase SUCCESS (no hypothesis is ever executed twice).

Every exit carries ``exited_due_to`` — the trace answers "why did the
phase end" without inference.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from webpent.campaign.executor.budget_guard import (
    BudgetRequest,
    BudgetSnapshot,
    BudgetState,
)
from webpent.campaign.schemas import CampaignBudget, Phase, PhaseStatus

__all__ = ["HypothesisResult", "PhaseResult", "PhaseRunner", "PhaseStatus"]


@dataclass(frozen=True)
class HypothesisResult:
    """One hypothesis's outcome, as the brain reported it."""

    hypothesis_id: str
    success: bool
    findings: list[Any]
    requests_used: int
    time_seconds: float
    llm_calls_used: int
    failure_reason: str | None


@dataclass(frozen=True)
class PhaseResult:
    """The phase's ending, fully accounted (L-9: no silent drift)."""

    phase_id: str
    target_id: str | None
    status: PhaseStatus
    hypothesis_results: list[HypothesisResult]
    findings: list[Any]
    requests_used: int
    time_seconds: float
    llm_calls_used: int
    exited_due_to: str
    pivot_decision: Any | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None


class PhaseRunner:
    """Runs one phase's hypotheses through the injected brain/apex."""

    def __init__(
        self,
        *,
        brain: Any,
        apex: Any,
        budget_guard: Any,
        pivot_engine: Any,
        entry_criteria_check: Callable[[Phase], bool] | None = None,
    ):
        self._brain = brain
        self._apex = apex
        self._budget_guard = budget_guard
        self._pivot_engine = pivot_engine
        self._entry_criteria_check = entry_criteria_check

    def run(
        self,
        phase: Phase,
        campaign_budget: CampaignBudget,
        *,
        campaign_used: BudgetRequest | None = None,
    ) -> PhaseResult:
        """Execute ``phase`` against the campaign budget.

        ``campaign_used`` is the usage the EARLIER phases of this
        campaign already spent (the orchestrator's ledger). This run's
        own spends accumulate on top of it for every guard check —
        the campaign cap is law across phases, not per phase.
        """
        started_at = datetime.now(timezone.utc)

        if (self._entry_criteria_check is not None
                and not self._entry_criteria_check(phase)):
            return PhaseResult(
                phase_id=phase.phase_id,
                target_id=phase.target_id,
                status=PhaseStatus.SKIPPED,
                hypothesis_results=[],
                findings=[],
                requests_used=0,
                time_seconds=0.0,
                llm_calls_used=0,
                exited_due_to="entry_criteria",
                started_at=started_at,
                ended_at=datetime.now(timezone.utc),
            )

        prior = campaign_used or BudgetRequest(
            requests=0, time_seconds=0.0, llm_calls=0)
        campaign_max = BudgetRequest(
            requests=int(campaign_budget.max_requests),
            time_seconds=float(campaign_budget.max_time_minutes * 60),
            llm_calls=int(campaign_budget.max_llm_calls),
        )
        phase_max = BudgetRequest(
            requests=int(phase.budget.max_requests),
            time_seconds=float(phase.budget.max_time_minutes * 60),
            llm_calls=int(phase.budget.max_llm_calls),
        )

        phase_used = BudgetRequest(requests=0, time_seconds=0.0, llm_calls=0)
        results: list[HypothesisResult] = []
        findings: list[Any] = []
        pivot_decision = None
        exited_due_to: str | None = None

        for hypothesis in phase.hypotheses:
            # L-3: the guard rules BEFORE every spend. A refusal ends
            # the phase — the runner never negotiates with the law.
            campaign_sofar = BudgetRequest(
                requests=prior.requests + phase_used.requests,
                time_seconds=prior.time_seconds + phase_used.time_seconds,
                llm_calls=prior.llm_calls + phase_used.llm_calls,
            )
            ruling = self._budget_guard.check(
                BudgetState(
                    campaign_used=campaign_sofar,
                    campaign_max=campaign_max,
                    phase_used=phase_used,
                    phase_max=phase_max,
                ),
                requested=BudgetRequest(
                    requests=int(hypothesis.estimated_requests),
                    time_seconds=float(hypothesis.estimated_duration_seconds),
                    llm_calls=int(hypothesis.estimated_llm_calls),
                ),
            )
            if not ruling.allowed:
                exited_due_to = "budget"
                break

            remaining = BudgetSnapshot(
                requests_remaining=max(
                    0, campaign_max.requests - campaign_sofar.requests),
                time_seconds_remaining=max(
                    0.0, campaign_max.time_seconds - campaign_sofar.time_seconds),
                llm_calls_remaining=max(
                    0, campaign_max.llm_calls - campaign_sofar.llm_calls),
            )
            outcome = self._brain.evaluate(hypothesis, remaining)
            results.append(outcome)
            findings.extend(outcome.findings)
            phase_used = BudgetRequest(
                requests=phase_used.requests + outcome.requests_used,
                time_seconds=phase_used.time_seconds + outcome.time_seconds,
                llm_calls=phase_used.llm_calls + outcome.llm_calls_used,
            )

            # L-6: declared triggers are evaluated mechanically after
            # every hypothesis — pivoting at frustration is impossible
            # here because only the plan's own triggers can fire.
            fired = self._pivot_engine.check(phase, results)
            if fired is not None:
                pivot_decision = fired
                exited_due_to = "pivot_trigger"
                break

            if findings:
                exited_due_to = "success"
                break

        if exited_due_to == "pivot_trigger":
            status = PhaseStatus.PIVOTED
        elif exited_due_to == "success":
            status = PhaseStatus.SUCCESS
        elif exited_due_to == "budget":
            status = PhaseStatus.EXHAUSTED
        elif not phase.hypotheses:
            # A phase with no ammunition (e.g. the chain phase run
            # standalone) reports honestly instead of pretending.
            status = PhaseStatus.FAILED
            exited_due_to = "no_hypotheses"
        else:
            status = PhaseStatus.FAILED
            exited_due_to = "all_hypotheses_refuted"

        return PhaseResult(
            phase_id=phase.phase_id,
            target_id=phase.target_id,
            status=status,
            hypothesis_results=results,
            findings=findings,
            requests_used=phase_used.requests,
            time_seconds=phase_used.time_seconds,
            llm_calls_used=phase_used.llm_calls,
            exited_due_to=exited_due_to or "no_hypotheses",
            pivot_decision=pivot_decision,
            started_at=started_at,
            ended_at=datetime.now(timezone.utc),
        )
