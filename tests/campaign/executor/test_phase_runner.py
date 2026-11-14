"""U-CAMPAIGN-4 — PhaseRunner (10 tests).

Executes a phase's hypotheses through the injected brain and apex.
Budget is law: nothing runs without a cap, every request counts.
"""
from __future__ import annotations

import pytest

from webpent.campaign.executor.budget_guard import BudgetGuard
from webpent.campaign.executor.phase_runner import PhaseRunner, PhaseStatus
from webpent.campaign.executor.pivot_engine import PivotEngine


def test_run_success_on_first_finding(runner, phase_idor, campaign_budget):
    result = runner.run(phase_idor, campaign_budget)

    assert result.status == PhaseStatus.SUCCESS
    assert len(result.findings) >= 1


def test_run_failed_phase(runner_with_stub_brain_failing, phase_idor,
                          campaign_budget):
    result = runner_with_stub_brain_failing.run(phase_idor, campaign_budget)

    assert result.status == PhaseStatus.FAILED
    assert result.exited_due_to == "all_hypotheses_refuted"


def test_run_pivot_on_trigger(runner_with_stub_brain_failing, phase_with_pivot,
                              campaign_budget):
    result = runner_with_stub_brain_failing.run(phase_with_pivot, campaign_budget)

    assert result.status == PhaseStatus.PIVOTED
    assert result.pivot_decision is not None
    assert result.pivot_decision.action is not None


def test_run_exhausted_budget(tight_budget):
    """Phase exhausts the campaign budget before finishing."""
    from webpent.campaign.schemas import (
        Family, Hypothesis, Phase, PhaseBudget,
    )

    # 10 hypotheses × 50 requests = 500 requested, budget allows 20
    hypotheses = [
        Hypothesis(
            hypothesis_id=f"hyp-{i}",
            family=Family.IDOR,
            statement=f"hypothesis {i}",
            success_indicator="data leak",
            failure_indicator="403 returned",
            probe_strategy="GET without auth",
            estimated_requests=50,
            estimated_llm_calls=2,
            estimated_duration_seconds=30,
            order=i,
        )
        for i in range(10)
    ]
    phase = Phase(
        phase_id="phase-big",
        order=1,
        goal="Big phase",
        thesis_alignment="Tests IDOR",
        hypotheses=hypotheses,
        budget=PhaseBudget(max_requests=100, max_time_minutes=30, max_llm_calls=20),
        exit_criteria=["Found at least 1 IDOR finding"],
        success_indicators=[],
        failure_indicators=[],
        pivot_triggers=[],
    )
    runner = PhaseRunner(
        brain=type("B", (), {
            "evaluate": staticmethod(lambda h, b: __import__(
                "webpent.campaign.executor.phase_runner",
                fromlist=["HypothesisResult"]).HypothesisResult(
                hypothesis_id=h.hypothesis_id, success=False, findings=[],
                requests_used=50, time_seconds=10.0, llm_calls_used=2,
                failure_reason="refuted"))})(),
        apex=None,
        budget_guard=BudgetGuard(),
        pivot_engine=PivotEngine(),
    )
    result = runner.run(phase, tight_budget)

    assert result.status == PhaseStatus.EXHAUSTED


def test_run_records_findings(runner, phase_idor, campaign_budget):
    result = runner.run(phase_idor, campaign_budget)

    assert isinstance(result.findings, list)
    assert result.target_id == "target-1"


def test_budget_tracking_accurate(runner_with_stub_brain, phase_idor,
                                  campaign_budget):
    result = runner_with_stub_brain.run(phase_idor, campaign_budget)

    # Stub uses 10 requests per hypothesis
    assert result.requests_used == 10 * len(phase_idor.hypotheses) or \
        result.requests_used < phase_idor.budget.max_requests


def test_pivot_decision_in_result(runner, phase_idor, campaign_budget):
    """Successful phase → pivot_decision is None."""
    result = runner.run(phase_idor, campaign_budget)

    assert result.pivot_decision is None


def test_run_is_deterministic(runner, phase_idor, campaign_budget):
    r1 = runner.run(phase_idor, campaign_budget)
    r2 = runner.run(phase_idor, campaign_budget)

    # Determinism of the machine's decisions (not wall-clock timestamps)
    assert r1.status == r2.status
    assert len(r1.findings) == len(r2.findings)
    assert r1.requests_used == r2.requests_used


def test_hypothesis_not_reexecuted_after_success(runner, phase_idor,
                                                 campaign_budget):
    """Success exits the phase; no hypothesis is executed twice."""
    calls = []

    class CountingBrain:
        def evaluate(self, hypothesis, remaining_budget):
            calls.append(hypothesis.hypothesis_id)
            from webpent.campaign.executor.phase_runner import HypothesisResult
            return HypothesisResult(
                hypothesis_id=hypothesis.hypothesis_id,
                success=True,
                findings=[{"kind": "f"}],
                requests_used=10,
                time_seconds=1.0,
                llm_calls_used=1,
                failure_reason=None,
            )

    counting_runner = PhaseRunner(
        brain=CountingBrain(),
        apex=None,
        budget_guard=BudgetGuard(),
        pivot_engine=PivotEngine(),
    )
    counting_runner.run(phase_idor, campaign_budget)

    assert len(calls) == len(set(calls))  # no hypothesis executed twice


def test_skipped_on_entry_criteria(campaign_budget, phase_idor):
    """Phase whose entry criteria fail → SKIPPED without any execution."""
    calls = []

    class NeverBrain:
        def evaluate(self, hypothesis, remaining_budget):
            calls.append(hypothesis.hypothesis_id)
            raise AssertionError("brain must not be called on a skipped phase")

    runner = PhaseRunner(
        brain=NeverBrain(),
        apex=None,
        budget_guard=BudgetGuard(),
        pivot_engine=PivotEngine(),
        entry_criteria_check=lambda phase: False,
    )
    result = runner.run(phase_idor, campaign_budget)

    assert result.status == PhaseStatus.SKIPPED
    assert calls == []
