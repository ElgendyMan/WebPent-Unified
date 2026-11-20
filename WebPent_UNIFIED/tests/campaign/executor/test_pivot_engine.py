"""U-CAMPAIGN-5 — PivotEngine (12 tests).

Knowing when to quit is as valuable as knowing when to push. Pivot
triggers are declared UP FRONT in the phase (before any traffic) and
evaluated mechanically — pivot at boundaries, not at frustration.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webpent.campaign.executor.budget_guard import BudgetSnapshot
from webpent.campaign.executor.phase_runner import HypothesisResult
from webpent.campaign.executor.pivot_engine import PivotEngine, PivotDecision
from webpent.campaign.schemas import (
    Family,
    Hypothesis,
    Phase,
    PhaseBudget,
    PhaseStatus,
    PivotAction,
    PivotTrigger,
)

NOW = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)


def make_phase(trigger=None):
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
        for i in range(1, 4)
    ]
    return Phase(
        phase_id="phase-1",
        order=1,
        goal="Test IDOR",
        thesis_alignment="Tests IDOR",
        hypotheses=hypotheses,
        budget=PhaseBudget(max_requests=500, max_time_minutes=30, max_llm_calls=20),
        exit_criteria=["Found at least 1 IDOR finding"],
        success_indicators=[],
        failure_indicators=[],
        pivot_triggers=[trigger] if trigger else [],
    )


def make_result(status=PhaseStatus.FAILED, findings=None,
                hypothesis_results=None):
    from webpent.campaign.executor.phase_runner import (
        HypothesisResult, PhaseResult,
    )

    if hypothesis_results is None:
        hypothesis_results = [
            HypothesisResult(
                hypothesis_id=f"hyp-{i}", success=False, findings=[],
                requests_used=10, time_seconds=1.0, llm_calls_used=1,
                failure_reason="refuted",
            )
            for i in range(1, 4)
        ]
    return PhaseResult(
        phase_id="phase-1",
        target_id="t1",
        status=status,
        hypothesis_results=hypothesis_results,
        findings=list(findings or []),
        requests_used=30,
        time_seconds=3.0,
        llm_calls_used=3,
        exited_due_to="test",
        started_at=NOW,
        ended_at=NOW,
    )


def make_budget(requests=5000, seconds=3600.0, llm=500):
    return BudgetSnapshot(
        requests_remaining=requests,
        time_seconds_remaining=seconds,
        llm_calls_remaining=llm,
    )


def make_trigger(threshold=2, action=PivotAction.NEXT_PHASE):
    return PivotTrigger(
        trigger_id="pivot-1",
        condition=f"{threshold} consecutive hypothesis failures",
        condition_type="consecutive_failures",
        threshold=threshold,
        action=action,
        reason="Family refuted",
    )


# ---------------------------------------------------------------------------
# Trigger evaluation
# ---------------------------------------------------------------------------

def test_trigger_fires_on_consecutive_failures(engine):
    phase = make_phase(make_trigger(threshold=2))
    result = make_result(hypothesis_results=[
        make_result().hypothesis_results[0],
        make_result().hypothesis_results[1],
    ])

    decision = engine.check(phase, result.hypothesis_results)
    assert decision is not None
    assert decision.action == PivotAction.NEXT_PHASE


def test_trigger_does_not_fire_below_threshold(engine):
    phase = make_phase(make_trigger(threshold=5))
    result = make_result()

    decision = engine.check(phase, result.hypothesis_results)
    assert decision is None


def test_trigger_success_resets_counter(engine):
    """A success between failures resets the consecutive count."""
    phase = make_phase(make_trigger(threshold=2))
    results = [
        make_result().hypothesis_results[0],          # fail
        HypothesisResult(                              # success
            hypothesis_id="hyp-ok", success=True, findings=[object()],
            requests_used=10, time_seconds=1.0, llm_calls_used=1,
            failure_reason=None,
        ),
        make_result().hypothesis_results[1],          # fail (consec = 1)
    ]

    decision = engine.check(phase, results)
    assert decision is None


def test_unknown_trigger_condition_ignored(engine):
    phase = make_phase(make_trigger())
    phase.pivot_triggers[0].condition_type = "operator_mood"

    decision = engine.check(phase, make_result().hypothesis_results)
    assert decision is None


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------

def test_decide_success_proceeds(engine, phase_idor):
    engine_ = engine
    result = make_result(status=PhaseStatus.SUCCESS, findings=[object()])

    decision = engine_.decide(phase_idor, result, make_budget())
    assert decision.action == PivotAction.PROCEED


def test_decide_failed_with_budget_next_phase(engine, phase_idor):
    result = make_result(status=PhaseStatus.FAILED)

    decision = engine.decide(phase_idor, result, make_budget())
    assert decision.action == PivotAction.NEXT_PHASE


def test_decide_failed_no_budget_abort(engine, phase_idor):
    result = make_result(status=PhaseStatus.FAILED)

    decision = engine.decide(phase_idor, result, make_budget(requests=0, seconds=0, llm=0))
    assert decision.action == PivotAction.ABORT


def test_decide_exhausted_no_findings_regenerate(engine, phase_idor):
    result = make_result(status=PhaseStatus.EXHAUSTED, findings=[])

    decision = engine.decide(phase_idor, result, make_budget(
        requests=100, seconds=600, llm=10))
    assert decision.action == PivotAction.REGENERATE


def test_decide_exhausted_no_budget_abort(engine, phase_idor):
    result = make_result(status=PhaseStatus.EXHAUSTED, findings=[])

    decision = engine.decide(phase_idor, result, make_budget(requests=0, seconds=0, llm=0))
    assert decision.action == PivotAction.ABORT


def test_decide_findings_override_failure(engine, phase_idor):
    """Findings change the calculus even on a failed phase."""
    result = make_result(status=PhaseStatus.FAILED, findings=[object()])

    decision = engine.decide(phase_idor, result, make_budget(requests=0, seconds=0, llm=0))
    assert decision.action == PivotAction.PROCEED_CAUTION


def test_decide_follows_declared_trigger(engine):
    phase = make_phase(make_trigger(threshold=2, action=PivotAction.NEXT_PHASE))
    result = make_result(status=PhaseStatus.PIVOTED)

    decision = engine.decide(phase, result, make_budget())
    assert decision.action == PivotAction.NEXT_PHASE


def test_decide_is_deterministic(engine, phase_idor):
    result = make_result(status=PhaseStatus.FAILED)
    budget = make_budget()

    d1 = engine.decide(phase_idor, result, budget)
    d2 = engine.decide(phase_idor, result, budget)

    assert d1.action == d2.action
    assert d1.reason == d2.reason


def test_pivot_decision_has_reason(engine, phase_idor):
    result = make_result(status=PhaseStatus.FAILED)

    decision = engine.decide(phase_idor, result, make_budget())
    assert decision.reason
