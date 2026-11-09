"""EGAIE selector + repetition register tests."""
from __future__ import annotations

from webpent.egaie.repetition import RepetitionRegister
from webpent.egaie.schemas import (
    HypothesisRecord,
    HypothesisStatus,
    InvestigationState,
    ProposedExperiment,
)
from webpent.egaie.selection import InformationGainSelector


def _state_with(family: str, status_h1: str = "proposed") -> InvestigationState:
    state = InvestigationState(engagement_id="e", target_url="t")
    record = HypothesisRecord(
        hypothesis_id="h-1", family=family, statement="s")
    if status_h1 != "proposed":
        from webpent.egaie.schemas import HypothesisStatus
        record = record.with_status(HypothesisStatus(status_h1))
    state.add_hypothesis(record)
    return state


def _exp(experiment_id: str, family: str, signature: str,
         cost: float = 0.2, risk: float = 0.2) -> ProposedExperiment:
    return ProposedExperiment(
        experiment_id=experiment_id, family=family, signature=signature,
        description="d", cost=cost, risk=risk, gain_estimate=0.5,
        rationale="r")


def test_selector_prefers_unresolved_family_over_resolved_one():
    state = InvestigationState(engagement_id="e", target_url="t")
    state.add_hypothesis(HypothesisRecord(
        hypothesis_id="h-a", family="IDOR", statement="open"))
    state.add_hypothesis(HypothesisRecord(
        hypothesis_id="h-b", family="XSS", statement="closed")
        .with_status(HypothesisStatus.CONFIRMED))
    chosen = _exp("e-idor", "IDOR", "sig-idor")
    other = _exp("e-xss", "XSS", "sig-xss")
    decision = InformationGainSelector().select(
        state, [other, chosen], RepetitionRegister())
    assert decision.selected_experiment_id == "e-idor"
    assert decision.scores["e-idor"] > decision.scores["e-xss"]


def test_repetition_penalty_orders_fresh_signature_first():
    state = _state_with("IDOR")
    register = RepetitionRegister()
    register.record("sig-repeated/IDOR", "inconclusive")
    register.record("sig-repeated/IDOR", "inconclusive")
    fresh = _exp("e-fresh", "IDOR", "sig-fresh/IDOR")
    repeated = _exp("e-repeat", "IDOR", "sig-repeated/IDOR")
    decision = InformationGainSelector().select(
        state, [repeated, fresh], register)
    assert decision.selected_experiment_id == "e-fresh"


def test_exhausted_signature_triggers_strategy_switch():
    state = _state_with("IDOR")
    register = RepetitionRegister()
    register.record("sig-x/IDOR", "inconclusive")
    register.record("sig-x/IDOR", "inconclusive")
    exhausted = _exp("e-x", "IDOR", "sig-x/IDOR")
    decision = InformationGainSelector().select(
        state, [exhausted], register)
    assert decision.action.value == "strategy_switch"
    assert decision.selected_experiment_id == ""
    assert "sig-x/IDOR" in decision.rationale


def test_no_candidates_terminates():
    state = _state_with("IDOR")
    decision = InformationGainSelector().select(
        state, [], RepetitionRegister())
    assert decision.action.value == "terminate"


def test_deterministic_tie_break_by_experiment_id():
    state = _state_with("IDOR")
    a = _exp("e-a", "IDOR", "sig-a/IDOR")
    b = _exp("e-b", "IDOR", "sig-b/IDOR")
    first = InformationGainSelector().select(
        state, [b, a], RepetitionRegister())
    second = InformationGainSelector().select(
        state, [a, b], RepetitionRegister())
    assert first.selected_experiment_id == second.selected_experiment_id
    assert first.selected_experiment_id == "e-a"


def test_higher_cost_and_risk_score_lower():
    state = _state_with("IDOR")
    cheap = _exp("e-cheap", "IDOR", "sig-a/IDOR", cost=0.1, risk=0.1)
    costly = _exp("e-costly", "IDOR", "sig-b/IDOR", cost=0.9, risk=0.9)
    decision = InformationGainSelector().select(
        state, [costly, cheap], RepetitionRegister())
    assert decision.scores["e-cheap"] > decision.scores["e-costly"]


def test_repetition_register_counts_uninformative_only():
    register = RepetitionRegister()
    register.record("sig/IDOR", "confirmed")
    register.record("sig/IDOR", "inconclusive")
    assert register.uninformative_count("sig/IDOR") == 1
    assert not register.is_exhausted("sig/IDOR")
    register.record("sig/IDOR", "blocked")
    register.record("sig/IDOR", "inconclusive")
    assert register.uninformative_count("sig/IDOR") == 3
    assert register.is_exhausted("sig/IDOR")
    assert register.is_exhausted("other/IDOR") is False
