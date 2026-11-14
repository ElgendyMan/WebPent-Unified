"""EGAIE investigation state: roundtrip, resume, helpers."""
from __future__ import annotations

import json

from webpent.egaie.schemas import (
    DecisionAction,
    DecisionRecord,
    EvidenceItem,
    EvidenceKind,
    HypothesisRecord,
    HypothesisStatus,
    InvestigationState,
    ProposedExperiment,
)


def _state() -> InvestigationState:
    state = InvestigationState(
        engagement_id="eng-1",
        target_url="fixture://demo",
    )
    state.add_hypothesis(HypothesisRecord(
        hypothesis_id="h-1", family="IDOR",
        statement="User A can read User B's invoice",
        source="deep", origin="pos-idor-1"))
    state.add_experiment(ProposedExperiment(
        experiment_id="e-1", family="IDOR", signature="pos-idor-1/IDOR",
        description="read cross-tenant invoice", cost=0.2, risk=0.3,
        gain_estimate=0.5, rationale="seeded from deep finding"))
    return state


def test_state_roundtrip_preserves_everything():
    state = _state()
    state.round = 3
    state.add_evidence(EvidenceItem(
        evidence_id="ev-1", kind=EvidenceKind.SUPPORTING,
        source="causal_guard", ref="e-1", summary="bypass observed",
        round=3))
    state.record_decision(DecisionRecord(
        round=3, action=DecisionAction.SELECT, selected_experiment_id="e-1",
        scores={"e-1": 0.9}, alternatives=(("e-1", 0.9),),
        rationale="highest information gain"))
    restored = InvestigationState.from_dict(json.loads(
        json.dumps(state.to_dict())))
    assert restored.round == 3
    assert restored.hypotheses[0].hypothesis_id == "h-1"
    assert restored.experiments[0].experiment_id == "e-1"
    assert restored.evidence[0].kind is EvidenceKind.SUPPORTING
    assert restored.decisions[0].action is DecisionAction.SELECT
    assert restored.decisions[0].scores == {"e-1": 0.9}


def test_resume_from_checkpoint_continues_round():
    state = _state()
    state.round = 5
    restored = InvestigationState.from_dict(state.to_dict())
    assert restored.round == 5
    assert restored.engagement_id == "eng-1"
    assert restored.pending_experiments()[0].experiment_id == "e-1"
    assert restored.terminal_reason == ""


def test_unresolved_and_pending_helpers():
    state = _state()
    assert [h.hypothesis_id for h in state.unresolved_hypotheses()] == ["h-1"]
    assert [e.experiment_id for e in state.pending_experiments()] == ["e-1"]
    state.mark_experiment_outcome("e-1", "confirmed")
    assert state.pending_experiments() == []
    assert state.experiment_outcome("e-1") == "confirmed"


def test_status_update_keeps_history_sorted():
    state = _state()
    state.set_hypothesis_status("h-1", HypothesisStatus.CONFIRMED)
    assert state.hypotheses[0].status is HypothesisStatus.CONFIRMED
    assert state.unresolved_hypotheses() == []


def test_decision_record_dict_is_deterministic():
    record = DecisionRecord(
        round=1, action=DecisionAction.SELECT, selected_experiment_id="e-1",
        scores={"e-1": 0.5, "e-2": 0.4}, alternatives=(("e-2", 0.4),),
        rationale="gain")
    first = record.to_dict()
    second = DecisionRecord(
        round=1, action=DecisionAction.SELECT, selected_experiment_id="e-1",
        scores={"e-1": 0.5, "e-2": 0.4}, alternatives=(("e-2", 0.4),),
        rationale="gain").to_dict()
    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(
        second, sort_keys=True)
