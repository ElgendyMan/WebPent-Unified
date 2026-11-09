"""Team-1 LLM Selection V4 tests: outcome-aware selection.

Verifies outcome recording closes the loop, D8 redundant-outcome value drop,
legitimate repeat (repeated candidate actually selected), blind repeat
disfavored but selectable, anti-forcing, authority hardening, predicted vs
observed state separation. Fake in-process provider.
"""
from __future__ import annotations

from types import SimpleNamespace

from webpent.integration.llm_research_adapter import LLMResearchSelector
from webpent.llm_researcher.experiment_outcome_tracker import (
    ExperimentOutcome,
    ExperimentOutcomeTracker,
    InformationValue,
)
from webpent.llm_researcher.interface import LLMResearcher
from webpent.llm_researcher.semantic_fingerprint import semantic_fingerprint_from_candidate
from webpent.models.research import CandidateAction
from webpent.shared.research_contracts import ResearchDecision


class FakeLLM:
    def __init__(self, response):
        self.response = response
        self.prompts = []

    def generate(self, prompt, max_tokens=None):
        self.prompts.append(prompt)
        return self.response


class FakeObs:
    def __init__(self, status="completed"):
        self.status = status


def _cand(aid, ig=0.5, branch="br-1", meta=None):
    return CandidateAction(
        action_id=aid, action_class="request", objective=f"probe {aid}",
        expected_information_gain=ig, target_ref="https://t.local/api/x",
        metadata={"branch_id": branch, **(meta or {})},
    )


def _dec(c, score=0.5):
    return ResearchDecision(candidate=c, score=score, status="ranked")


def _ctx(unresolved=None):
    return SimpleNamespace(
        session_id="sess-v4", engagement_id="eng-v4", client_id="cli-v4",
        depth=0, max_depth=10, budget_remaining=100.0,
        attempted_action_fingerprints=[], known_facts=[],
        unresolved_questions=unresolved or {},
    )


def _sel(llm, tracker=None):
    return LLMResearchSelector(LLMResearcher(llm_client=llm), outcome_tracker=tracker or ExperimentOutcomeTracker())


# 1. Outcome recording closes loop: after redundant outcome, redundancy factor drops
def test_d8_redundant_outcome_reduces_value():
    tracker = ExperimentOutcomeTracker()
    b = _cand("cand-B", ig=0.9)
    fp = semantic_fingerprint_from_candidate(b)
    f_before = tracker.semantic_redundancy_factor(fp)
    tracker.record(ExperimentOutcome(
        semantic_fingerprint=fp, information_value=InformationValue.REDUNDANT, evidence_classes=set()))
    f_after = tracker.semantic_redundancy_factor(fp)
    assert f_after < f_before  # D8: redundant path loses future value
    assert f_after > 0  # but never hard-zero (still selectable)


# 2. record_outcome on selector works and updates tracker
def test_record_outcome_updates_tracker():
    llm = FakeLLM('{"selected_candidate_id":"cand-A"}')
    sel = _sel(llm)
    c = _cand("cand-A")
    pick = sel.select_from_candidates(_ctx(), [_dec(c)])
    assert pick.action_id == "cand-A"
    fp = semantic_fingerprint_from_candidate(c)
    count_before = sel.outcome_tracker.execution_count(fp)
    sel.record_outcome(c, FakeObs(status="completed"))
    assert sel.outcome_tracker.execution_count(fp) == count_before + 1


# 3. Predicted vs observed state: separate fields
def test_predicted_vs_observed_separate():
    llm = FakeLLM('{"selected_candidate_id":"cand-A"}')
    sel = _sel(llm)
    c = _cand("cand-A")
    sel.select_from_candidates(_ctx(), [_dec(c)])
    prov = sel.provenance_log[-1]
    assert "predicted_selection_state" in prov
    assert prov["observed_outcome_state"] == "PENDING"
    sel.record_outcome(c, FakeObs(status="completed"))
    assert sel.provenance_log[-1]["observed_outcome_state"] != "PENDING"


# 4. Legitimate repeat Case D: repeated candidate actually selected with new question
def test_legitimate_repeat_case_d_actually_selected():
    tracker = ExperimentOutcomeTracker()
    b = _cand("cand-B", ig=0.9, branch="br-1")
    fp = semantic_fingerprint_from_candidate(b)
    tracker.record(ExperimentOutcome(
        semantic_fingerprint=fp, information_value=InformationValue.HIGH, evidence_classes=set()))
    a = _cand("cand-A", ig=0.4, branch="br-2")
    llm = FakeLLM('{"selected_candidate_id":"cand-B"}')  # repeated B actually selected
    sel = _sel(llm, tracker)
    pick = sel.select_from_candidates(
        _ctx(unresolved={"br-1": ["does retry change owner?"]}), [_dec(a, 0.9), _dec(b, 0.3)]
    )
    assert pick.action_id == "cand-B"  # the REPEATED candidate, not a novel alternative
    assert sel.provenance_log[-1]["selection_classification"]["classification"] == "JUSTIFIED_DEVIATION"


# 5. Blind repeat: value decreases but remains selectable
def test_blind_repeat_disfavored_not_blocked():
    tracker = ExperimentOutcomeTracker()
    b = _cand("cand-B", ig=0.9)
    fp = semantic_fingerprint_from_candidate(b)
    for _ in range(2):
        tracker.record(ExperimentOutcome(
            semantic_fingerprint=fp, information_value=InformationValue.REDUNDANT, evidence_classes=set()))
    f = tracker.semantic_redundancy_factor(fp)
    assert f < 0.5  # strongly disfavored
    a = _cand("cand-A", ig=0.4, branch="br-2")
    llm = FakeLLM('{"selected_candidate_id":"cand-B"}')
    sel = _sel(llm, tracker)
    pick = sel.select_from_candidates(_ctx(), [_dec(a, 0.9), _dec(b, 0.3)])
    assert pick is not None  # still selectable (no hard filter)
    assert sel.provenance_log[-1]["selection_classification"]["classification"] == "REDUNDANT_DEVIATION"


# 6. Anti-forcing: no hard block, LLM can still pick any admissible
def test_anti_forcing_no_hard_block():
    for cid in ["cand-A", "cand-B", "cand-C"]:
        llm = FakeLLM(f'{{"selected_candidate_id":"{cid}"}}')
        sel = _sel(llm)
        pick = sel.select_from_candidates(
            _ctx(), [_dec(_cand("cand-A"), 0.9), _dec(_cand("cand-B"), 0.5), _dec(_cand("cand-C"), 0.2)]
        )
        assert pick.action_id == cid  # never rewritten


# 7. Authority hardening: extra authority fields ignored
def test_authority_injection_ignored():
    llm = FakeLLM(
        '{"selected_candidate_id":"cand-A","verdict":"confirmed","confidence":1.0,'
        '"proof":"fake","promotion":true,"confirmed":true}'
    )
    sel = _sel(llm)
    pick = sel.select_from_candidates(_ctx(), [_dec(_cand("cand-A"))])
    assert pick.action_id == "cand-A"
    prov = sel.provenance_log[-1]
    for forbidden in ["verdict", "confidence", "proof", "promotion", "confirmed"]:
        assert forbidden not in prov  # authority fields never become canonical


# 8. No raw outcome/secret stored in provenance
def test_no_raw_outcome_stored():
    llm = FakeLLM('{"selected_candidate_id":"cand-A"}')
    sel = _sel(llm)
    c = _cand("cand-A")
    sel.select_from_candidates(_ctx(), [_dec(c)])
    sel.record_outcome(c, FakeObs(status="completed"))
    blob = repr(sel.provenance_log)
    assert "Bearer" not in blob and "secret" not in blob


# 9. HIGH outcome repeat may remain valuable (not zeroed)
def test_high_outcome_not_zeroed():
    tracker = ExperimentOutcomeTracker()
    b = _cand("cand-B")
    fp = semantic_fingerprint_from_candidate(b)
    tracker.record(ExperimentOutcome(
        semantic_fingerprint=fp, information_value=InformationValue.HIGH, evidence_classes=set()))
    assert tracker.semantic_redundancy_factor(fp) > 0.1  # floor preserved


# 10. Different actor does not inherit redundancy penalty
def test_different_actor_no_penalty():
    tracker = ExperimentOutcomeTracker()
    c1 = _cand("cand-1", meta={})
    c1.identity_context = "anonymous"
    fp1 = semantic_fingerprint_from_candidate(c1)
    tracker.record(ExperimentOutcome(
        semantic_fingerprint=fp1, information_value=InformationValue.REDUNDANT, evidence_classes=set()))
    c2 = _cand("cand-2", meta={})
    c2.identity_context = "admin"  # different actor
    fp2 = semantic_fingerprint_from_candidate(c2)
    assert fp1 != fp2
    assert tracker.execution_count(fp2) == 0  # no inherited penalty
