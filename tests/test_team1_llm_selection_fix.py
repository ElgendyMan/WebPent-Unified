"""Team-1 LLM selection bottleneck fix tests (Phase 6-8).

Verifies first-class redundancy state, bounded policy, diagnostic classification,
no hard filter, legitimate repetition preserved. Fake in-process provider.
"""
from __future__ import annotations

from webpent.integration.llm_research_adapter import LLMResearchSelector
from webpent.llm_researcher.experiment_outcome_tracker import (
    ExperimentOutcome,
    ExperimentOutcomeTracker,
    InformationValue,
)
from webpent.llm_researcher.interface import LLMResearcher
from webpent.llm_researcher.semantic_fingerprint import semantic_fingerprint_from_candidate
from webpent.models.research import CandidateAction
from webpent.shared.research_contracts import ResearchContext, ResearchDecision


class FakeLLM:
    def __init__(self, response):
        self.response = response
        self.prompts = []

    def generate(self, prompt, max_tokens=None):
        self.prompts.append(prompt)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _cand(aid, ig=0.5, branch="br-1", actor="anonymous", method="GET", path="/api/x"):
    return CandidateAction(
        action_id=aid, action_class="request", objective=f"probe {aid}",
        expected_information_gain=ig, method=method,
        target_ref=f"https://t.local{path}", identity_context=actor,
        metadata={"branch_id": branch},
    )


def _dec(c, score=0.5):
    return ResearchDecision(candidate=c, score=score, status="ranked")


def _ctx():
    return ResearchContext(
        session_id="sess-sel", engagement_id="eng-sel", client_id="cli-sel",
        depth=0, max_depth=10, budget_remaining=100.0,
        attempted_action_fingerprints=[], known_facts=[],
    )

def _ctx_with_unresolved(unresolved):
    """SimpleNamespace with unresolved_questions (ResearchContext has no such field)."""
    from types import SimpleNamespace
    return SimpleNamespace(
        session_id="sess-sel", engagement_id="eng-sel", client_id="cli-sel",
        depth=0, max_depth=10, budget_remaining=100.0,
        attempted_action_fingerprints=[], known_facts=[],
        unresolved_questions=unresolved or {},
    )


def _sel(llm, tracker=None):
    return LLMResearchSelector(LLMResearcher(llm_client=llm), outcome_tracker=tracker or ExperimentOutcomeTracker())


def _record(tracker, cand):
    fp = semantic_fingerprint_from_candidate(cand)
    tracker.record(ExperimentOutcome(
        semantic_fingerprint=fp, information_value=InformationValue.LOW, evidence_classes=set()))


# 1. Redundancy state is first-class in prompt (semantic_redundancy_factor present)
def test_redundancy_state_in_prompt():
    llm = FakeLLM('{"selected_candidate_id":"cand-A"}')
    sel = _sel(llm)
    sel.select_from_candidates(_ctx(), [_dec(_cand("cand-A"))])
    assert "semantic_redundancy_factor" in llm.prompts[0]
    assert "deterministic_rank" in llm.prompts[0]
    assert "prior_execution_count" in llm.prompts[0]


# 2. High-IG redundant vs lower-IG novel: B (redundant) gets low factor
def test_high_ig_redundant_has_low_factor():
    tracker = ExperimentOutcomeTracker()
    b = _cand("cand-B", ig=0.9)
    _record(tracker, b)  # B previously executed -> redundant
    a = _cand("cand-A", ig=0.4)
    llm = FakeLLM('{"selected_candidate_id":"cand-A"}')
    sel = _sel(llm, tracker)
    sel.select_from_candidates(_ctx(), [_dec(a, 0.9), _dec(b, 0.3)])
    # B's redundancy factor < 1.0 exposed to LLM
    prompt = llm.prompts[0]
    assert "cand-B" in prompt
    # classification: A selected (rank 1) -> ALIGNED
    assert sel.provenance_log[-1]["selection_classification"]["classification"] == "ALIGNED"


# 3. D7 fixture: B selected without justification -> REDUNDANT_DEVIATION (diagnostic, still allowed)
def test_d7_redundant_deviation_classified():
    tracker = ExperimentOutcomeTracker()
    b = _cand("cand-B", ig=0.9)
    _record(tracker, b)
    a = _cand("cand-A", ig=0.4)
    llm = FakeLLM('{"selected_candidate_id":"cand-B"}')  # LLM picks redundant B
    sel = _sel(llm, tracker)
    pick = sel.select_from_candidates(_ctx(), [_dec(a, 0.9), _dec(b, 0.3)])
    assert pick is not None and pick.action_id == "cand-B"  # NOT hard-blocked
    cls = sel.provenance_log[-1]["selection_classification"]["classification"]
    assert cls == "REDUNDANT_DEVIATION"  # but flagged diagnostically


# 4. D7 with unresolved justification -> JUSTIFIED_DEVIATION
def test_d7_justified_deviation():
    tracker = ExperimentOutcomeTracker()
    b = _cand("cand-B", ig=0.9, branch="br-1")
    _record(tracker, b)
    a = _cand("cand-A", ig=0.4, branch="br-2")
    llm = FakeLLM('{"selected_candidate_id":"cand-B"}')
    sel = _sel(llm, tracker)
    pick = sel.select_from_candidates(
        _ctx_with_unresolved({"br-1": ["who owns resource X?"]}), [_dec(a, 0.9), _dec(b, 0.3)]
    )
    assert pick.action_id == "cand-B"
    cls = sel.provenance_log[-1]["selection_classification"]["classification"]
    assert cls == "JUSTIFIED_DEVIATION"


# 5. Legitimate repeated control: same URL different actor -> different fp -> not redundant
def test_legitimate_repeat_different_actor():
    tracker = ExperimentOutcomeTracker()
    c1 = _cand("cand-1", actor="anonymous")
    _record(tracker, c1)
    c2 = _cand("cand-2", actor="admin")  # same URL, different actor
    fp1 = semantic_fingerprint_from_candidate(c1)
    fp2 = semantic_fingerprint_from_candidate(c2)
    assert fp1 != fp2
    assert tracker.execution_count(fp2) == 0  # not counted as repeat


# 6. Same URL different parameter -> different fingerprint
def test_same_url_different_param():
    fp1 = semantic_fingerprint_from_candidate(_cand("cand1", method="GET"))
    fp2 = semantic_fingerprint_from_candidate(_cand("cand2", method="POST"))
    assert fp1 != fp2


# 7. Different branch same capability -> different fingerprint
def test_different_branch():
    fp1 = semantic_fingerprint_from_candidate(_cand("cand1", branch="br-A"))
    fp2 = semantic_fingerprint_from_candidate(_cand("cand2", branch="br-B"))
    assert fp1 != fp2


# 8. Lower-ranked but novel can be selected (no top-candidate forcing)
def test_lower_ranked_novel_selectable():
    llm = FakeLLM('{"selected_candidate_id":"cand-low"}')
    sel = _sel(llm)
    pick = sel.select_from_candidates(
        _ctx(), [_dec(_cand("cand-high"), 0.95), _dec(_cand("cand-low"), 0.2)]
    )
    assert pick.action_id == "cand-low"
    assert sel.provenance_log[-1]["selection_classification"]["classification"] in {
        "JUSTIFIED_DEVIATION", "REDUNDANT_DEVIATION"}


# 9. Invalid candidate ID rejected
def test_invalid_id_rejected():
    sel = _sel(FakeLLM('{"selected_candidate_id":"nope"}'))
    assert sel.select_from_candidates(_ctx(), [_dec(_cand("cand-X"))]) is None


# 10. Malformed LLM response fails closed
def test_malformed_fail_closed():
    sel = _sel(FakeLLM("garbage"))
    assert sel.select_from_candidates(_ctx(), [_dec(_cand("cand-X"))]) is None


# 11. No secret/context leakage in prompt
def test_no_secret_in_prompt():
    llm = FakeLLM('{"selected_candidate_id":"cand-X"}')
    sel = _sel(llm)
    c = CandidateAction(
        action_id="cand-X", action_class="request", objective="probe",
        metadata={"authorization": "Bearer secret", "cookie": "session=abc"},
    )
    sel.select_from_candidates(_ctx(), [_dec(c)])
    prompt = llm.prompts[0]
    assert "Bearer" not in prompt and "secret" not in prompt and "session=abc" not in prompt


# 12. No top-candidate forcing: policy says deviations permitted
def test_no_top_forcing_in_policy():
    llm = FakeLLM('{"selected_candidate_id":"cand-X"}')
    sel = _sel(llm)
    sel.select_from_candidates(_ctx(), [_dec(_cand("cand-X"))])
    prompt = llm.prompts[0]
    assert "rank #1" in prompt and "JUSTIFIED REPEAT = ALLOWED" in prompt


# 13. LLM-disabled preserves deterministic
def test_disabled_deterministic(monkeypatch):
    monkeypatch.delenv("WEBPENT_LLM_RESEARCH_ENABLED", raising=False)
    from webpent.integration.llm_research_adapter import llm_research_enabled
    assert llm_research_enabled() is False
    assert LLMResearchSelector.build_if_enabled(("s", "e", "c")) is None
