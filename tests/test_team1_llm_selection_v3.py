"""Team-1 LLM Selection V3 tests: useful novelty vs blind risk aversion.

Verifies 3-dimension context, derived labels, 5-class classification,
legitimate repeats preserved, blind repeat disfavored (not hard-rejected),
context sanitization. Fake in-process provider.
"""
from __future__ import annotations

from types import SimpleNamespace

from webpent.integration.llm_research_adapter import (
    LLMResearchSelector,
    _justification_class,
    _path_shape,
    _redundancy_class,
)
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


def _cand(aid, ig=0.5, branch="br-1", actor="anonymous", method="GET", meta=None):
    return CandidateAction(
        action_id=aid, action_class="request", objective=f"probe {aid}",
        expected_information_gain=ig, method=method,
        target_ref="https://t.local/api/orders/123", identity_context=actor,
        metadata={"branch_id": branch, **(meta or {})},
    )


def _dec(c, score=0.5):
    return ResearchDecision(candidate=c, score=score, status="ranked")


def _ctx(unresolved=None):
    return SimpleNamespace(
        session_id="sess-v3", engagement_id="eng-v3", client_id="cli-v3",
        depth=0, max_depth=10, budget_remaining=100.0,
        attempted_action_fingerprints=[], known_facts=[],
        unresolved_questions=unresolved or {},
    )


def _sel(llm, tracker=None):
    return LLMResearchSelector(LLMResearcher(llm_client=llm), outcome_tracker=tracker or ExperimentOutcomeTracker())


def _record(tracker, cand, info=InformationValue.HIGH):
    fp = semantic_fingerprint_from_candidate(cand)
    tracker.record(ExperimentOutcome(
        semantic_fingerprint=fp, information_value=info, evidence_classes=set()))


# 1. D7 fixture: B (redundant, high IG) without justification -> REDUNDANT_DEVIATION but selectable
def test_d7_blind_repeat_disfavored_not_rejected():
    tracker = ExperimentOutcomeTracker()
    b = _cand("cand-B", ig=0.9)
    _record(tracker, b)  # previously executed, informative
    a = _cand("cand-A", ig=0.4, branch="br-2")
    llm = FakeLLM('{"selected_candidate_id":"cand-B"}')
    sel = _sel(llm, tracker)
    pick = sel.select_from_candidates(_ctx(), [_dec(a, 0.9), _dec(b, 0.3)])
    assert pick is not None and pick.action_id == "cand-B"  # NOT hard-rejected
    cls = sel.provenance_log[-1]["selection_classification"]["classification"]
    assert cls == "REDUNDANT_DEVIATION"  # but correctly flagged


# 2. Legitimate repeat: actor variant -> JUSTIFIED_DEVIATION
def test_legitimate_repeat_actor_variant():
    tracker = ExperimentOutcomeTracker()
    b = _cand("cand-B", ig=0.9, meta={"actor_variant": True})
    _record(tracker, b)
    a = _cand("cand-A", ig=0.4, branch="br-2")
    llm = FakeLLM('{"selected_candidate_id":"cand-B"}')
    sel = _sel(llm, tracker)
    sel.select_from_candidates(_ctx(), [_dec(a, 0.9), _dec(b, 0.3)])
    assert sel.provenance_log[-1]["selection_classification"]["classification"] == "JUSTIFIED_DEVIATION"


# 3. Legitimate repeat: parameter variant -> JUSTIFIED_DEVIATION
def test_legitimate_repeat_parameter_variant():
    tracker = ExperimentOutcomeTracker()
    b = _cand("cand-B", ig=0.9, meta={"parameter_variant": True})
    _record(tracker, b)
    a = _cand("cand-A", ig=0.4, branch="br-2")
    llm = FakeLLM('{"selected_candidate_id":"cand-B"}')
    sel = _sel(llm, tracker)
    sel.select_from_candidates(_ctx(), [_dec(a, 0.9), _dec(b, 0.3)])
    assert sel.provenance_log[-1]["selection_classification"]["classification"] == "JUSTIFIED_DEVIATION"


# 4. Legitimate repeat: independent control -> JUSTIFIED_DEVIATION
def test_legitimate_repeat_control():
    tracker = ExperimentOutcomeTracker()
    b = _cand("cand-B", ig=0.9, meta={"independent_control": True})
    _record(tracker, b)
    a = _cand("cand-A", ig=0.4, branch="br-2")
    llm = FakeLLM('{"selected_candidate_id":"cand-B"}')
    sel = _sel(llm, tracker)
    sel.select_from_candidates(_ctx(), [_dec(a, 0.9), _dec(b, 0.3)])
    assert sel.provenance_log[-1]["selection_classification"]["classification"] == "JUSTIFIED_DEVIATION"


# 5. Legitimate repeat: new unresolved question -> JUSTIFIED_DEVIATION
def test_legitimate_repeat_new_question():
    tracker = ExperimentOutcomeTracker()
    b = _cand("cand-B", ig=0.9, branch="br-1")
    _record(tracker, b)
    a = _cand("cand-A", ig=0.4, branch="br-2")
    llm = FakeLLM('{"selected_candidate_id":"cand-B"}')
    sel = _sel(llm, tracker)
    sel.select_from_candidates(
        _ctx(unresolved={"br-1": ["does owner change after retry?"]}), [_dec(a, 0.9), _dec(b, 0.3)]
    )
    assert sel.provenance_log[-1]["selection_classification"]["classification"] == "JUSTIFIED_DEVIATION"


# 6. Context sanitization: raw path/auth never in prompt; structural shape present
def test_context_sanitization():
    llm = FakeLLM('{"selected_candidate_id":"cand-A"}')
    sel = _sel(llm)
    c = CandidateAction(
        action_id="cand-A", action_class="request", objective="probe",
        target_ref="https://secret-host.internal/api/orders/999?token=abc",
        identity_context="admin", metadata={"branch_id": "br-1", "authorization": "Bearer xyz"},
    )
    sel.select_from_candidates(_ctx(), [_dec(c)])
    prompt = llm.prompts[0]
    assert "secret-host" not in prompt
    assert "999" not in prompt
    assert "token=abc" not in prompt
    assert "Bearer" not in prompt
    assert "path_shape" in prompt
    assert "has_auth" in prompt
    assert "{id}" in prompt  # structural shape


# 7. Redundancy class labels derived correctly
def test_redundancy_class_labels():
    assert _redundancy_class(1.0, 0) == "NOVEL"
    assert _redundancy_class(0.9, 1) == "LOW_REDUNDANCY"
    assert _redundancy_class(0.6, 1) == "MODERATE_REDUNDANCY"
    assert _redundancy_class(0.3, 2) == "HIGH_REDUNDANCY"


# 8. Justification class: no justification -> NO_NEW_JUSTIFICATION
def test_justification_class():
    c = _cand("cand-X")
    assert _justification_class(c, [], 1) == "NO_NEW_JUSTIFICATION"
    assert _justification_class(c, ["q1?"], 1) == "NEW_QUESTION"


# 9. Path shape sanitizes numeric segments
def test_path_shape():
    assert "{id}" in _path_shape("https://h/api/orders/123")
    assert "<host>" in _path_shape("https://h/api/x")


# 10. No hard filter: HIGH_REDUNDANCY candidate still selectable (no blanket ban)
def test_no_blanket_repetition_ban():
    tracker = ExperimentOutcomeTracker()
    b = _cand("cand-B", ig=0.9)
    for _ in range(3):
        _record(tracker, b)  # highly redundant
    a = _cand("cand-A", ig=0.4, branch="br-2")
    llm = FakeLLM('{"selected_candidate_id":"cand-B"}')
    sel = _sel(llm, tracker)
    pick = sel.select_from_candidates(_ctx(), [_dec(a, 0.9), _dec(b, 0.3)])
    assert pick is not None  # never hard-rejected
    assert sel.provenance_log[-1]["selection_classification"]["classification"] == "REDUNDANT_DEVIATION"


# 11. Prompt explicitly warns against blind risk aversion
def test_prompt_anti_risk_aversion():
    llm = FakeLLM('{"selected_candidate_id":"cand-A"}')
    sel = _sel(llm)
    sel.select_from_candidates(_ctx(), [_dec(_cand("cand-A"))])
    prompt = llm.prompts[0]
    assert "JUSTIFIED REPEAT = ALLOWED" in prompt
    assert "BLIND REPEAT" in prompt
    assert "Do NOT automatically avoid HIGH_REDUNDANCY" in prompt
