"""Team-1 candidate-selection contract tests (Phase 6 + Phase 7).

Verifies the LLM now selects by candidate_id from the admissible set (not a
tool type). Fake in-process provider. Zero real quota.
"""
from __future__ import annotations

from webpent.integration.llm_research_adapter import (
    LLMResearchSelector,
    llm_research_enabled,
)
from webpent.llm_researcher.interface import LLMResearcher
from webpent.models.research import CandidateAction
from webpent.shared.research_contracts import ResearchContext, ResearchDecision


class RecFakeLLM:
    def __init__(self, response):
        self.response = response
        self.prompts = []

    def generate(self, prompt, max_tokens=None):
        self.prompts.append(prompt)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _cand(aid, aclass="request", ig=0.5, novelty=0.5, cov=0.5):
    return CandidateAction(
        action_id=aid, action_class=aclass, objective=f"obj-{aid}",
        expected_information_gain=ig, novelty=novelty, coverage_value=cov,
    )


def _dec(c, score=0.5):
    return ResearchDecision(candidate=c, score=score, status="ranked")


def _ctx(attempted=None, facts=None):
    return ResearchContext(
        session_id="sess", engagement_id="eng", client_id="cli", depth=0, max_depth=10,
        budget_remaining=100.0, attempted_action_fingerprints=list(attempted or []),
        known_facts=list(facts or []),
    )


def _sel(llm):
    return LLMResearchSelector(LLMResearcher(llm_client=llm))


# 1. LLM receives >1 admissible candidate
def test_llm_receives_multiple_candidates():
    llm = RecFakeLLM('{"selected_candidate_id":"cand-alpha"}')
    sel = _sel(llm)
    sel.select_from_candidates(_ctx(), [_dec(_cand("cand-alpha")), _dec(_cand("cand-beta"))])
    assert sel.provenance_log[-1]["admissible_candidate_count"] == 2
    assert len(sel.provenance_log[-1]["candidate_ids_presented"]) == 2


# 2. Candidate IDs appear in decision context (the prompt)
def test_candidate_ids_in_prompt():
    llm = RecFakeLLM('{"selected_candidate_id":"cand-beta"}')
    sel = _sel(llm)
    sel.select_from_candidates(_ctx(), [_dec(_cand("cand-alpha")), _dec(_cand("cand-beta"))])
    prompt = llm.prompts[0]
    assert "cand-alpha" in prompt and "cand-beta" in prompt
    assert "ADMISSIBLE_CANDIDATES" in prompt


# 3. LLM can select candidate #2 (not the top-ranked)
def test_llm_selects_second_candidate():
    llm = RecFakeLLM('{"selected_candidate_id":"cand-beta"}')
    sel = _sel(llm)
    pick = sel.select_from_candidates(
        _ctx(), [_dec(_cand("cand-alpha"), score=0.9), _dec(_cand("cand-beta"), score=0.5)]
    )
    assert pick is not None and pick.action_id == "cand-beta"  # overrode top-ranked


# 4. Selected ID must exist in candidate set
def test_selected_id_validated():
    llm = RecFakeLLM('{"selected_candidate_id":"cand-alpha"}')
    sel = _sel(llm)
    pick = sel.select_from_candidates(_ctx(), [_dec(_cand("cand-alpha"))])
    assert pick is not None and pick.action_id == "cand-alpha"
    assert sel.provenance_log[-1]["outcome"] == "selected"


# 5. Unknown candidate ID rejected fail-closed
def test_unknown_id_rejected():
    llm = RecFakeLLM('{"selected_candidate_id":"does-not-exist"}')
    sel = _sel(llm)
    pick = sel.select_from_candidates(_ctx(), [_dec(_cand("cand-alpha"))])
    assert pick is None
    assert sel.provenance_log[-1]["outcome"] == "unknown_candidate_rejected"


# 6. Malformed LLM response fails closed
def test_malformed_fail_closed():
    llm = RecFakeLLM("not-json-at-all")
    sel = _sel(llm)
    pick = sel.select_from_candidates(_ctx(), [_dec(_cand("cand-alpha"))])
    assert pick is None
    assert sel.provenance_log[-1]["outcome"] == "malformed_rejected"


# 7. Candidate metadata / prompt contains no secrets
def test_no_secrets_in_context():
    llm = RecFakeLLM('{"selected_candidate_id":"cand-alpha"}')
    sel = _sel(llm)
    sel.select_from_candidates(
        _ctx(facts=["Bearer secret-token authorization: Basic abc"]),
        [_dec(_cand("cand-alpha"))],
    )
    prompt = llm.prompts[0]
    assert "Bearer" not in prompt
    assert "secret-token" not in prompt



# 8. LLM disabled preserves deterministic behavior
def test_disabled_deterministic(monkeypatch):
    monkeypatch.delenv("WEBPENT_LLM_RESEARCH_ENABLED", raising=False)
    assert llm_research_enabled() is False
    assert LLMResearchSelector.build_if_enabled(("s", "e", "c")) is None


# 9. ToolBoundary / deterministic gates remain authoritative: chosen always from admissible set
def test_chosen_always_from_admissible():
    for chosen in ["cand-a", "cand-b", "cand-c"]:
        llm = RecFakeLLM(f'{{"selected_candidate_id":"{chosen}"}}')
        sel = _sel(llm)
        cands = [_cand("cand-a"), _cand("cand-b"), _cand("cand-c")]
        pick = sel.select_from_candidates(_ctx(), [_dec(c) for c in cands])
        assert pick is not None
        assert pick.action_id in {c.action_id for c in cands}  # never fabricated


# 10. CausalGuard untouched: selector never imports/touches it
def test_causal_guard_untouched():
    import webpent.integration.llm_research_adapter as mod
    src = open(mod.__file__).read()
    assert "CausalGuard" not in src
    assert "guarded_causal_evaluate" not in src


# Phase 7 — adaptive-selection synthetic test (generic, no target-specific)
def test_adaptive_selection_allows_choice():
    # A: previously executed, low info gain. B: not executed, high IG. C: control.
    cand_a = _cand("cand-A", ig=0.1, novelty=0.1)
    cand_b = _cand("cand-B", ig=0.9, novelty=0.9)
    cand_c = _cand("cand-C", ig=0.5, novelty=0.5)
    attempted = {cand_a.fingerprint()}
    record = {}
    for chosen_id in ["cand-A", "cand-B", "cand-C"]:
        llm = RecFakeLLM(f'{{"selected_candidate_id":"{chosen_id}"}}')
        sel = _sel(llm)
        pick = sel.select_from_candidates(_ctx(attempted=attempted),
                                          [_dec(cand_a, 0.9), _dec(cand_b, 0.5), _dec(cand_c, 0.7)])
        assert pick is not None and pick.action_id == chosen_id
        record[chosen_id] = {
            "candidates_presented": sel.provenance_log[-1]["candidate_ids_presented"],
            "context_hash": sel.provenance_log[-1]["context_input_hash"],
            "previously_executed_A": True,
        }
    # System genuinely allows LLM to choose ANY of the three (no forced winner).
    assert len({record[k]["context_hash"] for k in record}) == 1  # same input each time
    assert all(set(record[k]["candidates_presented"]) == {"cand-A", "cand-B", "cand-C"} for k in record)
