"""Team-1 V6 Closeout tests: portfolio value signal makes reactivation visible.

Verifies A->sat->B->HIGH->A candidate value increases (adjusted_utility),
counterfactual with/without signal, no forcing. Fake in-process.
"""
from __future__ import annotations

from types import SimpleNamespace

from webpent.integration.hypothesis_portfolio import HypothesisPortfolio
from webpent.integration.llm_research_adapter import LLMResearchSelector
from webpent.llm_researcher.interface import LLMResearcher
from webpent.models.research import CandidateAction
from webpent.shared.research_contracts import ResearchDecision


class FakeLLM:
    def __init__(self, response):
        self.response = response
        self.prompts = []

    def generate(self, prompt, max_tokens=None):
        self.prompts.append(prompt)
        return self.response


def _cand(aid, branch="br-A"):
    return CandidateAction(
        action_id=aid, action_class="request", objective=f"probe {aid}",
        metadata={"branch_id": branch},
    )


def _dec(c, score=0.5):
    return ResearchDecision(candidate=c, score=score, status="ranked")


def _ctx():
    return SimpleNamespace(
        session_id="s", engagement_id="e", client_id="c", depth=0, max_depth=10,
        budget_remaining=100.0, attempted_action_fingerprints=[], known_facts=[],
        unresolved_questions={},
    )


def _extract_adjusted_utility(prompt, candidate_id):
    import re
    for block in prompt.split("candidate_id"):
        if candidate_id in block:
            m = re.search(r'"adjusted_utility":\s*([0-9.]+)', block)
            if m:
                return float(m.group(1))
    return None


# Phase 3: A saturates -> B HIGH -> A pressure decreases, exploitation increases, adjusted_utility increases
def test_reactivation_visible_in_candidate_value():
    llm = FakeLLM('{"selected_candidate_id":"cand-A"}')
    sel = LLMResearchSelector(LLMResearcher(llm_client=llm))
    # A saturates
    for _ in range(4):
        sel.portfolio.record_branch_outcome("br-A", "LOW", 0)
    sel.select_from_candidates(_ctx(), [_dec(_cand("cand-A", "br-A"), 0.9)])
    util_before = _extract_adjusted_utility(llm.prompts[-1], "cand-A")
    # B produces HIGH -> A reactivates
    sel.portfolio.record_branch_outcome("br-B", "HIGH", 2)
    llm2 = FakeLLM('{"selected_candidate_id":"cand-A"}')
    sel.researcher = LLMResearcher(llm_client=llm2)
    sel.select_from_candidates(_ctx(), [_dec(_cand("cand-A", "br-A"), 0.9)])
    util_after = _extract_adjusted_utility(llm2.prompts[-1], "cand-A")
    assert util_after is not None and util_before is not None
    assert util_after > util_before  # A's candidate value increased (visible)


# Counterfactual: with signal, adjusted_utility differs from raw deterministic
def test_counterfactual_signal_changes_visible_value():
    llm = FakeLLM('{"selected_candidate_id":"cand-A"}')
    sel = LLMResearchSelector(LLMResearcher(llm_client=llm))
    sel.portfolio.record_branch_outcome("br-A", "HIGH", 3)  # high exploitation
    sel.select_from_candidates(_ctx(), [_dec(_cand("cand-A", "br-A"), 0.5)])
    adj = _extract_adjusted_utility(llm.prompts[-1], "cand-A")
    assert adj is not None
    assert adj != 0.5  # adjusted differs from raw deterministic (signal visible)


# B still selectable after A reactivation (no forcing)
def test_b_still_selectable():
    llm = FakeLLM('{"selected_candidate_id":"cand-B"}')
    sel = LLMResearchSelector(LLMResearcher(llm_client=llm))
    sel.portfolio.record_branch_outcome("br-B", "HIGH", 2)
    pick = sel.select_from_candidates(_ctx(), [
        _dec(_cand("cand-A", "br-A"), 0.9), _dec(_cand("cand-B", "br-B"), 0.5)])
    assert pick.action_id == "cand-B"


# LOW evidence does NOT trigger reactivation
def test_low_does_not_reactivate():
    p = HypothesisPortfolio()
    for _ in range(4):
        p.record_branch_outcome("br-A", "LOW", 0)
    before = p.branch_signal("br-A")["exploration_pressure"]
    p.record_branch_outcome("br-B", "LOW", 0)
    assert p.branch_signal("br-A")["exploration_pressure"] == before


# No branch hard-selected: both remain admissible
def test_no_hard_selection():
    for cid in ["cand-A", "cand-B", "cand-C"]:
        llm = FakeLLM(f'{{"selected_candidate_id":"{cid}"}}')
        sel = LLMResearchSelector(LLMResearcher(llm_client=llm))
        pick = sel.select_from_candidates(_ctx(), [
            _dec(_cand("cand-A", "br-A")), _dec(_cand("cand-B", "br-B")), _dec(_cand("cand-C", "br-C"))])
        assert pick.action_id == cid


# portfolio_value_signal present in prompt
def test_portfolio_value_signal_in_prompt():
    llm = FakeLLM('{"selected_candidate_id":"cand-A"}')
    sel = LLMResearchSelector(LLMResearcher(llm_client=llm))
    sel.select_from_candidates(_ctx(), [_dec(_cand("cand-A", "br-A"))])
    assert "portfolio_value_signal" in llm.prompts[0]
    assert "adjusted_utility" in llm.prompts[0]


# No forcing mechanism in source
def test_no_forcing_in_source():
    src = open("src/webpent/integration/llm_research_adapter.py").read()
    for forbidden in ["force_return", "return_after", "always_return", "round_robin", "branch_rotation"]:
        assert forbidden not in src
