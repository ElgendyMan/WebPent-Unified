"""Team-1 Hypothesis Portfolio / Exploration vs Exploitation tests (V5).

Deterministic unit tests A-I + long-horizon synthetic. No real target.
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


def _cand(aid, branch="br-1", ig=0.5):
    return CandidateAction(
        action_id=aid, action_class="request", objective=f"probe {aid}",
        expected_information_gain=ig, metadata={"branch_id": branch},
    )


def _dec(c, score=0.5):
    return ResearchDecision(candidate=c, score=score, status="ranked")


def _ctx():
    return SimpleNamespace(
        session_id="s", engagement_id="e", client_id="c", depth=0, max_depth=10,
        budget_remaining=100.0, attempted_action_fingerprints=[], known_facts=[],
        unresolved_questions={},
    )


# A. Strong productive branch remains attractive
def test_strong_branch_remains_attractive():
    p = HypothesisPortfolio()
    p.record_branch_outcome("br-hot", "HIGH", new_question_count=3)
    sig = p.branch_signal("br-hot")
    assert sig["exploitation_value"] > 0.5
    assert sig["saturation_state"] == "ACTIVE"


# B. Strong branch with repeated LOW outcomes loses value (exploration pressure rises)
def test_repeated_low_outcomes_saturate():
    p = HypothesisPortfolio()
    for _ in range(4):
        p.record_branch_outcome("br-hot", "LOW", new_question_count=0)
    sig = p.branch_signal("br-hot")
    assert sig["exploration_pressure"] > 0.5
    assert sig["saturation_state"] in {"SATURATING", "SATURATED"}
    assert sig["exploitation_value"] < 0.5


# C. Strong branch with unresolved question can legitimately repeat
def test_unresolved_question_allows_repeat():
    p = HypothesisPortfolio()
    p.record_branch_outcome("br-hot", "HIGH", new_question_count=2)
    sig = p.branch_signal("br-hot")
    assert sig["unresolved_question_count"] == 2
    assert sig["exploration_pressure"] < 0.5  # not forced away


# D. Weak branch can recover after positive evidence
def test_weak_branch_recovers():
    p = HypothesisPortfolio()
    p.record_branch_outcome("br-cold", "LOW", 0)
    low = p.branch_signal("br-cold")["exploitation_value"]
    p.record_branch_outcome("br-cold", "HIGH", 2)
    high = p.branch_signal("br-cold")["exploitation_value"]
    assert high > low


# E. Alternative branch gains exploration pressure when main saturates
def test_alternative_gains_exploration_pressure():
    p = HypothesisPortfolio()
    for _ in range(4):
        p.record_branch_outcome("br-main", "LOW", 0)
    main_pressure = p.branch_signal("br-main")["exploration_pressure"]
    alt_pressure = p.branch_signal("br-alt")["exploration_pressure"]
    assert main_pressure > alt_pressure  # main saturated; alt remains open


# F. Multiple branches coexist
def test_multiple_branches_coexist():
    p = HypothesisPortfolio()
    p.record_branch_outcome("br-a", "HIGH", 1)
    p.record_branch_outcome("br-b", "MEDIUM", 1)
    p.record_branch_outcome("br-c", "LOW", 0)
    assert len(p.all_branches()) == 3


# G. No branch hard-filtered: LLM can select any candidate
def test_no_branch_hard_filtered():
    for branch in ["br-a", "br-b", "br-c"]:
        llm = FakeLLM(f'{{"selected_candidate_id":"cand-{branch}"}}')
        sel = LLMResearchSelector(LLMResearcher(llm_client=llm))
        pick = sel.select_from_candidates(_ctx(), [
            _dec(_cand("cand-br-a", "br-a")),
            _dec(_cand("cand-br-b", "br-b")),
            _dec(_cand("cand-br-c", "br-c")),
        ])
        assert pick.action_id == f"cand-{branch}"  # never hard-blocked


# H. No second scheduler: single portfolio object per selector
def test_single_portfolio_authority():
    sel = LLMResearchSelector(LLMResearcher(llm_client=FakeLLM('{"selected_candidate_id":"x"}')))
    assert hasattr(sel, "portfolio")
    assert isinstance(sel.portfolio, HypothesisPortfolio)


# I. LLM authority remains candidate selection only (extra fields ignored)
def test_llm_authority_candidate_only():
    llm = FakeLLM('{"selected_candidate_id":"cand-br-a","switch_branch":true,"explore":true}')
    sel = LLMResearchSelector(LLMResearcher(llm_client=llm))
    pick = sel.select_from_candidates(_ctx(), [_dec(_cand("cand-br-a", "br-a"))])
    assert pick.action_id == "cand-br-a"
    prov = sel.provenance_log[-1]
    assert "switch_branch" not in prov and "explore" not in prov


# Long-horizon synthetic: 3 branches, dominant -> saturation -> alternative open
def test_long_horizon_synthetic():
    p = HypothesisPortfolio()
    # Phase 1: br-main dominant and productive
    for _ in range(2):
        p.record_branch_outcome("br-main", "HIGH", 3)
    assert p.branch_signal("br-main")["saturation_state"] == "ACTIVE"
    # Phase 2: br-main saturates (repeated LOW, no questions)
    for _ in range(4):
        p.record_branch_outcome("br-main", "LOW", 0)
    main_sig = p.branch_signal("br-main")
    assert main_sig["saturation_state"] in {"SATURATING", "SATURATED"}
    assert main_sig["exploration_pressure"] > 0.5
    # Phase 3: alternative branch br-alt remains open (low pressure)
    alt_sig = p.branch_signal("br-alt")
    assert alt_sig["exploration_pressure"] < main_sig["exploration_pressure"]
    # No branch deleted
    assert len(p.all_branches()) >= 2


# Branch portfolio signal exposed to LLM in prompt
def test_portfolio_signal_in_prompt():
    llm = FakeLLM('{"selected_candidate_id":"cand-br-a"}')
    sel = LLMResearchSelector(LLMResearcher(llm_client=llm))
    sel.select_from_candidates(_ctx(), [_dec(_cand("cand-br-a", "br-a"))])
    assert "branch_portfolio_signal" in llm.prompts[0]
    assert "exploration_pressure" in llm.prompts[0]
