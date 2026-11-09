"""Team-1 V6 Return-to-Exploitation tests.

Verifies: A strong -> A saturates -> B explores -> B produces useful evidence ->
A re-evaluated -> A competitive again -> A naturally selectable. No forcing.
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


# Phase 4: full lifecycle A -> saturation -> B -> useful evidence -> A competitive again
def test_return_to_exploitation_lifecycle():
    p = HypothesisPortfolio()
    # 1. A starts strong (productive)
    for _ in range(2):
        p.record_branch_outcome("br-A", "HIGH", new_question_count=3)
    assert p.branch_signal("br-A")["saturation_state"] == "ACTIVE"
    # 2. A saturates (repeated LOW, no questions)
    for _ in range(4):
        p.record_branch_outcome("br-A", "LOW", new_question_count=0)
    a_sat = p.branch_signal("br-A")
    assert a_sat["saturation_state"] in {"SATURATING", "SATURATED"}
    assert a_sat["exploration_pressure"] > 0.5
    a_exploit_before = a_sat["exploitation_value"]
    # 3. B explores and produces USEFUL evidence (HIGH)
    p.record_branch_outcome("br-B", "HIGH", new_question_count=2)
    # 4. A re-evaluated: exploration pressure decayed, exploitation value recovered
    a_after = p.branch_signal("br-A")
    assert a_after["exploration_pressure"] < a_sat["exploration_pressure"]
    assert a_after["exploitation_value"] > a_exploit_before
    assert a_after["saturation_state"] != "SATURATED"  # competitive again


# V6 re-activation only on HIGH evidence (not LOW)
def test_reactivation_only_on_high():
    p = HypothesisPortfolio()
    for _ in range(4):
        p.record_branch_outcome("br-A", "LOW", 0)
    pressure_before = p.branch_signal("br-A")["exploration_pressure"]
    p.record_branch_outcome("br-B", "LOW", 0)  # LOW does NOT re-activate
    assert p.branch_signal("br-A")["exploration_pressure"] == pressure_before


# No forcing: LLM can select A again after re-activation (naturally)
def test_a_naturally_selectable_after_reactivation():
    llm = FakeLLM('{"selected_candidate_id":"cand-A"}')
    sel = LLMResearchSelector(LLMResearcher(llm_client=llm))
    pick = sel.select_from_candidates(_ctx(), [
        _dec(_cand("cand-A", "br-A"), 0.9),
        _dec(_cand("cand-B", "br-B"), 0.5),
    ])
    assert pick.action_id == "cand-A"  # never blocked from returning


# No forcing: no rotation/round-robin logic in source
def test_no_forcing_mechanism():
    src = open("src/webpent/integration/hypothesis_portfolio.py").read()
    for forbidden in ["rotate", "round_robin", "return_after", "force_switch", "always_return"]:
        assert forbidden not in src.lower()


# Saturation still causes exploration (V5 preserved, not collapsed)
def test_exploration_preserved():
    p = HypothesisPortfolio()
    for _ in range(4):
        p.record_branch_outcome("br-A", "LOW", 0)
    assert p.branch_signal("br-A")["exploration_pressure"] > 0.5


# Multiple branches coexist and both can be selected (no hard filter)
def test_both_branches_selectable():
    for cid in ["cand-A", "cand-B"]:
        llm = FakeLLM(f'{{"selected_candidate_id":"{cid}"}}')
        sel = LLMResearchSelector(LLMResearcher(llm_client=llm))
        pick = sel.select_from_candidates(_ctx(), [
            _dec(_cand("cand-A", "br-A")), _dec(_cand("cand-B", "br-B"))])
        assert pick.action_id == cid
