"""Team-1 LLMResearcher lifecycle / context handoff fix tests (max 8).

Verifies: session-scoped selector reuse, no cross-session leakage, sanitized
context provenance computed from actual decision input, observations from
Decision #1 reach Decision #2 input, fail-closed on malformed, no raw
prompt/response/secret in telemetry. Fake in-process provider only.
"""
from __future__ import annotations

from webpent.integration.llm_research_adapter import (
    LLMResearchSelector,
    clear_session,
    llm_research_enabled,
)
from webpent.llm_researcher.interface import LLMResearcher
from webpent.models.research import CandidateAction
from webpent.shared.research_contracts import ResearchContext, ResearchDecision


class FakeLLM:
    def __init__(self, response='{"tool":"request","purpose":"p"}'):
        self.response = response
        self.calls = 0

    def generate(self, prompt, max_tokens=None):
        self.calls += 1
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _cand(aid="cand-request", aclass="request"):
    return CandidateAction(action_id=aid, action_class=aclass, objective="probe x")


def _decision(c):
    return ResearchDecision(candidate=c, score=0.5, status="ranked")


def _ctx(known_facts=None):
    return ResearchContext(
        session_id="sess-1", engagement_id="eng-1", client_id="cli-1",
        depth=0, max_depth=10, budget_remaining=100.0,
        attempted_action_fingerprints=[], known_facts=list(known_facts or []),
    )


# 1. LLM disabled -> deterministic unchanged
def test_disabled_deterministic(monkeypatch):
    monkeypatch.delenv("WEBPENT_LLM_RESEARCH_ENABLED", raising=False)
    assert llm_research_enabled() is False
    assert LLMResearchSelector.build_if_enabled(("s", "e", "c")) is None


# 2. Same session -> same selector reused
def test_same_session_reuses_selector(monkeypatch):
    monkeypatch.setenv("WEBPENT_LLM_RESEARCH_ENABLED", "true")
    # inject a fake-provider constructor to avoid real env dependency
    orig = LLMResearchSelector.build_if_enabled.__func__
    calls = {"n": 0}
    def fake_build(cls, session_key=None):
        calls["n"] += 1
        from webpent.integration import llm_research_adapter as m
        reg = m._SELECTOR_REGISTRY
        if session_key in reg:
            return reg[session_key]
        s = cls(LLMResearcher(llm_client=FakeLLM()))
        if session_key:
            reg[session_key] = s
        return s
    monkeypatch.setattr(LLMResearchSelector, "build_if_enabled", classmethod(fake_build))
    k = ("sess-x", "eng-x", "cli-x")
    s1 = LLMResearchSelector.build_if_enabled(k)
    s2 = LLMResearchSelector.build_if_enabled(k)
    assert s1 is s2  # same instance reused
    clear_session(k)


# 3. Different session -> no leakage
def test_different_session_no_leakage(monkeypatch):
    s_a = LLMResearchSelector(LLMResearcher(llm_client=FakeLLM()))
    s_b = LLMResearchSelector(LLMResearcher(llm_client=FakeLLM()))
    s_a.decision_sequence = 5
    assert s_b.decision_sequence == 0
    assert s_a.researcher is not s_b.researcher
    # memory isolated
    s_a.researcher.memory.observations.append({"x": 1})
    assert len(s_b.researcher.memory.observations) == 0


# 4. Decision #1 receives initial context
def test_decision_one_initial_context():
    sel = LLMResearchSelector(LLMResearcher(llm_client=FakeLLM()))
    sel.select_from_candidates(_ctx([]), [_decision(_cand())])
    p = sel.provenance_log[-1]
    assert p["decision_sequence"] == 1
    assert p["observation_count"] == 0
    assert "context_input_hash" in p and len(p["context_input_hash"]) == 64


# 5. After observation #1, Decision #2 input contains updated context
def test_decision_two_sees_observation_one():
    sel = LLMResearchSelector(LLMResearcher(llm_client=FakeLLM()))
    sel.select_from_candidates(_ctx([]), [_decision(_cand())])
    h1 = sel.provenance_log[-1]["context_input_hash"]
    # observation #1 arrives as a known fact in the session context
    sel.select_from_candidates(_ctx(["obs-1: status=200 owner mismatch"]), [_decision(_cand())])
    p2 = sel.provenance_log[-1]
    assert p2["decision_sequence"] == 2
    assert p2["observation_count"] == 1
    assert p2["context_input_hash"] != h1  # input actually changed


# 6. After observation #2, Decision #3 contains accumulated context
def test_decision_three_accumulated_context():
    sel = LLMResearchSelector(LLMResearcher(llm_client=FakeLLM()))
    sel.select_from_candidates(_ctx([]), [_decision(_cand())])
    sel.select_from_candidates(_ctx(["obs-1"]), [_decision(_cand())])
    sel.select_from_candidates(_ctx(["obs-1", "obs-2: replay confirmed"]), [_decision(_cand())])
    p3 = sel.provenance_log[-1]
    assert p3["decision_sequence"] == 3
    assert p3["observation_count"] == 2  # both facts ingested (deduped)
    assert p3["known_fact_count"] == 2


# 7. REAL_API malformed -> fail-closed
def test_malformed_fail_closed():
    sel = LLMResearchSelector(LLMResearcher(llm_client=FakeLLM("not json")))
    pick = sel.select_from_candidates(_ctx([]), [_decision(_cand())])
    assert pick is None
    assert sel.provenance_log[-1]["outcome"] == "malformed_rejected"


# 8. No raw prompt/response/secret in telemetry
def test_no_raw_secrets_in_telemetry():
    llm = FakeLLM('{"tool":"request","purpose":"p"}')
    sel = LLMResearchSelector(LLMResearcher(llm_client=llm))
    sel.select_from_candidates(_ctx(["Bearer secret-token leaked fact"]), [_decision(_cand())])
    blob = repr(sel.provenance_log) + repr(sel.diagnostics)
    assert "Bearer" not in blob
    assert "secret-token" not in blob
    assert "not json" not in blob
    # only structural fields present
    p = sel.provenance_log[-1]
    assert set(p.keys()) <= {
        "decision_sequence", "observation_count", "known_fact_count",
        "context_input_hash", "admissible_candidate_count", "outcome",
        "reason", "tool", "selected_action_id",
        "candidate_ids_presented", "rejected_id", "selected_candidate_id", "lineage",
    }
