"""Team-1 minimal live-graph LLM Researcher integration tests (Phase 3).

Focused tests only (~8). Uses an in-process fake REAL_API provider
(llm_client is not None) — zero real quota consumed. Verifies: deterministic
path unchanged when disabled, LLM path called when enabled, valid admissible
candidate reaches execution, malformed/invalid/non-executable rejected
fail-closed, LLM cannot confirm/modify authority.
"""
from __future__ import annotations

from webpent.integration.llm_research_adapter import (
    LLMResearchSelector,
    llm_research_enabled,
)
from webpent.llm_researcher.interface import LLMResearcher
from webpent.models.research import CandidateAction
from webpent.shared.research_contracts import (
    ActiveResearchLoop,
    ResearchContext,
    ResearchDecision,
    active_research_node,
)


class FakeLLM:
    def __init__(self, response):
        self.response = response
        self.calls = 0

    def generate(self, prompt, max_tokens=None):
        self.calls += 1
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _candidate(action_id, action_class, capability="http_read", ig=0.5):
    return CandidateAction(
        action_id=action_id, action_class=action_class,
        objective=f"probe {action_id}", capability=capability,
        expected_information_gain=ig,
    )


def _decision(c):
    return ResearchDecision(candidate=c, score=0.5, status="ranked")


def _context():
    return ResearchContext(
        session_id="sess-test", engagement_id="eng-test", client_id="client-test",
        depth=0, max_depth=10, budget_remaining=100.0,
        attempted_action_fingerprints=[], known_facts=[],
    )


# A. LLM disabled -> deterministic path unchanged
def test_disabled_deterministic_unchanged(monkeypatch):
    monkeypatch.delenv("WEBPENT_LLM_RESEARCH_ENABLED", raising=False)
    assert llm_research_enabled() is False
    assert LLMResearchSelector.build_if_enabled() is None
    # ActiveResearchLoop with no selector behaves deterministically
    loop = ActiveResearchLoop()
    assert loop.llm_selector is None


# B. REAL_API enabled -> active path calls LLMResearcher
def test_enabled_calls_llm(monkeypatch):
    monkeypatch.setenv("WEBPENT_LLM_RESEARCH_ENABLED", "true")
    llm = FakeLLM('{"selected_candidate_id":"cand1","decision_reason":"r"}')
    selector = LLMResearchSelector(LLMResearcher(llm_client=llm))
    pick = selector.select_from_candidates(
        _context(), [_decision(_candidate("cand1", "discover"))]
    )
    assert llm.calls == 1
    assert pick is not None and pick.action_id == "cand1"


# C. valid LLM decision -> valid admissible candidate reaches handler
def test_valid_decision_reaches_handler(monkeypatch):
    monkeypatch.setenv("WEBPENT_LLM_RESEARCH_ENABLED", "true")
    llm = FakeLLM('{"selected_candidate_id":"disc-c","decision_reason":"r"}')
    selector = LLMResearchSelector(LLMResearcher(llm_client=llm))
    executed = []
    def handler(c):
        executed.append(c.action_id)
        return {"status": "ok"}
    candidates = [_candidate("req-c", "request", ig=0.9), _candidate("disc-c", "discover", ig=0.5)]
    loop = ActiveResearchLoop(llm_selector=selector)
    result = loop.step(_context(), candidates, handler=handler,
                       available_capabilities={"http_read", "discover"},
                       target_allowed=True, approved=True)
    assert executed == ["disc-c"]  # LLM picked discover (lower-ranked) -> executed
    assert result.observation.status != "blocked"


# D. malformed LLM output -> rejected fail-closed, deterministic proceeds
def test_malformed_rejected_fail_closed():
    llm = FakeLLM("not json at all")
    selector = LLMResearchSelector(LLMResearcher(llm_client=llm))
    pick = selector.select_from_candidates(
        _context(), [_decision(_candidate("cand1", "request"))]
    )
    assert pick is None  # rejected
    assert selector.diagnostics[-1]["reason"] == "malformed_or_missing_id"


# E. invalid/non-executable LLM decision -> rejected before execution
def test_non_executable_rejected():
    llm = FakeLLM('{"selected_candidate_id":"unknown-cand-zzz"}')
    selector = LLMResearchSelector(LLMResearcher(llm_client=llm))
    candidates = [_candidate("cand1", "request"), _candidate("cand2", "discover")]
    pick = selector.select_from_candidates(
        _context(), [_decision(c) for c in candidates]
    )
    assert pick is None  # non-executable -> rejected at LLMResearcher or adapter layer
    assert selector.diagnostics[-1]["reason"] in {
        "malformed_or_missing_id", "unknown_candidate_id"}


# F. safety: LLM cannot confirm / modify proof authority
def test_llm_cannot_confirm():
    llm = FakeLLM('{"selected_candidate_id":"cand1","confirm_vulnerability":true}')
    selector = LLMResearchSelector(LLMResearcher(llm_client=llm))
    pick = selector.select_from_candidates(
        _context(), [_decision(_candidate("cand1", "request"))]
    )
    # LLM extra field ignored; only tool/candidate mapping matters.
    assert pick is not None
    # No confirmation authority: selector never touches proof/evidence.
    assert not hasattr(selector, "proof_authority")


# G. mock provider never used (build_if_enabled rejects mock)
def test_mock_provider_rejected(monkeypatch):
    monkeypatch.setenv("WEBPENT_LLM_RESEARCH_ENABLED", "true")
    monkeypatch.setenv("ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION", "true")
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    # get_provider_from_env would return MockLLMProvider; build_if_enabled
    # must reject it (selector None -> deterministic, no mock).
    sel = LLMResearchSelector.build_if_enabled()
    assert sel is None


# H. active_research_node end-to-end with LLM override (state -> handler)
def test_active_research_node_llm_override(monkeypatch):
    monkeypatch.setenv("WEBPENT_LLM_RESEARCH_ENABLED", "true")
    executed = []
    def handler(c):
        executed.append(c.action_id)
        return {"status": "completed", "observation_ref": "obs::1"}
    state = {
        "research_candidate_actions": [
            _candidate("req-node", "request", ig=0.9).model_dump(),
            _candidate("disc-node", "discover", ig=0.5).model_dump(),
        ],
        "action_budget": {"research_budget_remaining": 100.0},
        "capability_manifest": {"capabilities": {"http_read": True, "discover": True}},
        "surface_coverage": {},
        "research_failed_paths": [],
    }
    # Inject a selector with a fake LLM that picks "discover"
    from webpent.integration import llm_research_adapter as mod
    orig = mod.LLMResearchSelector.build_if_enabled
    mod.LLMResearchSelector.build_if_enabled = classmethod(
        lambda cls, *a, **k: LLMResearchSelector(LLMResearcher(llm_client=FakeLLM('{"selected_candidate_id":"disc-node"}')))
    )
    try:
        out = active_research_node(state, handler=handler, target_allowed=True, approved=True)
    finally:
        mod.LLMResearchSelector.build_if_enabled = orig
    assert executed == ["disc-node"]  # LLM overrode deterministic top (request)
    assert "research_observations" in out or "observation" in str(out)
