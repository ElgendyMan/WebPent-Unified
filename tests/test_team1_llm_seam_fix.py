"""Team-1 production LLM experiment-selection seam repair tests.

Tests the SEAM LOGIC only with a fake in-process LLM client (llm_client is not
None => REAL_API configured path). No real API quota consumed; no mock is
reported as real API validation. Verifies: real selection happens, no silent
mock fallback, malformed/invalid rejected fail-closed, decision context
complete, backward compat when llm_client is None.
"""
from __future__ import annotations

import pytest

from webpent.llm_researcher.interface import Hypothesis, HypothesisStatus, LLMResearcher


class FakeLLM:
    """In-process fake standing in for a configured REAL_API provider."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0
        self.seen_prompts = []

    def generate(self, prompt, max_tokens=None):
        self.calls += 1
        self.seen_prompts.append(prompt)
        r = self.responses[self.calls - 1]
        if isinstance(r, Exception):
            raise r
        return r


class FailingLLM:
    def generate(self, prompt, max_tokens=None):
        raise ConnectionError("provider timeout")


def _hyp(desc="Potential missing authorization at /admin"):
    return Hypothesis(description=desc, confidence=0.5, status=HypothesisStatus.PROPOSED)


def _researcher(llm):
    r = LLMResearcher(llm_client=llm)
    r.ingest_observation({
        "request": {"path": "/admin", "method": "GET"},
        "status_code": 200, "body_length": 120,
        "headers": {"x-authorization-outcome": "granted_full",
                    "x-resource-owner": "owner-a", "x-actor-echo": "actor-b"},
    })
    return r


# A. production _llm_select_experiment actually performs REAL_API selection
def test_llm_select_performs_real_selection():
    llm = FakeLLM(['{"tool": "request", "purpose": "probe_auth", "parameters": {"method": "GET"}}'])
    researcher = _researcher(llm)
    decision = researcher.select_experiment(_hyp())
    assert decision is not None
    assert decision["tool"] == "request"
    assert llm.calls == 1  # real provider was actually called
    assert researcher.memory.selection_source[-1]["source"] == "llm"


# B. no silent mock fallback under REAL_API
def test_no_silent_mock_fallback_under_real_api():
    researcher = LLMResearcher(llm_client=FailingLLM())
    with pytest.raises(RuntimeError) as exc:
        researcher.select_experiment(_hyp())
    assert "REAL_API_EXPERIMENT_SELECTION_FAILED" in str(exc.value)
    # must NOT return a mock experiment (e.g. tool "compare"/"request" from mock)


# C. valid decision reaches existing experiment/action pipeline shape
def test_valid_decision_matches_pipeline_schema():
    llm = FakeLLM(['{"tool":"compare","purpose":"verify_boundary","parameters":{"strategy":"x"}}'])
    decision = _researcher(llm).select_experiment(_hyp())
    assert set(decision.keys()) >= {"tool", "purpose", "parameters"}
    from webpent.llm_researcher.tool_boundary import ALLOWED_TOOLS
    assert decision["tool"] in ALLOWED_TOOLS


# D. malformed response -> structured decision failure (None, no mock)
def test_malformed_response_fail_closed():
    llm = FakeLLM(["not json at all ###"])
    assert _researcher(llm).select_experiment(_hyp()) is None


# E. invalid experiment (forbidden tool) rejected before ToolBoundary
def test_invalid_tool_rejected_before_boundary():
    llm = FakeLLM(['{"tool":"rm_rf","purpose":"evil"}'])
    assert _researcher(llm).select_experiment(_hyp()) is None


# F. missing key => REAL_API_UNAVAILABLE (provider gate)
def test_missing_key_real_api_unavailable(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION", raising=False)
    from webpent.llm_researcher.providers import factory
    with pytest.raises(RuntimeError) as exc:
        factory.get_provider("openai_compatible", "gpt-test")
    assert "REAL_API_UNAVAILABLE" in str(exc.value)


# G. decision context exposes required structured state
def test_decision_context_complete():
    llm = FakeLLM(['{"tool":"request","purpose":"p"}'])
    r = _researcher(llm)
    r.memory.loop_count = 3
    r.select_experiment(_hyp())
    prompt = llm.seen_prompts[0]
    for marker in ["ALLOWED_TOOLS", "RESEARCH POLICY HASH", "LOOP_COUNT",
                   "MAX_EXPERIMENTS_PER_HYPOTHESIS", "HYPOTHESIS UNDER TEST",
                   "OBSERVATIONS"]:
        assert marker in prompt, f"missing context: {marker}"
    assert "/admin" in prompt  # observation visible to decision


# H. no secrets exposed in prompt
def test_no_secrets_in_prompt():
    llm = FakeLLM(['{"tool":"request","purpose":"p"}'])
    r = _researcher(llm)
    r.ingest_observation({"request": {"path": "/x"}, "status_code": 200,
                          "headers": {"authorization": "Bearer secret-leaked",
                                      "x-api-key": "sk-should-not-appear"}})
    r.select_experiment(_hyp())
    prompt = llm.seen_prompts[0].lower()
    assert "bearer secret" not in prompt
    assert "sk-should-not-appear" not in prompt


# I. backward compatible: mock still used when NO llm_client configured
def test_backward_compat_mock_when_no_llm():
    r = LLMResearcher(llm_client=None)
    decision = r.select_experiment(Hypothesis(description="tenant isolation failure", confidence=0.5))
    assert decision is not None
    assert decision["tool"] == "compare"  # deterministic mock path


# J. 3 sequential decisions, each valid, lineage/policy preserved
def test_three_sequential_decisions():
    llm = FakeLLM([
        '{"tool":"request","purpose":"p1"}',
        '{"tool":"discover","purpose":"p2"}',
        '{"tool":"compare","purpose":"p3"}',
    ])
    r = _researcher(llm)
    decisions = [r.select_experiment(_hyp()) for _ in range(3)]
    assert all(d is not None for d in decisions)
    assert [d["tool"] for d in decisions] == ["request", "discover", "compare"]
    assert len(r.memory.selection_source) == 3
    assert all(s["policy_hash"] == r.system_prompt_hash for s in r.memory.selection_source)
