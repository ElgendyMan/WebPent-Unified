# tests/test_causal_chain_candidates.py
"""Proposal 2 Phase 1 — the causal chain-candidate wiring in validator_node.

The contract: behind ENABLE_CAUSAL_CHAIN_CANDIDATES (default False), each
CONFIRMED finding feeds causal_reasoning_v2's documented
``on_finding_confirmed`` hook and its sibling-probe hypotheses land in
``state.causal_chain_candidates`` as ADVISORY candidates — never
auto-confirmed, never executed, structurally absent when the flag is off,
and fail-soft on any hook failure.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from webpent.agents.validator import agent as validator_module
from webpent.config.settings import get_settings
from webpent.models.findings import Confidence, Finding, Severity, VulnClass


@pytest.fixture(autouse=True)
def _reset_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _confirmed_finding() -> Finding:
    return Finding(
        title="idor candidate",
        severity=Severity.MEDIUM,
        description="Regression-test candidate.",
        tool_name="test",
        url="http://127.0.0.1:4280/test",
        vuln_class=VulnClass.IDOR,
        confidence=Confidence.CONFIRMED,
        confidence_level="Tool-Confirmed",
        evidence={
            "tool_infra_failure": True,
            "validation_attempted": True,
            # M1-B (E-1): model-level proof requirement.
            "tool_confirmed_by": "test.fixture",
        },
    )


def _tentative_finding() -> Finding:
    return Finding(
        title="sqli candidate",
        severity=Severity.MEDIUM,
        description="Not confirmed.",
        tool_name="test",
        url="http://127.0.0.1:4280/other",
        vuln_class=VulnClass.SQLI,
        confidence=Confidence.TENTATIVE,
        confidence_level="Pending",
        evidence={"tool_infra_failure": True, "validation_attempted": True},
    )


class _FakeLayer:
    instances: list["_FakeLayer"] = []
    calls: list[dict] = []
    result: list[dict] | None = None
    raise_on_call: Exception | None = None

    def __init__(self, *, engagement_id: str = ""):
        self.engagement_id = engagement_id
        _FakeLayer.instances.append(self)

    def on_finding_confirmed(self, finding, state):
        _FakeLayer.calls.append({"finding": dict(finding), "state": dict(state)})
        if _FakeLayer.raise_on_call is not None:
            raise _FakeLayer.raise_on_call
        return list(_FakeLayer.result or [])


@pytest.fixture(autouse=True)
def _fake_layer(monkeypatch):
    _FakeLayer.instances = []
    _FakeLayer.calls = []
    _FakeLayer.result = None
    _FakeLayer.raise_on_call = None
    monkeypatch.setattr(
        "webpent.causal_reasoning_v2.integration_layer.CausalIntegrationLayer",
        _FakeLayer,
    )
    yield


def test_flag_off_wiring_is_structurally_absent(monkeypatch):
    monkeypatch.setenv("ENABLE_CAUSAL_CHAIN_CANDIDATES", "false")
    finding = _confirmed_finding()
    result = validator_module.validator_node({"findings": [finding]})
    assert "causal_chain_candidates" not in result
    assert _FakeLayer.calls == []          # the hook is never constructed
    assert _FakeLayer.instances == []
    summary = result["messages"][0].content
    assert "causal chain candidate" not in summary


def test_flag_unset_by_default():
    assert get_settings().enable_causal_chain_candidates is False


def test_flag_on_confirmed_finding_yields_candidates(monkeypatch):
    monkeypatch.setenv("ENABLE_CAUSAL_CHAIN_CANDIDATES", "true")
    _FakeLayer.result = [
        {
            "id": "cand-1",
            "statement": "[causal sibling] probe",
            "vuln_class": "idor",
            "confidence_score": 0.8,
        }
    ]
    confirmed = _confirmed_finding()
    result = validator_module.validator_node({"findings": [confirmed]})
    candidates = result["causal_chain_candidates"]
    assert len(candidates) == 1
    assert candidates[0]["id"] == "cand-1"
    assert len(_FakeLayer.calls) == 1
    # the hook receives the finding dict + the state snapshot
    assert str(_FakeLayer.calls[0]["finding"]["id"]) == str(confirmed.id)
    # the summary marks the candidates advisory and unconfirmed
    summary = result["messages"][0].content
    assert "causal chain candidate(s) (advisory" in summary
    assert "never auto-confirmed" in summary


def test_flag_on_skips_unconfirmed_findings(monkeypatch):
    monkeypatch.setenv("ENABLE_CAUSAL_CHAIN_CANDIDATES", "true")
    result = validator_module.validator_node(
        {"findings": [_tentative_finding()]})
    assert "causal_chain_candidates" not in result
    assert _FakeLayer.calls == []


def test_hook_failure_is_fail_soft(monkeypatch):
    monkeypatch.setenv("ENABLE_CAUSAL_CHAIN_CANDIDATES", "true")
    _FakeLayer.raise_on_call = RuntimeError("causal layer exploded")
    finding = _confirmed_finding()
    result = validator_module.validator_node({"findings": [finding]})
    # validation itself completed; no candidates surfaced
    assert "causal_chain_candidates" not in result
    assert result["findings"][0].id == finding.id


def test_hook_returning_none_is_tolerated(monkeypatch):
    monkeypatch.setenv("ENABLE_CAUSAL_CHAIN_CANDIDATES", "true")
    _FakeLayer.result = None
    result = validator_module.validator_node(
        {"findings": [_confirmed_finding()]})
    assert "causal_chain_candidates" not in result


def test_flag_on_preserves_validation_outputs(monkeypatch):
    monkeypatch.setenv("ENABLE_CAUSAL_CHAIN_CANDIDATES", "true")
    finding = _confirmed_finding()
    baseline = validator_module.validator_node({"findings": [finding]})
    confirmed2 = _confirmed_finding()
    flagon = validator_module.validator_node({"findings": [confirmed2]})
    # everything except the advisory key/summary is unchanged in shape
    for key in ("findings", "current_phase"):
        assert key in flagon and key in baseline
    assert str(flagon["findings"][0].id) != str(baseline["findings"][0].id)
    assert (flagon["findings"][0].title
            == baseline["findings"][0].title)
    assert (flagon["findings"][0].vuln_class
            == baseline["findings"][0].vuln_class)
