from __future__ import annotations

from webpent.agents.execution_sandbox.agent import execution_sandbox_node
from webpent.models.findings import Finding, Severity, VulnClass
from webpent.models.targets import Target
from webpent.shared.poc_policy import (
    derive_execution_risk,
    evaluate_execution_gate,
)


def _target() -> Target:
    return Target(url="https://example.test")


def _finding(
    *,
    severity: Severity = Severity.LOW,
    vuln_class: VulnClass = VulnClass.XSS,
) -> Finding:
    return Finding(
        title="bounded test finding",
        severity=severity,
        description="synthetic regression finding",
        tool_name="test",
        url="https://example.test/form",
        vuln_class=vuln_class,
    )


def test_auto_approved_high_risk_requires_human_approval() -> None:
    state = {
        "auto_approve": True,
        "findings": [_finding(severity=Severity.HIGH)],
        "planner_decision": {},
    }
    assert derive_execution_risk(state) == "high"
    decision = evaluate_execution_gate(state)
    assert decision.status == "needs_approval"


def test_destructive_planner_risk_is_rejected_even_when_auto_approved() -> None:
    state = {
        "auto_approve": True,
        "findings": [],
        "planner_decision": {"risk_level": "destructive"},
    }
    assert derive_execution_risk(state) == "destructive"
    assert evaluate_execution_gate(state).status == "rejected"


def test_execution_node_blocks_high_risk_before_browser_launch(monkeypatch) -> None:
    state = {
        "target": _target(),
        "findings": [_finding(severity=Severity.HIGH)],
        "payloads_to_test": {str(_finding().id): ["<test>"]},
        "auth_state": {},
        "credentials": {},
        "playwright_enabled": True,
        "stealth_mode": False,
        "auto_approve": True,
        "planner_decision": {},
    }

    def fail_if_browser_launches(*args, **kwargs):
        raise AssertionError("high-risk auto-approved execution must be blocked")

    monkeypatch.setattr(
        "webpent.agents.execution_sandbox.agent._try_launch_browser",
        fail_if_browser_launches,
    )
    result = execution_sandbox_node(state)
    assert result["execution_gate"]["status"] == "needs_approval"
    assert result["execution_gate"]["risk_level"] == "high"
    assert result["execution_gate"]["human_approval_required"] is True
    assert "<test>" not in str(result)


def test_low_risk_execution_gate_is_allowed_without_sensitive_state() -> None:
    state = {
        "auto_approve": True,
        "findings": [_finding()],
        "planner_decision": {},
    }
    decision = evaluate_execution_gate(state)
    assert decision.allowed is True
    assert "cookie" not in decision.reason.lower()
    assert "token" not in decision.reason.lower()
