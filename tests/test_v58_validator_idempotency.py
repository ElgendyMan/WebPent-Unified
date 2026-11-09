"""V58 regressions for idempotent validation across bounded graph loops."""

from __future__ import annotations

from webpent.agents.payload_generator import agent as payload_generator_module
from webpent.agents.payload_optimizer import agent as payload_optimizer_module
from webpent.agents.validator import agent as validator_module
from webpent.graph.builder import (
    NODE_DEVILS_ADVOCATE,
    route_after_validator,
)
from webpent.models.findings import Finding, Severity, VulnClass


def _finding(
    *,
    vuln_class: VulnClass,
    confidence_level: str = "Pending",
    evidence: dict | None = None,
) -> Finding:
    return Finding(
        title=f"{vuln_class.value} candidate",
        severity=Severity.MEDIUM,
        description="Regression-test candidate.",
        tool_name="test",
        url="http://127.0.0.1:4280/test",
        vuln_class=vuln_class,
        confidence_level=confidence_level,
        evidence=evidence,
    )


def test_validator_skips_terminal_finding_without_duplicate_tool_call(monkeypatch):
    finding = _finding(
        vuln_class=VulnClass.SQLI,
        confidence_level="Needs Human Review",
        evidence={
            "tool_infra_failure": True,
            "validation_attempted": True,
        },
    )
    calls: list[str] = []

    def fail_if_called(*args, **kwargs):
        calls.append("called")
        raise AssertionError("terminal finding was validated twice")

    monkeypatch.setattr(validator_module, "_validate_with_tool", fail_if_called)

    result = validator_module.validator_node({"findings": [finding]})

    assert calls == []
    assert result["findings"][0].id == finding.id
    assert result["findings"][0].evidence["tool_infra_failure"] is True


def test_route_does_not_send_sqlmap_synthetic_marker_to_optimizer():
    finding = _finding(
        vuln_class=VulnClass.SQLI,
        confidence_level="Pending",
        evidence={"validation_attempted": True},
    )
    state = {
        "findings": [finding],
        "payloads_to_test": {
            str(finding.id): ["__SQLMAP_TOOL_DRIVEN__"],
        },
        "optimization_retries": {str(finding.id): 0},
    }

    assert route_after_validator(state) == NODE_DEVILS_ADVOCATE


def test_payload_generator_does_not_reseed_terminal_sqli_marker():
    finding = _finding(
        vuln_class=VulnClass.SQLI,
        confidence_level="Needs Human Review",
        evidence={
            "tool_infra_failure": True,
            "validation_attempted": True,
        },
    )

    result = payload_generator_module.payload_generator_node(
        {"findings": [finding]}
    )

    assert result["payloads_to_test"] == {}
    assert result["findings"][0].id == finding.id
    assert result["findings"][0].payload is None


def test_optimizer_marks_only_new_payload_as_validation_requeue(monkeypatch):
    finding = _finding(
        vuln_class=VulnClass.XSS,
        evidence={
            "validation_attempted": True,
            "validation_failure_reason": "tool_no_marker",
        },
    )

    monkeypatch.setattr(
        payload_optimizer_module,
        "_generate_optimized_payloads",
        lambda finding, failed, llm: ["<svg/onload=alert(1)>"]
    )

    result = payload_optimizer_module.payload_optimizer_node(
        {
            "findings": [finding],
            "payloads_to_test": {str(finding.id): ["<script>alert(1)</script>"]},
            "optimization_retries": {str(finding.id): 0},
        }
    )

    assert result["payloads_to_test"][str(finding.id)] == [
        "<svg/onload=alert(1)>"
    ]
    assert result["findings"][0].evidence["validation_requeue"] is True
    assert result["optimization_retries"][str(finding.id)] == 1


def test_offline_llm_supervisor_is_fail_closed_without_invoke():
    finding = _finding(vuln_class=VulnClass.XSS)
    assert (
        validator_module._llm_supervisor_verdict(
            None,
            finding,
            VulnClass.XSS.value,
            "dalfox",
            "tool output",
        )
        is False
    )
