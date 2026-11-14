from __future__ import annotations

from webpent.agents.validator import structural_checks
from webpent.models.findings import Finding


def _finding(vuln_class: str, url: str) -> Finding:
    return Finding(
        title=f"Potential {vuln_class}",
        severity="medium",
        description="test",
        tool_name="structural",
        url=url,
        confidence="tentative",
        confidence_level="Pending",
        vuln_class=vuln_class,
        hypothesis_id="00000000-0000-4000-8000-000000000001",
    )


def test_javascript_sink_is_observation_until_runtime_taint_proof(monkeypatch):
    monkeypatch.setattr(
        structural_checks,
        "_fetch_page",
        lambda *args, **kwargs: (200, "<html><script>eval(userInput)</script></html>", {}),
    )

    result = structural_checks.validate_javascript(
        _finding("javascript", "http://lab.test/javascript")
    )

    assert result.confidence_level == "Needs Human Review"
    assert result.confidence == "tentative"
    assert result.evidence["exploitability_unproven"] is True
    assert result.evidence["runtime_taint_validation_required"] is True


def test_api_surface_is_observation_until_security_impact_is_proven(monkeypatch):
    monkeypatch.setattr(
        structural_checks,
        "_fetch_page",
        lambda *args, **kwargs: (
            200,
            '{"openapi":"3.0.0","paths":{}}',
            {"content-type": "application/json"},
        ),
    )

    result = structural_checks.validate_api_issue(
        _finding("api_issue", "http://lab.test/api")
    )

    assert result.confidence_level == "Needs Human Review"
    assert result.confidence == "tentative"
    assert result.evidence["security_impact_unproven"] is True
    assert result.evidence["follow_up_required"] is True
