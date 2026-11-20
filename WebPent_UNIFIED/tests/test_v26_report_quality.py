from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


_SECRET = "super-secret-value"


def _sealed_proof_bundle_dict() -> dict:
    """A minimal but fully valid, sealed ProofBundle for report-boundary tests.

    See tests/test_v15_review_hardening.py's copy of this helper for the
    full rationale (GOED's evidence-quality gate at the report boundary —
    webpent.shared.evidence_quality / report_quality — requires a real
    causal_signal + negative_control_complete + promotion-ready sealed
    ProofBundle before a "Tool-Confirmed" finding is treated as
    lifecycle-"Confirmed").
    """
    from webpent.models.proof_bundle import build_proof_bundle

    bundle = build_proof_bundle(
        engagement_id="engagement-fixture",
        finding_id="finding-quality-1",
        evidence=[{"status": 200, "body": "marker"}],
        evidence_refs=["execution:1"],
        negative_control={"status": 403},
        hypothesis_id="hyp-quality-1",
        target_fingerprint="sha256:fixture-target",
        scope_context={"targets": ["target.test"], "authorized": True},
        identity_context={"identity": "primary", "authenticated": True},
        baseline={"status": 403, "body": "baseline"},
        request_evidence=[{"method": "GET", "url": "https://target.test/item?id=1"}],
        response_evidence=[{"status": 200}],
        causal_oracle={
            "causal_signal": True,
            "negative_control_complete": True,
            "requires_target_backed": False,
        },
        validator_id="report-fixture-validator",
        validator_version="v1",
        replay_metadata={"replayable": True},
        cleanup_status="not_applicable",
    ).seal(actor="test-fixture")
    return bundle.model_dump(mode="json")


def _finding(**overrides):
    value = {
        "id": "finding-quality-1",
        "title": "Evidence-backed finding",
        "severity": "high",
        "description": "A deterministic test finding",
        "tool_name": "safe-test-tool",
        "payload": "marker",
        "url": "https://target.test/item?id=1&token=" + _SECRET,
        "confidence": "high",
        "confidence_level": "Tool-Confirmed",
        "tool_confirmed_by": "test.fixture",
        "cvss_score": 8.1,
        "business_impact": "An unauthorized user can access protected data.",
        "vuln_class": "broken_access_control",
        "reasoning": "The response differential was observed deterministically.",
        "evidence_bundle": {
            "request": {
                "method": "GET",
                "url": "https://target.test/item?id=1",
                "headers": {"Authorization": "Bearer " + _SECRET},
            },
            "response": {"status": 200, "body": "marker"},
            "reproduction": {"steps_to_reproduce": ["Repeat the read-only request."]},
            "scope_status": "allowed",
            "hypothesis": {"hypothesis_id": "hyp-quality-1"},
            "related_findings": ["finding-prerequisite-1"],
        },
        "evidence": {
            "causal_signal": True,
            "negative_control_complete": True,
            "proof_bundle": _sealed_proof_bundle_dict(),
        },
        "evidence_hash": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "compliance_tags": [],
        "canary_token": None,
        "strategic_confidence_score": 0.95,
        "hypothesis_id": "hyp-quality-1",
        "post_exploitation_data": {"token": _SECRET},
    }
    value.update(overrides)
    return value


def test_quality_gate_ready_uses_shared_lifecycle_and_returns_no_values():
    from webpent.shared.report_quality import evaluate_report_quality

    result = evaluate_report_quality([_finding()])
    dumped = result.model_dump(mode="json")

    assert result.ready is True
    assert result.status == "ready"
    assert result.ready_finding_count == 1
    assert result.findings[0].lifecycle_stage == "Confirmed"
    assert result.findings[0].blocking_issues == []
    assert _SECRET not in str(dumped)
    assert "evidence_bundle" not in str(dumped)


def test_quality_gate_blocks_missing_contract_fields_without_exposing_values():
    from webpent.shared.report_quality import evaluate_report_quality

    incomplete = _finding(
        confidence_level="Pending",
        cvss_score="",
        business_impact="",
        hypothesis_id=None,
        evidence_bundle={"request": {"method": "GET"}},
    )
    result = evaluate_report_quality([incomplete])
    item = result.findings[0]

    assert result.ready is False
    assert result.status == "blocked"
    assert set(item.blocking_issues) >= {
        "hypothesis",
        "reproduction",
        "business_impact",
        "cvss",
    }
    assert _SECRET not in str(result.model_dump(mode="json"))


def test_strict_report_export_fails_closed_but_legacy_mode_remains_available(tmp_path):
    from webpent.reporter.export import build_report_data
    from webpent.shared.report_quality import ReportQualityGateError

    with pytest.raises(ReportQualityGateError):
        build_report_data(
            "https://target.test",
            [_finding(business_impact="")],
            strict_quality_gate=True,
        )

    legacy_data = build_report_data(
        "https://target.test",
        [_finding(business_impact="")],
        strict_quality_gate=False,
    )
    assert legacy_data["quality_gate"]["status"] == "blocked"
    assert _SECRET not in str(legacy_data)
    assert (
        legacy_data["findings"][0]["evidence_bundle"]["request"]["headers"]["Authorization"]
        == "[REDACTED]"
    )
    assert legacy_data["findings"][0]["post_exploitation_data"]["token"] == "[REDACTED]"


def test_html_report_surfaces_quality_gate_and_finding_lifecycle(tmp_path):
    from webpent.reporter.export import export_to_html

    path = export_to_html("https://target.test", [_finding()], tmp_path)
    html = path.read_text(encoding="utf-8")

    assert "Evidence Quality Gate" in html
    assert "Status:" in html
    assert "Lifecycle: Confirmed" in html
    assert _SECRET not in html


def test_report_quality_flag_is_safe_by_default_and_env_configurable(monkeypatch):
    from webpent.config.settings import Settings

    assert Settings().enable_report_quality_gate is False
    monkeypatch.setenv("ENABLE_REPORT_QUALITY_GATE", "true")
    assert Settings().enable_report_quality_gate is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
