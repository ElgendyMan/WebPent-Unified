from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


GATES = [
    "real_runtime_observations",
    "baseline_present",
    "candidate_present",
    "negative_control_present",
    "causal_validator_confirmed",
    "proof_bundle_signed",
    "replay_verified",
    "no_external_scanner_authority",
]


def _finding(monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.setenv("WEBPENT_AUDIT_SECRET_KEY", "x" * 48)
    from webpent.models.proof_bundle import build_proof_bundle

    requests = [
        {"role": "baseline", "method": "GET", "url": "http://127.0.0.1:3000/api/item?id=1"},
        {"role": "candidate", "method": "GET", "url": "http://127.0.0.1:3000/api/item?id=2"},
        {"role": "negative_control", "method": "GET", "url": "http://127.0.0.1:3000/api/item?id=999"},
    ]
    responses = [
        {"status_code": 403, "body": "baseline"},
        {"status_code": 200, "body": "candidate"},
        {"status_code": 403, "body": "control"},
    ]
    bundle = build_proof_bundle(
        engagement_id="juice-shop-campaign",
        campaign_id="juice-shop-campaign",
        run_id="run-001",
        finding_id="finding-001",
        hypothesis_id="hyp-001",
        vulnerability_class="broken_access_control",
        evidence=[*responses],
        evidence_refs=["execution:baseline", "execution:candidate", "execution:negative-control"],
        negative_control=responses[2],
        target_fingerprint="juice-shop-loopback",
        target_identity="regular-user",
        scope_context={"authorized": True, "target": "127.0.0.1:3000"},
        identity_context={"principal": "regular-user", "authenticated": True},
        baseline=responses[0],
        request_evidence=requests,
        response_evidence=responses,
        causal_oracle={
            "causal_signal": True,
            "negative_control_complete": True,
            "requires_target_backed": True,
            "baseline_access_result": 403,
            "candidate_access_result": 200,
            "negative_control_result": 403,
        },
        target_backed=True,
        negative_control_independent=True,
        validator_id="juice-shop-validator",
        validator_version="1.0",
        replay_metadata={"replayable": True, "requests_executed": 3},
        cleanup_status="not_applicable",
        baseline_evidence_ref="execution:baseline",
        candidate_evidence_ref="execution:candidate",
        negative_control_evidence_ref="execution:negative-control",
        oracle_decision="CONFIRMED",
        validator_result={"gates_passed": GATES},
        evidence_origin="target_runtime",
    ).seal(actor="test")
    return {
        "id": "finding-001",
        "title": "Regular user can read another user's item",
        "severity": "high",
        "description": "The item endpoint does not enforce ownership.",
        "vuln_class": "broken_access_control",
        "url": requests[1]["url"],
        "confidence_level": "Tool-Confirmed",
        "tool_confirmed_by": "test.fixture",
        "cvss_score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 7.1",
        "reasoning": "The CVSS vector reflects network reachability, low complexity, low privileges, and high confidentiality impact.",
        "business_impact": "An authenticated user can read another user's protected record.",
        "evidence": {
            "proof_bundle": bundle.model_dump(mode="json"),
            "gates_passed": GATES,
            "request_sequence": requests,
            "response_sequence": responses,
            "baseline": {"request": requests[0], "response": responses[0]},
            "candidate": {"request": requests[1], "response": responses[1]},
            "negative_control": {"request": requests[2], "response": responses[2]},
            "promotion": {"decision": "PROMOTED", "gates_passed": GATES},
            "audit_chain": {"verified": True, "root": "sha256:audit-root"},
        },
    }


def test_promoted_finding_generates_complete_report(monkeypatch: pytest.MonkeyPatch) -> None:
    from webpent.reporter.bounty_report import build_bounty_report

    report = build_bounty_report(_finding(monkeypatch))
    assert report.severity == "High"
    assert report.cvss_score == 7.1
    assert report.cvss_vector.startswith("CVSS:3.1/")
    assert len(report.steps_to_reproduce) == 3
    assert len(report.supporting_material["gates_passed"]) == 8
    assert report.supporting_material["authenticity_verified"] is True
    assert "## Steps to Reproduce" in report.to_markdown()
    assert "Authorization" not in report.to_markdown()


def test_refuted_finding_does_not_generate_report(monkeypatch: pytest.MonkeyPatch) -> None:
    from webpent.reporter.bounty_report import BountyReportError, build_bounty_report

    finding = _finding(monkeypatch)
    finding["confidence_level"] = "Refuted"
    finding["evidence"]["promotion"] = {"decision": "REFUTED", "gates_passed": GATES}
    with pytest.raises(BountyReportError, match="refuted"):
        build_bounty_report(finding)


def test_missing_executed_request_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    from webpent.reporter.bounty_report import BountyReportError, build_bounty_report

    finding = _finding(monkeypatch)
    finding["evidence"].pop("request_sequence")
    finding["evidence"].pop("request_sequence", None)
    finding["evidence"].pop("request", None)
    finding["evidence"]["baseline"].pop("request")
    finding["evidence"]["candidate"].pop("request")
    finding["evidence"]["negative_control"].pop("request")
    with pytest.raises(BountyReportError, match="executed_request"):
        build_bounty_report(finding)


def test_report_generator_skips_refuted_and_unpromoted(monkeypatch: pytest.MonkeyPatch) -> None:
    from webpent.reporter.bounty_report import generate_bounty_reports

    promoted = _finding(monkeypatch)
    refuted = _finding(monkeypatch)
    refuted["id"] = "finding-refuted"
    refuted["confidence_level"] = "Refuted"
    refuted["evidence"]["promotion"] = {"decision": "REFUTED"}
    assert len(generate_bounty_reports([promoted, refuted], campaign_id="campaign")) == 1


def test_api_and_cli_surfaces_are_registered() -> None:
    from webpent.api.app import app
    from webpent.cli.commands import app as cli_app

    paths = {route.path for route in app.routes}
    assert "/api/v1/campaigns/{campaign_id}/reports" in paths
    command_names = {command.name for command in cli_app.registered_commands}
    assert "reports" in command_names
