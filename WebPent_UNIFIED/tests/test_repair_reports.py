"""Regression coverage for repaired submission-report boundaries."""
from __future__ import annotations

import json
from pathlib import Path

from webpent.reporter.bounty_report import BountyReport, CausalEvidence, ReproductionStep
from webpent.reporter.poc_export import build_curl_commands, export_finding_evidence


_SECRET = "super-secret-value"


def test_bounty_markdown_renders_rationale_step_details_and_evidence_refs() -> None:
    report = BountyReport(
        report_id="report-1",
        finding_id="finding-1",
        campaign_id="campaign-1",
        title="[HIGH] Access control",
        severity="High",
        cvss_score=8.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        cvss_justification="Network reachable, low complexity, authenticated user, high confidentiality impact.",
        description="The owner boundary is not enforced.",
        steps_to_reproduce=[
            ReproductionStep(
                number=1,
                method="GET",
                url="https://target.test/item/1",
                request_digest="sha256:" + "1" * 64,
                response_status=200,
                response_digest="sha256:" + "2" * 64,
                description="Replay the sealed candidate request.",
            )
        ],
        evidence={
            "causal_chain": [
                CausalEvidence(
                    role="candidate",
                    status_code=200,
                    request_digest="sha256:" + "1" * 64,
                    response_digest="sha256:" + "2" * 64,
                    evidence_ref="execution:candidate",
                ).model_dump(mode="json")
            ]
        },
        impact="Protected data is readable.",
        remediation="Enforce server-side object authorization.",
        supporting_material={
            "proof_bundle_id": "bundle-1",
            "seal_digest": "sha256:" + "3" * 64,
            "audit_chain_status": "verified",
            "gates_passed": ["gate-1"],
        },
        generated_at="2026-10-06T00:00:00+00:00",
    )
    markdown = report.to_markdown()
    assert "**CVSS rationale:**" in markdown
    assert report.cvss_justification in markdown
    assert "Replay the sealed candidate request." in markdown
    assert "sha256:" + "2" * 64 in markdown
    assert "Evidence ref" in markdown
    assert "execution:candidate" in markdown


def test_curl_token_placeholders_expand_and_target_input_is_redacted() -> None:
    finding = {
        "url": "https://target.test/item?token=" + _SECRET + "&q=a'$(id)",
        "request_data": {"token": _SECRET, "name": "safe"},
    }
    text = "\n".join(build_curl_commands(finding))
    assert "'$OWNER_TOKEN'" not in text
    assert "'$FOREIGN_TOKEN'" not in text
    assert '"$OWNER_TOKEN"' in text
    assert '"$FOREIGN_TOKEN"' in text
    assert _SECRET not in text
    assert "[REDACTED]" in text


def test_poc_export_redacts_prose_url_and_references_and_uses_honest_defaults(tmp_path: Path) -> None:
    finding = {
        "id": "repair-1",
        "title": "Finding with redacted evidence",
        "severity": "high",
        "url": "https://target.test/?token=" + _SECRET,
        "request_method": "GET",
        "vuln_class": "IDOR",
        "evidence": {"promotion": {"decision": "PROMOTED"}},
        "description": "Observed with Authorization: Bearer " + _SECRET,
        "references": ["https://example.test/advisory?token=" + _SECRET],
    }
    result = export_finding_evidence(finding, output_dir=tmp_path)
    markdown = Path(result["markdown"]).read_text(encoding="utf-8")
    sidecar = json.loads(Path(result["json"]).read_text(encoding="utf-8"))
    assert _SECRET not in markdown
    assert _SECRET not in json.dumps(sidecar)
    assert "[REDACTED]" in markdown
    assert sidecar["impact"] == "Observed with Authorization: Bearer [REDACTED]"
    assert "TARGET_URL" not in markdown  # supplied URL is retained, but redacted
