from webpent.models.proof_bundle import build_proof_bundle
from webpent.shared.report_quality import validate_finding_quality


def _finding(proof_bundle=None):
    return {
        "id": "finding-1",
        "confidence_level": "Tool-Confirmed",
        "tool_confirmed_by": "test.fixture",
        "url": "http://example.test/object/1",
        "hypothesis_id": "hypothesis-1",
        "evidence": {
            "reproduction": {"request": "redacted", "response": "redacted"},
            "scope_status": "in_scope",
        },
        "business_impact": "bounded test impact",
        "cvss_score": "6.5",
        "proof_bundle": proof_bundle,
    }


def test_strict_gate_blocks_tool_confirmed_without_bundle():
    result = validate_finding_quality(_finding(), require_proof_bundle=True)

    assert result.ready is False
    assert "sealed_proof_bundle" in result.blocking_issues


def test_strict_gate_requires_negative_control():
    bundle = build_proof_bundle(
        engagement_id="engagement-1",
        finding_id="finding-1",
        evidence=[{"status": 200}],
        evidence_refs=["execution:1"],
    ).seal(actor="test")

    result = validate_finding_quality(
        _finding(bundle.model_dump(mode="json")), require_proof_bundle=True
    )

    assert result.ready is False
    assert "sealed_proof_bundle" in result.blocking_issues


def test_strict_gate_accepts_sealed_replayable_bundle():
    bundle = build_proof_bundle(
        engagement_id="engagement-1",
        finding_id="finding-1",
        evidence=[{"status": 200}],
        evidence_refs=["execution:1"],
        negative_control={"status": 403},
    ).seal(actor="test")

    result = validate_finding_quality(
        _finding(bundle.model_dump(mode="json")), require_proof_bundle=True
    )

    assert result.ready is True
    assert "sealed_proof_bundle" not in result.blocking_issues


def test_legacy_gate_remains_backward_compatible():
    result = validate_finding_quality(_finding(), require_proof_bundle=False)

    assert "sealed_proof_bundle" not in result.blocking_issues
