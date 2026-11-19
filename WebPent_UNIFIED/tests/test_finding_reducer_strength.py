from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.state.reducers import merge_findings


def _finding(*, confidence: Confidence, confidence_level: str) -> Finding:
    finding = Finding(
        title="Swagger SSRF",
        severity=Severity.HIGH,
        description="The application performs a server-side request.",
        tool_name="smart_campaigns",
        url="http://127.0.0.1:8000/swagger_ui",
        confidence=confidence,
        vuln_class=VulnClass.SSRF,
    )
    return finding.model_copy(update={"confidence_level": confidence_level})


def test_merge_findings_keeps_confirmed_over_later_tentative() -> None:
    confirmed = _finding(confidence=Confidence.CONFIRMED, confidence_level="Tool-Confirmed")
    tentative = confirmed.model_copy(
        update={"confidence": Confidence.TENTATIVE, "confidence_level": "Needs Human Review"}
    )

    merged = merge_findings([confirmed], [tentative])

    assert len(merged) == 1
    assert merged[0].id == confirmed.id
    assert merged[0].confidence == Confidence.CONFIRMED
    assert merged[0].confidence_level == "Tool-Confirmed"


def test_merge_findings_allows_confirmed_to_replace_tentative() -> None:
    tentative = _finding(confidence=Confidence.TENTATIVE, confidence_level="Needs Human Review")
    confirmed = tentative.model_copy(
        update={
            "confidence": Confidence.CONFIRMED,
            "confidence_level": "Tool-Confirmed",
            # M1-B (E-1): model-level proof requirement.
            "evidence": {"tool_confirmed_by": "test.fixture"},
        }
    )

    merged = merge_findings([tentative], [confirmed])

    assert len(merged) == 1
    assert merged[0].confidence == Confidence.CONFIRMED
