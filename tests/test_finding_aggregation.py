from datetime import datetime, timezone

from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.shared.finding_aggregation import (
    aggregate_findings,
    default_engagement_id,
    finding_fingerprint,
)


def _finding(
    *,
    title: str,
    url: str,
    vuln_class: VulnClass,
    confidence: Confidence = Confidence.TENTATIVE,
    confidence_level: str = "Pending",
    created_at: datetime,
    evidence: dict | None = None,
) -> Finding:
    return Finding(
        title=title,
        severity=Severity.HIGH,
        description="regression finding",
        tool_name="test",
        url=url,
        vuln_class=vuln_class,
        confidence=confidence,
        confidence_level=confidence_level,
        created_at=created_at,
        evidence=evidence,
    )


def test_aggregate_findings_keeps_distinct_findings_from_multiple_runs() -> None:
    first = _finding(
        title="IDOR on invoice",
        url="https://target.test/invoices/1",
        vuln_class=VulnClass.IDOR,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    second = _finding(
        title="Stored XSS on comments",
        url="https://target.test/comments",
        vuln_class=VulnClass.XSS,
        created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    merged = aggregate_findings([first, second])

    assert len(merged) == 2
    assert {item.title for item in merged} == {first.title, second.title}


def test_aggregate_findings_does_not_replace_confirmed_with_new_candidate() -> None:
    confirmed = _finding(
        title="SQL injection",
        url="https://target.test/search?q=1",
        vuln_class=VulnClass.SQLI,
        confidence=Confidence.CONFIRMED,
        confidence_level="Tool-Confirmed",
        # M1-B (E-1): model-level proof requirement — a confirmed finding
        # must name its confirming gate.
        evidence={"tool_confirmed_by": "test.fixture.aggregation"},
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    candidate = _finding(
        title="SQL injection",
        url="https://target.test/search?q=2",
        vuln_class=VulnClass.SQLI,
        created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    merged = aggregate_findings([confirmed, candidate])

    assert len(merged) == 1
    assert merged[0].confidence_level == "Tool-Confirmed"
    assert merged[0].id == confirmed.id


def test_fingerprint_and_default_scope_are_deterministic() -> None:
    first = _finding(
        title="Open redirect",
        url="https://target.test/redirect/?next=https%3A%2F%2Fexample.test",
        vuln_class=VulnClass.OPEN_REDIRECT,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    second = first.model_copy(update={"url": "HTTPS://TARGET.TEST/redirect?next=https://example.test"})

    assert finding_fingerprint(first) == finding_fingerprint(second)
    assert default_engagement_id(first.url, "client-a") == default_engagement_id(
        first.url,
        "client-a",
    )
    assert default_engagement_id(first.url, "client-a") != default_engagement_id(
        first.url,
        "client-b",
    )
