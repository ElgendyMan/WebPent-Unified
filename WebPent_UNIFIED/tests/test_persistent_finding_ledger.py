from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.shared.persistent_finding_ledger import PersistentFindingLedger


def _finding(
    *,
    title: str,
    url: str,
    vuln_class: VulnClass,
    created_at: datetime,
    confidence: Confidence = Confidence.TENTATIVE,
    confidence_level: str = "Pending",
    evidence: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        title=title,
        severity=Severity.HIGH,
        description="persistent ledger regression finding",
        tool_name="regression-test",
        url=url,
        vuln_class=vuln_class,
        confidence=confidence,
        confidence_level=confidence_level,
        evidence=evidence,
        created_at=created_at,
    )


def test_cross_release_accumulation(tmp_path) -> None:
    """Old release findings remain when a later release discovers new issues."""
    ledger = PersistentFindingLedger(tmp_path / "ledger.sqlite3")
    first_release = [
        _finding(
            title="SQL injection",
            url="https://target.test/search",
            vuln_class=VulnClass.SQLI,
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ),
        _finding(
            title="Stored XSS",
            url="https://target.test/comments",
            vuln_class=VulnClass.XSS,
            created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        ),
    ]
    second_release = [
        _finding(
            title="Owner versus foreign invoice IDOR",
            url="https://target.test/invoices/1",
            vuln_class=VulnClass.IDOR,
            created_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
        ),
        _finding(
            title="Out-of-band SSRF",
            url="https://target.test/fetch",
            vuln_class=VulnClass.SSRF,
            created_at=datetime(2026, 2, 2, tzinfo=timezone.utc),
        ),
    ]

    ledger.merge("eng-1", first_release, release_id="v1.0")
    result = ledger.merge("eng-1", second_release, release_id="v2.0")

    assert len(result) == 4
    assert {finding.title for finding in result} == {
        "SQL injection",
        "Stored XSS",
        "Owner versus foreign invoice IDOR",
        "Out-of-band SSRF",
    }


def test_dedup_same_finding_across_releases_keeps_stronger_evidence(tmp_path) -> None:
    """The same logical finding is stored once and promoted when stronger."""
    ledger = PersistentFindingLedger(tmp_path / "ledger.sqlite3")
    pending = _finding(
        title="SQL injection",
        url="https://target.test/search",
        vuln_class=VulnClass.SQLI,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    confirmed = pending.model_copy(
        update={
            "confidence": Confidence.CONFIRMED,
            "confidence_level": "Tool-Confirmed",
            "tool_confirmed_by": "test.fixture",
            "evidence": {
                "authorization": "Bearer should-not-persist",
                # M1-B (E-1): model-level proof requirement — the
                # confirming gate must be named.
                "tool_confirmed_by": "test.fixture.ledger",
            },
            "created_at": datetime(2026, 2, 1, tzinfo=timezone.utc),
        }
    )

    ledger.merge("eng-1", [pending], release_id="v1.0")
    result = ledger.merge("eng-1", [confirmed], release_id="v2.0")

    assert len(result) == 1
    assert result[0].confidence == Confidence.CONFIRMED
    assert result[0].confidence_level == "Tool-Confirmed"

    with sqlite3.connect(str(tmp_path / "ledger.sqlite3")) as connection:
        raw = connection.execute("SELECT finding_json FROM cumulative_findings").fetchone()[0]
    assert "should-not-persist" not in raw
    assert "[REDACTED]" in raw


def test_engagement_isolation(tmp_path) -> None:
    """Findings from different engagement scopes never mix."""
    ledger = PersistentFindingLedger(tmp_path / "ledger.sqlite3")
    finding_a = _finding(
        title="SQL injection on tenant A",
        url="https://tenant-a.test/search",
        vuln_class=VulnClass.SQLI,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    finding_b = _finding(
        title="SQL injection on tenant B",
        url="https://tenant-b.test/search",
        vuln_class=VulnClass.SQLI,
        created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    ledger.merge("eng-a", [finding_a], release_id="v1.0")
    ledger.merge("eng-b", [finding_b], release_id="v1.0")

    assert [finding.title for finding in ledger.get("eng-a")] == [finding_a.title]
    assert [finding.title for finding in ledger.get("eng-b")] == [finding_b.title]
    assert ledger.get("eng-missing") == []
