"""Regression contracts for the bounded P2 reliability improvements."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from webpent.integrations import webhook
from webpent.models.findings import Finding, Severity


def _finding(confidence_level: str = "Tool-Confirmed") -> Finding:
    return Finding(
        title="Bounded webhook delivery",
        severity=Severity.MEDIUM,
        description="Synthetic regression finding.",
        tool_name="test",
        url="https://example.test/endpoint",
        confidence_level=confidence_level,
        # M1-B/E-1 provenance contract: a Tool-Confirmed finding must name
        # its confirming gate; this fixture predates that hardening.
        evidence={"tool_confirmed_by": "validator"} if confidence_level == "Tool-Confirmed" else {},
        id=uuid4(),
    )


@pytest.mark.asyncio
async def test_webhook_batch_respects_configured_concurrency(monkeypatch):
    active = 0
    peak = 0

    class _Settings:
        webhook_max_concurrency = 2

    async def fake_push(finding, webhook_url):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0)
        active -= 1
        return True

    monkeypatch.setattr(webhook, "get_settings", lambda: _Settings())
    monkeypatch.setattr(webhook, "push_to_webhook", fake_push)

    findings = [_finding() for _ in range(6)]
    findings.append(_finding("Pending"))
    result = await webhook.push_findings_batch(findings, "https://hooks.example.test")

    assert len(result) == 6
    assert all(result.values())
    assert peak <= 2


@pytest.mark.asyncio
async def test_webhook_batch_keeps_per_finding_failure_isolated(monkeypatch):
    class _Settings:
        webhook_max_concurrency = 2

    first = _finding()
    second = _finding()

    async def fake_push(finding, webhook_url):
        if finding.id == first.id:
            raise RuntimeError("synthetic failure")
        return True

    monkeypatch.setattr(webhook, "get_settings", lambda: _Settings())
    monkeypatch.setattr(webhook, "push_to_webhook", fake_push)

    result = await webhook.push_findings_batch([first, second], "https://hooks.example.test")

    assert result[str(first.id)] is False
    assert result[str(second.id)] is True


def test_grounding_reasoning_requires_minimum_quote_and_full_overlap():
    from webpent.shared.grounding import (
        citation_overlap_ratio,
        verify_all_citations,
        verify_citation,
    )

    assert citation_overlap_ratio("is vulnerable", "tool says is vulnerable") == 1.0
    assert verify_citation("500", "status=500")[0] is True

    grounded, hallucinated, quote_count = verify_all_citations(
        "YES <quote>500</quote>",
        "status=500",
    )
    assert grounded is False
    assert hallucinated == ["500"]
    assert quote_count == 1

    grounded, hallucinated, quote_count = verify_all_citations(
        "YES <quote>status=500</quote>",
        "status=500",
    )
    assert grounded is True
    assert hallucinated == []
    assert quote_count == 1


def test_grounding_thresholds_reject_invalid_configuration():
    from webpent.shared.grounding import verify_all_citations

    with pytest.raises(ValueError):
        verify_all_citations(
            "<quote>valid citation</quote>",
            "valid citation",
            min_citation_length=0,
        )
    with pytest.raises(ValueError):
        verify_all_citations(
            "<quote>valid citation</quote>",
            "valid citation",
            min_overlap_ratio=1.1,
        )


def test_oob_polling_is_bounded_by_max_attempts(monkeypatch):
    from webpent.agents.validator import agent as validator

    class _PendingFinding:
        confidence_level = "Needs Human Review"

    class _Database:
        calls = 0

        def get_finding(self, finding_id):
            self.calls += 1
            return _PendingFinding()

    database = _Database()
    monkeypatch.setattr(validator, "get_db_manager", lambda: database)

    assert validator._poll_for_oob_callback(
        uuid4(), timeout_seconds=30.0, max_attempts=1
    ) is None
    assert database.calls == 1


