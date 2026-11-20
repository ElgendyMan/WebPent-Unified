"""U-FORGE-17 — The Payload Dashboard (red tests).

The corpus status view, exactly the spec's sections: totals, By
Family, By Quality, By Complexity (freshness), Learning. Rendered
from the real models (indexer + outcome tracker), deterministic,
zero network.
"""
from __future__ import annotations

import pytest

from webpent.forge.payload_dashboard import PayloadDashboard
from webpent.forge.outcome_tracker import OutcomeTracker, PayloadOutcome
from webpent.forge.schemas import (
    Family,
    NormalizedPayload,
    PayloadAttribution,
)
from webpent.forge.indexer import PayloadIndexer

from datetime import datetime, timedelta, timezone


def _attr(pid: str, days_old: int) -> PayloadAttribution:
    return PayloadAttribution(
        payload_id=pid,
        original_source="seclists",
        original_url="https://example.test/seclists",
        original_author="auth",
        license="MIT",
        license_url="https://example.test/MIT",
        ingested_at=datetime.now(timezone.utc) - timedelta(days=days_old),
    )


def _payload(pid: str, family: Family, complexity: str,
             days_old: int) -> NormalizedPayload:
    return NormalizedPayload(payload_id=pid, family=family,
                             subfamily="", raw=f"{pid}-raw",
                             complexity=complexity,
                             attribution=_attr(pid, days_old))


@pytest.fixture
def rig():
    indexer = PayloadIndexer()
    seeded = [
        _payload("q1", Family.SQLI, "expert", 10),
        _payload("q2", Family.SQLI, "moderate", 60),
        _payload("q3", Family.XSS, "simple", 120),
        _payload("q4", Family.XSS, "advanced", 15),
        _payload("q5", Family.SSRF, "moderate", 45),
    ]
    for p in seeded:
        indexer.store_payload(p)
    tracker = OutcomeTracker(indexer)

    def outcome(pid, target, success):
        return PayloadOutcome(
            outcome_id=f"o-{pid}-{target}",
            payload_id=pid, target_id=target, family="SQLI",
            context=None, sent_at=datetime.now(timezone.utc),
            success=success, evidence={}, failure_reason=None)

    tracker.record(outcome("q1", "t1", True))
    tracker.record(outcome("q1", "t2", True))
    tracker.record(outcome("q1", "t3", False))
    tracker.record(outcome("q2", "t1", True))
    tracker.record(outcome("q3", "t1", False))
    return indexer, tracker, PayloadDashboard(indexer, tracker)


def test_data_totals(rig):
    indexer, tracker, dashboard = rig
    data = dashboard.data()
    assert data["payloads"] == 5
    assert data["families"] == 3
    assert data["sources"] >= 1


def test_by_family_counts_and_percentages(rig):
    indexer, tracker, dashboard = rig
    by_family = dashboard.data()["by_family"]
    assert by_family["SQLI"]["count"] == 2
    assert by_family["SQLI"]["pct"] == pytest.approx(40.0, abs=0.1)
    assert by_family["XSS"]["count"] == 2
    total_pct = sum(v["pct"] for v in by_family.values())
    assert total_pct == pytest.approx(100.0, abs=0.5)


def test_by_quality_and_freshness(rig):
    indexer, tracker, dashboard = rig
    data = dashboard.data()
    assert data["by_quality"] == {
        "expert": 1, "advanced": 1, "moderate": 2, "simple": 1}
    freshness = data["by_complexity"]
    assert freshness["fresh"] == 3    # 10, 15, 45 days
    assert freshness["recent"] == 1   # 60 days
    assert freshness["stable"] == 1   # 120 days


def test_learning_section(rig):
    indexer, tracker, dashboard = rig
    learning = dashboard.data()["learning"]
    assert learning["total_outcomes"] == 5
    assert learning["success_rate"] == pytest.approx(0.6)
    assert learning["top_performer"]["payload_id"] == "q1"
    assert learning["top_performer"]["success_rate"] == \
        pytest.approx(2 / 3)


def test_render_contains_the_numbers(rig):
    indexer, tracker, dashboard = rig
    text = dashboard.render()
    for token in ("Payloads", "5", "SQLI", "By Family",
                  "Success rate", "60.0%", "q1"):
        assert token in text
    again = dashboard.render()
    assert text == again
