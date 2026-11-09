"""U-FORGE-13 — The Outcome Tracker (red tests).

Record every payload's real-world result (success or failure with
evidence and reason) in a queryable store. Zero network.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webpent.forge.indexer import PayloadIndexer
from webpent.forge.outcome_tracker import PayloadOutcome, OutcomeTracker

NOW = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)


def _outcome(**over):
    fields = dict(
        outcome_id="", payload_id="p-1", target_id="t-9",
        family="SQLI", context=None, sent_at=NOW,
        success=True, evidence={"status": 200, "reflected": True},
        failure_reason=None, phase_id="ph-1", campaign_id="c-1")
    fields.update(over)
    return PayloadOutcome(**fields)


@pytest.fixture
def tracker():
    return OutcomeTracker(PayloadIndexer())


def test_outcome_frozen():
    with pytest.raises(Exception):
        _outcome().success = False


def test_record_returns_id(tracker):
    oid = tracker.record(_outcome())
    assert oid


def test_record_id_deterministic(tracker):
    a = OutcomeTracker(PayloadIndexer()).record(_outcome())
    b = OutcomeTracker(PayloadIndexer()).record(_outcome())
    assert a == b


def test_round_trip(tracker):
    oid = tracker.record(_outcome())
    got = tracker.outcomes_for("p-1")
    assert len(got) == 1
    assert got[0].outcome_id == oid
    assert got[0].payload_id == "p-1"
    assert got[0].target_id == "t-9"
    assert got[0].success is True
    assert got[0].evidence == {"status": 200, "reflected": True}
    assert got[0].failure_reason is None
    assert got[0].phase_id == "ph-1"
    assert got[0].campaign_id == "c-1"
    assert got[0].sent_at == NOW


def test_failure_reason_and_evidence_preserved(tracker):
    tracker.record(_outcome(success=False,
                            failure_reason="waf blocked: cloudflare",
                            evidence={"status": 403}))
    got = tracker.outcomes_for("p-1")[0]
    assert got.success is False
    assert got.failure_reason == "waf blocked: cloudflare"
    assert got.evidence == {"status": 403}


def test_outcomes_isolated_by_payload(tracker):
    tracker.record(_outcome(payload_id="p-1"))
    tracker.record(_outcome(payload_id="p-2"))
    assert len(tracker.outcomes_for("p-1")) == 1
    assert len(tracker.outcomes_for("p-2")) == 1
    assert tracker.outcomes_for("p-404") == []


def test_chronological_order(tracker):
    later = _outcome(sent_at=NOW.replace(minute=1))
    tracker.record(later)
    tracker.record(_outcome())
    got = tracker.outcomes_for("p-1")
    assert [o.sent_at for o in got] == sorted(o.sent_at for o in got)


def test_multiple_records_kept(tracker):
    for i in range(3):
        tracker.record(_outcome(sent_at=NOW.replace(minute=i),
                                success=bool(i % 2)))
    assert len(tracker.outcomes_for("p-1")) == 3
