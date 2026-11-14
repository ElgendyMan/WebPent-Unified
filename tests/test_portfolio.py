"""Tests for webpent.service.portfolio (Ultimate plan, proposal 6).

All inputs are injected — no service objects, no databases, no network.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webpent.service.portfolio import (
    MAX_CAMPAIGNS,
    compute_campaign_priority,
    order_campaign_queue,
    portfolio_dashboard,
)


def _snapshot(
    campaign_id: str,
    *,
    findings: int = 0,
    cost: float = 0.0,
    status: str = "running",
    severity: str | None = None,
) -> dict:
    return {
        "campaign_id": campaign_id,
        "status": status,
        "findings_confirmed": findings,
        "cost_usd": cost,
        "started_at": "2026-10-27T00:00:00+00:00",
        "current_phase": "recon",
        "highest_severity": severity,
    }


# ---------------------------------------------------------------------------
# portfolio_dashboard
# ---------------------------------------------------------------------------


def test_dashboard_aggregates_totals_across_campaigns() -> None:
    snapshots = {
        "alpha": _snapshot("alpha", findings=3, cost=1.5, severity="high"),
        "beta": _snapshot("beta", findings=2, cost=0.5, severity="critical"),
        "gamma": _snapshot("gamma", findings=0, cost=2.0),
    }
    dashboard = portfolio_dashboard(
        ["alpha", "beta", "gamma"], facade_snapshot_fn=lambda cid: snapshots[cid]
    )
    assert dashboard["totals"] == {
        "campaigns": 3,
        "findings_confirmed": 5,
        "cost_usd": pytest.approx(4.0),
    }
    assert dashboard["highest_severity_open"] == "critical"
    assert len(dashboard["campaigns"]) == 3
    parsed = datetime.fromisoformat(dashboard["generated_at"])
    assert parsed.tzinfo is not None


def test_dashboard_sorts_by_findings_desc_then_cost_asc() -> None:
    snapshots = {
        "low-findings-cheap": _snapshot("low-findings-cheap", findings=1, cost=0.1),
        "high-findings-expensive": _snapshot("high-findings-expensive", findings=5, cost=9.0),
        "high-findings-cheap": _snapshot("high-findings-cheap", findings=5, cost=1.0),
        "zero": _snapshot("zero", findings=0, cost=0.0),
    }
    dashboard = portfolio_dashboard(
        list(snapshots.keys()), facade_snapshot_fn=lambda cid: snapshots[cid]
    )
    order = [c["campaign_id"] for c in dashboard["campaigns"]]
    assert order == [
        "high-findings-cheap",  # 5 findings, cheaper of the two
        "high-findings-expensive",  # 5 findings, more expensive
        "low-findings-cheap",
        "zero",
    ]


def test_dashboard_empty_campaign_list() -> None:
    dashboard = portfolio_dashboard([])
    assert dashboard["campaigns"] == []
    assert dashboard["totals"] == {"campaigns": 0, "findings_confirmed": 0, "cost_usd": 0.0}
    assert dashboard["highest_severity_open"] is None
    assert dashboard["generated_at"]


def test_dashboard_default_stub_returns_honest_zero_snapshots() -> None:
    dashboard = portfolio_dashboard(["alpha", "beta"])  # no facade_snapshot_fn
    assert dashboard["totals"]["campaigns"] == 2
    assert dashboard["totals"]["findings_confirmed"] == 0
    assert dashboard["totals"]["cost_usd"] == 0.0
    for campaign in dashboard["campaigns"]:
        assert campaign["status"] == "unknown"
        assert campaign["findings_confirmed"] == 0


def test_dashboard_failing_snapshot_yields_honest_error_entry() -> None:
    def flaky(campaign_id: str) -> dict:
        if campaign_id == "broken":
            raise KeyError("campaign not found")
        return _snapshot(campaign_id, findings=2)

    dashboard = portfolio_dashboard(["ok", "broken"], facade_snapshot_fn=flaky)
    by_id = {c["campaign_id"]: c for c in dashboard["campaigns"]}
    assert by_id["ok"]["findings_confirmed"] == 2
    assert by_id["broken"]["status"] == "snapshot_error"
    assert by_id["broken"]["findings_confirmed"] == 0
    assert "KeyError" in by_id["broken"]["error"]
    # The healthy campaign still contributes to the totals.
    assert dashboard["totals"]["findings_confirmed"] == 2


def test_dashboard_highest_severity_prefers_open_and_ignores_unknown_labels() -> None:
    snapshots = {
        "a": _snapshot("a", severity="medium"),
        "b": {
            **_snapshot("b"),
            "highest_severity_open": "high",
            "highest_severity": "low",
        },
        "c": _snapshot("c", severity="not-a-severity"),
    }
    dashboard = portfolio_dashboard(
        list(snapshots), facade_snapshot_fn=lambda cid: snapshots[cid]
    )
    # "b" wins via its open-severity key; the unrankable label never wins.
    assert dashboard["highest_severity_open"] == "high"


def test_dashboard_bounds_campaign_count() -> None:
    dashboard = portfolio_dashboard([f"c{i}" for i in range(MAX_CAMPAIGNS + 50)])
    assert dashboard["totals"]["campaigns"] == MAX_CAMPAIGNS


# ---------------------------------------------------------------------------
# compute_campaign_priority
# ---------------------------------------------------------------------------


def test_priority_base_score_without_any_bonus() -> None:
    assert compute_campaign_priority("camp") == 0.5


def test_priority_lessons_bonus() -> None:
    lessons = [{"lesson": "target uses GraphQL"}]
    with_lessons = compute_campaign_priority("camp", lambda cid: lessons)
    without = compute_campaign_priority("camp", lambda cid: [])
    assert with_lessons == pytest.approx(0.7)
    assert without == 0.5


def test_priority_failing_lessons_lookup_counts_as_no_lessons() -> None:
    def broken(campaign_id: str):
        raise RuntimeError("lessons db unavailable")

    assert compute_campaign_priority("camp", broken) == 0.5


def test_priority_findings_rate_component() -> None:
    half = compute_campaign_priority(
        "camp", stats={"findings_confirmed": 5, "findings_total": 10}
    )
    full = compute_campaign_priority(
        "camp", stats={"findings_confirmed": 10, "findings_total": 10}
    )
    zero = compute_campaign_priority("camp", stats={"findings_confirmed": 0, "findings_total": 10})
    assert half == pytest.approx(0.6)  # 0.5 + 0.2*0.5
    assert full == pytest.approx(0.7)  # 0.5 + 0.2*1.0
    assert zero == 0.5
    # No stats at all -> no rate bonus.
    assert compute_campaign_priority("camp", stats=None) == 0.5


def test_priority_stalled_bonus_and_clamping() -> None:
    score = compute_campaign_priority(
        "camp",
        lambda cid: [{"lesson": "x"}],
        stats={"findings_confirmed": 10, "findings_total": 10, "stalled": True},
    )
    assert score == 1.0  # 0.5 + 0.2 + 0.2 + 0.1, clamped at 1.0
    stalled_only = compute_campaign_priority("camp", stats={"stalled": True})
    assert stalled_only == pytest.approx(0.6)


# ---------------------------------------------------------------------------
# order_campaign_queue
# ---------------------------------------------------------------------------


def test_queue_orders_by_priority_descending() -> None:
    stats = {
        "best": {"findings_confirmed": 10, "findings_total": 10},
        "mid": {"findings_confirmed": 5, "findings_total": 10},
        "worst": {},
    }
    lessons = {"best": [{"lesson": "known target"}]}
    queue = order_campaign_queue(
        ["worst", "best", "mid"],
        stats_by_campaign=stats,
        lessons_lookup=lambda cid: lessons.get(cid, []),
    )
    assert [cid for cid, _ in queue] == ["best", "mid", "worst"]
    assert queue[0][1] == pytest.approx(0.9)  # 0.5 + 0.2 lessons + 0.2 rate
    assert queue[1][1] == pytest.approx(0.6)  # 0.5 + 0.2*0.5
    assert queue[2][1] == 0.5


def test_queue_ties_keep_input_order() -> None:
    queue = order_campaign_queue(
        ["a", "b", "c"], stats_by_campaign={}, lessons_lookup=None
    )
    assert queue == [("a", 0.5), ("b", 0.5), ("c", 0.5)]


def test_queue_injected_lessons_change_the_order() -> None:
    stats = {"a": {"findings_confirmed": 1, "findings_total": 4}, "b": {}}
    without_lessons = order_campaign_queue(["a", "b"], stats_by_campaign=stats)
    assert [cid for cid, _ in without_lessons] == ["a", "b"]
    with_lessons = order_campaign_queue(
        ["a", "b"],
        stats_by_campaign=stats,
        lessons_lookup=lambda cid: [{"lesson": "x"}] if cid == "b" else [],
    )
    # b: 0.5 + 0.2 lessons = 0.7 beats a: 0.5 + 0.2*0.25 = 0.55.
    assert [cid for cid, _ in with_lessons] == ["b", "a"]
    assert with_lessons[0][1] == pytest.approx(0.7)


def test_queue_missing_stats_entries_score_as_empty() -> None:
    queue = order_campaign_queue(["known", "unknown"], stats_by_campaign={"known": {}})
    assert queue == [("known", 0.5), ("unknown", 0.5)]


def test_queue_bounds_campaign_count() -> None:
    queue = order_campaign_queue(
        [f"c{i}" for i in range(MAX_CAMPAIGNS + 10)], stats_by_campaign={}
    )
    assert len(queue) == MAX_CAMPAIGNS
