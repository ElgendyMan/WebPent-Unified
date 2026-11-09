"""FEATURE_PROPOSALS ق11 — multi-target fleet portfolio manager.

Pins:
  * one entry per target with its OWN priority (1..5, 1=highest) and
    budget caps (USD / wallclock / findings), linked to the scheduler's
    ScheduledCampaign by campaign_id — the portfolio orders and budgets,
    it never re-implements scheduling,
  * plan_wave() is the operator-inspectable launch plan: priority
    ascending, FIFO within priority, capacity-bounded, with an explicit
    skipped list (state_X / budget_cap_reached / fleet_capacity_full) —
    nothing is silently dropped; planned targets carry the
    WorkerCoordinator-compatible work_unit_id,
  * record_outcome() accumulates spend and fails CLOSED at the caps:
    a target crossing any cap becomes exhausted and cannot be re-planned
    until the operator resumes it (resume on an exhausted target
    raises),
  * dashboard() is the read-only لوحة قيادة: fleet totals, spend vs
    caps, utilization, next-in-line preview,
  * fail-closed validation everywhere (PortfolioError on bad entries);
    no network (scheduler + workers own execution).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webpent.portfolio import (
    FleetDashboard,
    PlanWave,
    PortfolioEntry,
    PortfolioError,
    PortfolioManager,
)


def _entry(target: str, *, priority: int = 3, budget: float = 100.0, campaign: str | None = None):
    return PortfolioEntry(
        target_ref=target,
        campaign_id=campaign or f"camp-{target}",
        priority=priority,
        budget_usd_cap=budget,
        wallclock_minutes_cap=60.0,
        max_findings_cap=50,
    )


# ---------------------------------------------------------------------------
# entries and validation
# ---------------------------------------------------------------------------


def test_entry_requires_target_and_campaign() -> None:
    with pytest.raises(PortfolioError):
        PortfolioEntry(target_ref="", campaign_id="c1")
    with pytest.raises(PortfolioError):
        PortfolioEntry(target_ref="t1", campaign_id="  ")


def test_entry_priority_and_caps_are_validated() -> None:
    with pytest.raises(PortfolioError):
        PortfolioEntry(target_ref="t", campaign_id="c", priority=0)
    with pytest.raises(PortfolioError):
        PortfolioEntry(target_ref="t", campaign_id="c", priority=6)
    with pytest.raises(PortfolioError):
        PortfolioEntry(target_ref="t", campaign_id="c", budget_usd_cap=-1)
    with pytest.raises(PortfolioError):
        PortfolioEntry(target_ref="t", campaign_id="c", max_findings_cap=-5)
    entry = _entry("t1", budget=10.0)
    assert entry.work_unit_id() == "portfolio:camp-t1:t1"


def test_add_preserves_spend_and_operator_state_on_replace() -> None:
    manager = PortfolioManager()
    manager.add(_entry("t1"))
    manager.record_outcome("t1", {"cost_usd": 40.0})
    manager.pause("t1", reason="hold")
    # operator re-adds with a higher priority: spend + paused state survive
    manager.add(_entry("t1", priority=1, budget=200.0))
    entry = manager.get("t1")
    assert entry.priority == 1
    assert entry.budget_usd_cap == 200.0
    assert entry.spent_usd == 40.0
    assert entry.state == "paused"
    assert entry.pause_reason == "hold"


def test_unknown_target_operations_fail_closed() -> None:
    manager = PortfolioManager()
    with pytest.raises(PortfolioError):
        manager.pause("ghost")
    with pytest.raises(PortfolioError):
        manager.record_outcome("ghost", {"cost_usd": 1.0})
    assert manager.get("ghost") is None


# ---------------------------------------------------------------------------
# waves — priority order + explicit skips
# ---------------------------------------------------------------------------


def test_plan_wave_orders_by_priority_then_fifo() -> None:
    manager = PortfolioManager()
    manager.add(_entry("low", priority=5))
    manager.add(_entry("high", priority=1))
    manager.add(_entry("mid", priority=3))
    wave = manager.plan_wave(capacity=3)
    assert [p["target_ref"] for p in wave.planned] == ["high", "mid", "low"]
    assert wave.skipped == []
    assert wave.utilization == 1.0


def test_plan_wave_capacity_bounds_and_records_skips() -> None:
    manager = PortfolioManager()
    manager.add(_entry("a", priority=1))
    manager.add(_entry("b", priority=2))
    manager.add(_entry("c", priority=3))
    wave = manager.plan_wave(capacity=1)
    assert [p["target_ref"] for p in wave.planned] == ["a"]
    reasons = {s["target_ref"]: s["reason"] for s in wave.skipped}
    assert reasons == {"b": "fleet_capacity_full", "c": "fleet_capacity_full"}
    assert wave.utilization == 1.0
    # capacity 0 plans nothing but records everything, honestly
    empty = manager.plan_wave(capacity=0)
    assert empty.planned == []
    assert len(empty.skipped) == 3


def test_plan_wave_skips_paused_and_exhausted_with_reasons() -> None:
    manager = PortfolioManager()
    manager.add(_entry("paused-one", priority=1))
    manager.pause("paused-one", reason="hold")
    manager.add(_entry("poor-one", priority=2, budget=10.0))
    manager.record_outcome("poor-one", {"cost_usd": 10.0})
    manager.add(_entry("live-one", priority=3))
    wave = manager.plan_wave(capacity=5)
    assert [p["target_ref"] for p in wave.planned] == ["live-one"]
    reasons = {s["target_ref"]: s["reason"] for s in wave.skipped}
    assert reasons["paused-one"] == "state_paused"
    # poor-one was exhausted by record_outcome BEFORE the wave, so the
    # skip carries the state reason with the cap reason as detail
    assert reasons["poor-one"] == "state_exhausted"
    details = {s["target_ref"]: s["detail"] for s in wave.skipped}
    assert details["poor-one"] == "budget_cap_reached"


def test_plan_wave_work_unit_ids_match_coordinator_vocabulary() -> None:
    manager = PortfolioManager()
    manager.add(_entry("t1", campaign="camp-42"))
    wave = manager.plan_wave(capacity=1)
    assert wave.planned[0]["work_unit_id"] == "portfolio:camp-42:t1"


def test_zero_capacity_rejected_only_negative() -> None:
    manager = PortfolioManager()
    manager.add(_entry("t"))
    assert manager.plan_wave(capacity=0).planned == []  # zero is legal
    with pytest.raises(PortfolioError):
        manager.plan_wave(capacity=-1)


# ---------------------------------------------------------------------------
# outcomes — spend accounting + fail-closed caps
# ---------------------------------------------------------------------------


def test_record_outcome_accumulates_all_three_budgets() -> None:
    manager = PortfolioManager()
    manager.add(_entry("t1", budget=100.0))
    manager.record_outcome(
        "t1", {"cost_usd": 30.0, "wallclock_minutes": 20.0, "findings_confirmed": 4}
    )
    manager.record_outcome(
        "t1", {"cost_usd": 10.0, "wallclock_minutes": 5.0, "findings": 2}
    )
    entry = manager.get("t1")
    assert entry.spent_usd == 40.0
    assert entry.spent_wallclock_minutes == 25.0
    assert entry.findings == 6
    remaining = entry.remaining()
    assert remaining["usd"] == 60.0
    assert remaining["wallclock_minutes"] == 35.0
    assert remaining["findings"] == 44


def test_record_outcome_refuses_negatives_and_bad_numbers() -> None:
    manager = PortfolioManager()
    manager.add(_entry("t1"))
    with pytest.raises(PortfolioError):
        manager.record_outcome("t1", {"cost_usd": -1.0})
    with pytest.raises(PortfolioError):
        manager.record_outcome("t1", {"cost_usd": "lots"})


def test_budget_cap_pauses_target_and_resume_raises_until_operator() -> None:
    manager = PortfolioManager()
    manager.add(_entry("t1", budget=50.0))
    manager.record_outcome("t1", {"cost_usd": 50.0})
    entry = manager.get("t1")
    assert entry.state == "exhausted"
    assert entry.pause_reason == "budget_cap_reached"
    wave = manager.plan_wave(capacity=5)
    assert wave.planned == []
    # the entry was already exhausted by record_outcome, so the skip is
    # recorded with the state reason and the cap reason as detail
    assert wave.skipped[0]["reason"] == "state_exhausted"
    assert wave.skipped[0]["detail"] == "budget_cap_reached"
    with pytest.raises(PortfolioError):
        manager.resume("t1")


def test_wallclock_and_findings_caps_also_exhaust() -> None:
    manager = PortfolioManager()
    manager.add(_entry("time-capped", budget=0.0))
    manager.get("time-capped").wallclock_minutes_cap = 10.0
    manager.record_outcome("time-capped", {"wallclock_minutes": 10.0})
    assert manager.get("time-capped").state == "exhausted"

    manager2 = PortfolioManager()
    manager2.add(_entry("finding-capped", budget=0.0))
    manager2.get("finding-capped").max_findings_cap = 2
    manager2.record_outcome("finding-capped", {"findings": 2})
    assert manager2.get("finding-capped").state == "exhausted"


def test_resume_restores_active_state() -> None:
    manager = PortfolioManager()
    manager.add(_entry("t1"))
    manager.pause("t1", reason="maintenance")
    assert manager.resume("t1") is True
    entry = manager.get("t1")
    assert entry.state == "active"
    assert entry.pause_reason == ""
    wave = manager.plan_wave(capacity=5)
    assert [p["target_ref"] for p in wave.planned] == ["t1"]


# ---------------------------------------------------------------------------
# dashboard — the لوحة قيادة
# ---------------------------------------------------------------------------


def test_dashboard_reports_totals_and_next_in_line() -> None:
    manager = PortfolioManager()
    manager.add(_entry("a", priority=1, budget=100.0))
    manager.add(_entry("b", priority=2, budget=50.0))
    manager.add(_entry("c", priority=3, budget=0.0))
    manager.pause("c", reason="hold")
    manager.record_outcome("b", {"cost_usd": 50.0})
    dashboard = manager.dashboard()
    assert isinstance(dashboard, FleetDashboard)
    payload = dashboard.as_dict()
    totals = payload["totals"]
    assert totals["targets"] == 3
    assert totals["active"] == 1
    assert totals["paused"] == 1
    assert totals["exhausted"] == 1
    assert totals["total_spent_usd"] == 50.0
    assert totals["total_budget_usd_cap"] == 150.0
    assert totals["budget_utilization"] == pytest.approx(50.0 / 150.0, abs=1e-4)
    assert payload["next_in_line"] == ["a"]
    target_refs = [t["target_ref"] for t in payload["targets"]]
    assert target_refs == ["a", "b", "c"]  # priority order


def test_dashboard_is_json_safe() -> None:
    import json

    manager = PortfolioManager()
    manager.add(_entry("t1"))
    payload = manager.dashboard().as_dict()
    encoded = json.dumps(payload)  # must not raise
    assert isinstance(encoded, str)


def test_wave_as_dict_is_json_safe() -> None:
    import json

    manager = PortfolioManager()
    manager.add(_entry("t1"))
    wave = manager.plan_wave(capacity=2)
    assert isinstance(wave, PlanWave)
    assert isinstance(json.dumps(wave.as_dict()), str)


def test_injected_clock_makes_waves_deterministic() -> None:
    fixed = datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc)
    manager = PortfolioManager(now=lambda: fixed)
    manager.add(_entry("t1"))
    wave = manager.plan_wave(capacity=1)
    assert wave.created_at == "2026-11-04T12:00:00+00:00"
