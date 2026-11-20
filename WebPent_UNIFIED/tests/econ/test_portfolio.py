"""U-ECON-10 — PortfolioManager tests (NC-ECON-1 charter, exact test names)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from webpent.econ.portfolio import (
    ACTIVE,
    ARCHIVED,
    DORMANT,
    WATCHING,
    AutoContext,
    PortfolioManager,
)

NOW = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
PORTFOLIO_YAML = """
targets:
  - target_id: t-corp
    program_id: example-corp
    state: WATCHING
    ev_per_hour: 120.0
    total_findings: 2
    total_payout_usd: 900
  - target_id: t-bank
    program_id: example-bank
    state: ACTIVE
    ev_per_hour: 400.0
    total_findings: 5
    total_payout_usd: 4200
  - target_id: t-social
    program_id: example-social
    state: DORMANT
    ev_per_hour: 15.0
    total_findings: 0
    total_payout_usd: 0
  - target_id: t-old
    program_id: example-gov-portal
    state: ARCHIVED
    ev_per_hour: 0.0
    total_findings: 0
    total_payout_usd: 0
"""


def _manager(tmp_path: Path) -> PortfolioManager:
    return PortfolioManager(now=NOW, log_path=tmp_path / "econ" / "transitions.jsonl")


def _load(tmp_path: Path) -> tuple[PortfolioManager, object]:
    yaml_file = tmp_path / "portfolio.yaml"
    yaml_file.write_text(PORTFOLIO_YAML, encoding="utf-8")
    mgr = _manager(tmp_path)
    return mgr, mgr.load(yaml_file)


def test_load_portfolio_from_yaml(tmp_path):
    mgr, portfolio = _load(tmp_path)
    assert set(portfolio.targets) == {"t-corp", "t-bank", "t-social", "t-old"}
    assert portfolio.targets["t-bank"].state == ACTIVE
    assert portfolio.targets["t-bank"].ev_per_hour == 400.0
    assert portfolio.targets["t-social"].state == DORMANT
    # corrupt/missing -> empty portfolio, never a raise
    broken = tmp_path / "broken.yaml"
    broken.write_text("targets: [unclosed", encoding="utf-8")
    assert mgr.load(broken).targets == {}
    assert mgr.load(tmp_path / "missing.yaml").targets == {}


def test_transition_updates_timestamp(tmp_path):
    mgr, portfolio = _load(tmp_path)
    # loaded value may equal NOW; what matters is that a transition updates it
    mgr.transition(portfolio, "t-corp", ACTIVE, "signal-high from CEM")
    entry = portfolio.targets["t-corp"]
    assert entry.state == ACTIVE
    assert entry.last_transition == NOW  # injected now, not the wall clock


def test_auto_transition_respects_triggers(tmp_path):
    mgr, portfolio = _load(tmp_path)
    ctx = AutoContext(
        now=NOW,
        high_signals={"t-corp": True},
        ev_per_hour_now={"t-bank": 180.0},
        ev_per_hour_week_ago={"t-bank": 400.0},
        consecutive_campaign_failures={"t-social": 3},
    )
    applied = mgr.auto_transition(portfolio, ctx)
    moves = {(t.target_id, t.from_state, t.to_state) for t in applied}
    assert ("t-corp", WATCHING, ACTIVE) in moves          # signal-high
    assert ("t-bank", ACTIVE, WATCHING) in moves          # EV fell 55%
    assert ("t-social", DORMANT, ARCHIVED) in moves       # 3 failures
    # ARCHIVED never moves automatically (L-8)
    assert portfolio.targets["t-old"].state == ARCHIVED
    # below-threshold EV drop does not demote
    portfolio2 = mgr.load(tmp_path / "portfolio.yaml")
    ctx2 = AutoContext(
        now=NOW,
        ev_per_hour_now={"t-bank": 250.0},
        ev_per_hour_week_ago={"t-bank": 400.0},
    )
    assert mgr.auto_transition(portfolio2, ctx2) == []


def test_daily_plan_totals_correct(tmp_path):
    mgr, portfolio = _load(tmp_path)
    plan = mgr.daily_plan(portfolio, 40.0)
    total = sum(plan.hours_by_state.values())
    assert abs(total - 40.0) < 1e-9
    assert abs(plan.hours_by_state[ACTIVE] - 24.0) < 1e-9   # 60%
    assert abs(plan.hours_by_state[WATCHING] - 12.0) < 1e-9  # 30%
    assert abs(plan.hours_by_state[DORMANT] - 4.0) < 1e-9    # 10%
    assert plan.hours_by_state[ARCHIVED] == 0.0
    assert plan.targets_by_state[ACTIVE] == ["t-bank"]
    with pytest.raises(ValueError):
        mgr.daily_plan(portfolio, 0.0)


def test_invalid_transition_rejected(tmp_path):
    mgr, portfolio = _load(tmp_path)
    with pytest.raises(ValueError, match="illegal transition"):
        mgr.transition(portfolio, "t-bank", ARCHIVED, "skip the queue")
    with pytest.raises(ValueError, match="illegal transition"):
        mgr.transition(portfolio, "t-social", ACTIVE, "dormant cannot jump")
    with pytest.raises(ValueError, match="already"):
        mgr.transition(portfolio, "t-bank", ACTIVE, "same state")
    with pytest.raises(ValueError, match="unknown target"):
        mgr.transition(portfolio, "t-ghost", ACTIVE, "who")
    with pytest.raises(ValueError, match="reason"):
        mgr.transition(portfolio, "t-corp", ACTIVE, "")
    # nothing moved
    assert portfolio.targets["t-bank"].state == ACTIVE


def test_transitions_logged(tmp_path):
    mgr, portfolio = _load(tmp_path)
    mgr.transition(portfolio, "t-corp", ACTIVE, "signal-high from CEM")
    log_file = tmp_path / "econ" / "transitions.jsonl"
    assert log_file.exists()
    rows = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    row = rows[0]
    assert row["target_id"] == "t-corp"
    assert row["from_state"] == WATCHING
    assert row["to_state"] == ACTIVE
    assert row["reason"] == "signal-high from CEM"
    assert row["advisory"] is True
    # an auto pass logs its moves too
    ctx = AutoContext(now=NOW, consecutive_campaign_failures={"t-social": 3})
    mgr.auto_transition(portfolio, ctx)
    rows2 = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    assert len(rows2) == 2
    assert rows2[1]["to_state"] == ARCHIVED
