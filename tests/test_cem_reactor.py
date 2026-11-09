"""v83 T5 / U-CEM-5: the change reactor."""

from __future__ import annotations

from pathlib import Path

from webpent.autonomous.cem.reactor import (
    MAX_ACTIVE_CAMPAIGNS,
    MINI_CAMPAIGN_BUDGET_FRACTION,
    ChangeReactor,
)

NOW = 1_700_000_000.0


def _diff(signal="signal-high", target="t1", item="/admin"):
    return {
        "target_id": target,
        "top_signal": signal,
        "change_count": 1,
        "changes": [{"field": "endpoints", "kind": "added", "item": item}],
    }


def test_quiet_diff_yields_no_proposal() -> None:
    reactor = ChangeReactor(Path("/nonexistent/x.json"), daily_budget=1000)
    for signal in ("noise", "signal-low"):
        assert reactor.propose(_diff(signal=signal), now=NOW) == []
    assert reactor.propose({}, now=NOW) == []
    assert reactor.propose("junk", now=NOW) == []  # type: ignore[arg-type]


def test_actionable_diff_proposes_mini_campaign_with_fraction_budget() -> None:
    reactor = ChangeReactor(Path("/nonexistent/x.json"), daily_budget=1000)
    proposals = reactor.propose(_diff(), now=NOW)
    assert len(proposals) == 1
    assert proposals[0]["kind"] == "mini_campaign"
    assert proposals[0]["budget"] == int(1000 * MINI_CAMPAIGN_BUDGET_FRACTION)
    assert proposals[0]["advisory"] is True


def test_critical_diff_proposes_wake_up(tmp_path: Path) -> None:
    reactor = ChangeReactor(tmp_path / "r.json", daily_budget=1000)
    proposals = reactor.propose(_diff(signal="critical"), now=NOW)
    assert proposals[0]["kind"] == "wake_up"


def test_cooldown_blocks_repeat_trigger_for_same_change(tmp_path: Path) -> None:
    reactor = ChangeReactor(tmp_path / "r.json", daily_budget=1000)
    diff = _diff()
    reactor.register_launch(reactor.propose(diff, now=NOW)[0], now=NOW)
    assert reactor.propose(diff, now=NOW + 3600) == []  # within 12h cooldown
    later = NOW + 13 * 3600
    assert reactor.propose(diff, now=later) != []


def test_different_change_is_not_blocked_by_cooldown(tmp_path: Path) -> None:
    reactor = ChangeReactor(tmp_path / "r.json", daily_budget=1000)
    reactor.register_launch(reactor.propose(_diff(item="/admin"), now=NOW)[0], now=NOW)
    other = reactor.propose(_diff(item="/api/v2"), now=NOW + 60)
    assert other and other[0]["change_key"] != _diff(item="/admin")["changes"][0]["item"]


def test_slot_cap_of_four_active_campaigns(tmp_path: Path) -> None:
    reactor = ChangeReactor(tmp_path / "r.json", daily_budget=1000)
    launched = 0
    for i in range(MAX_ACTIVE_CAMPAIGNS):
        proposal = reactor.propose(_diff(item=f"/p{i}", target=f"t{i}"), now=NOW + i * 60)
        if proposal and reactor.register_launch(proposal[0], now=NOW + i * 60):
            launched += 1
    assert launched == MAX_ACTIVE_CAMPAIGNS
    assert len(reactor.active(NOW)) == MAX_ACTIVE_CAMPAIGNS
    assert reactor.propose(_diff(item="/new", target="tX"), now=NOW) == []


def test_campaigns_expire_after_ttl(tmp_path: Path) -> None:
    reactor = ChangeReactor(tmp_path / "r.json", daily_budget=1000, campaign_ttl_hours=1.0)
    reactor.register_launch(reactor.propose(_diff(), now=NOW)[0], now=NOW)
    assert len(reactor.active(NOW + 0.5 * 3600)) == 1
    assert reactor.active(NOW + 2 * 3600) == []


def test_roundtrip_and_corruption_degrade_cleanly(tmp_path: Path) -> None:
    path = tmp_path / "r.json"
    reactor = ChangeReactor(path, daily_budget=1000)
    reactor.register_launch(reactor.propose(_diff(), now=NOW)[0], now=NOW)
    reloaded = ChangeReactor(path, daily_budget=1000)
    assert len(reloaded.active(NOW)) == 1

    path.write_text("{broken", encoding="utf-8")
    broken = ChangeReactor(path, daily_budget=1000)
    assert broken.active(NOW) == []
    assert broken.propose(_diff(), now=NOW)[0]["kind"] == "mini_campaign"


def test_garbage_launch_is_refused(tmp_path: Path) -> None:
    reactor = ChangeReactor(tmp_path / "r.json", daily_budget=1000)
    assert reactor.register_launch({}, now=NOW) is None
    assert reactor.register_launch("junk", now=NOW) is None  # type: ignore[arg-type]
    # RT83-3: an inflated proposal clamps to the mini-campaign budget, not the
    # whole daily budget (kind defaults to mini_campaign)
    assert reactor.register_launch({"target_id": "t1", "budget": 10**9}, now=NOW)[
        "budget"
    ] == reactor.budget_per_campaign()


def test_register_launch_clamps_to_mini_campaign_budget(tmp_path):
    """RT83-3: an inflated proposal cannot register above the mini-campaign cap."""
    reactor = ChangeReactor(tmp_path / "reactor.json", daily_budget=2000)
    proposal = {"target_id": "t.example", "change_key": "abc", "kind": "mini_campaign",
                "budget": 99999}
    campaign = reactor.register_launch(proposal, now=0.0)
    assert campaign["budget"] == reactor.budget_per_campaign()


def test_register_launch_wake_up_keeps_daily_budget_cap(tmp_path):
    """RT83-3: wake_up campaigns may use up to the full daily budget."""
    reactor = ChangeReactor(tmp_path / "reactor.json", daily_budget=2000)
    proposal = {"target_id": "t.example", "change_key": "abc", "kind": "wake_up",
                "budget": 99999}
    campaign = reactor.register_launch(proposal, now=0.0)
    assert campaign["budget"] == reactor.daily_budget
