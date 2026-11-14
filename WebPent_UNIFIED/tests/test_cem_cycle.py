"""v83 T4b: the pure CEM cycle and the 72-hour simulation."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from webpent.autonomous.cem.cycle import (
    load_cem_state,
    new_cem_state,
    run_cem_cycle,
    save_cem_state,
)
from webpent.autonomous.cem.scheduler import PoliteScheduler
from webpent.autonomous.cem.snapshot import SnapshotStore

SCOPE = ["example.com"]


def _ts(hour: int) -> float:
    return datetime(2023, 11, 14, hour, tzinfo=timezone.utc).timestamp()


def _fetchers(subdomains=(), endpoints=(), headers=None):
    return {
        "fetch_subdomains": lambda: list(subdomains),
        "fetch_endpoints": lambda: list(endpoints),
        "fetch_headers": lambda: dict(headers or {}),
        "fetch_cert_expiry": lambda: "",
        "fetch_js_hashes": lambda: {},
        "fetch_tech_stack": lambda: [],
        "fetch_response_shapes": lambda: {},
    }


def _fresh(tmp_path: Path) -> tuple[SnapshotStore, PoliteScheduler]:
    store = SnapshotStore(tmp_path / "snap.json")
    scheduler = PoliteScheduler(
        tmp_path / "sched.json", active_hours="00:00-23:59", daily_request_cap=100000
    )
    return store, scheduler


def test_first_cycle_observes_without_diff_alerts(tmp_path: Path) -> None:
    store, scheduler = _fresh(tmp_path)
    state = new_cem_state(targets=["app.example.com"])
    report = run_cem_cycle(
        state, now=_ts(10), snapshot_store=store, scheduler=scheduler,
        fetchers=_fetchers(subdomains=["app.example.com"], endpoints=["/login"]),
        scope_entries=SCOPE,
    )
    assert not report["skipped"]
    assert len(report["observed"]) == 1
    assert report["observed"][0]["first_observation"] is True
    assert report["proposals"] == []


def test_kill_switch_skips_the_cycle_without_spend(tmp_path: Path) -> None:
    store, scheduler = _fresh(tmp_path)
    scheduler.kill_switch.engage(reason="halt", now=_ts(10))
    state = new_cem_state(targets=["app.example.com"])
    report = run_cem_cycle(state, now=_ts(10), snapshot_store=store, scheduler=scheduler,
                          fetchers=_fetchers(endpoints=["/a"]), scope_entries=SCOPE)
    assert report["skipped"]
    assert report["observed"] == [] and report["spend"] == 0
    assert state["cycle_count"] == 0  # state untouched on a skipped cycle


def test_out_of_scope_subdomain_yields_alert_not_proposal(tmp_path: Path) -> None:
    store, scheduler = _fresh(tmp_path)
    state = new_cem_state(targets=["app.example.com"])
    run_cem_cycle(state, now=_ts(10), snapshot_store=store, scheduler=scheduler,
                  fetchers=_fetchers(subdomains=["a.example.com"]), scope_entries=SCOPE)
    report = run_cem_cycle(
        state, now=_ts(11), snapshot_store=store, scheduler=scheduler,
        fetchers=_fetchers(subdomains=["a.example.com", "evil.other.net"]),
        scope_entries=SCOPE,
    )
    kinds = {a["kind"] for a in report["alerts"]}
    assert "scope_drift" in kinds
    assert all(p.get("target_id") != "evil.other.net" for p in report["proposals"])


def test_changed_target_produces_mini_campaign_proposal(tmp_path: Path) -> None:
    store, scheduler = _fresh(tmp_path)
    state = new_cem_state(targets=["app.example.com"])
    run_cem_cycle(state, now=_ts(10), snapshot_store=store, scheduler=scheduler,
                  fetchers=_fetchers(endpoints=["/login"]), scope_entries=SCOPE)
    report = run_cem_cycle(
        state, now=_ts(11), snapshot_store=store, scheduler=scheduler,
        fetchers=_fetchers(endpoints=["/login", "/admin"]),
        scope_entries=SCOPE,
    )
    assert any(p["kind"] == "mini_campaign" for p in report["proposals"])


def test_new_subdomain_produces_wake_up_proposal(tmp_path: Path) -> None:
    store, scheduler = _fresh(tmp_path)
    state = new_cem_state(targets=["app.example.com"])
    run_cem_cycle(state, now=_ts(10), snapshot_store=store, scheduler=scheduler,
                  fetchers=_fetchers(subdomains=["app.example.com"]), scope_entries=SCOPE)
    report = run_cem_cycle(
        state, now=_ts(11), snapshot_store=store, scheduler=scheduler,
        fetchers=_fetchers(subdomains=["app.example.com", "new.example.com"]),
        scope_entries=SCOPE,
    )
    assert any(p["kind"] == "wake_up" for p in report["proposals"])


def test_broken_fetcher_degrades_section_not_cycle(tmp_path: Path) -> None:
    store, scheduler = _fresh(tmp_path)
    state = new_cem_state(targets=["app.example.com"])

    def boom() -> list[str]:
        raise RuntimeError("fetcher down")

    fetchers = _fetchers(endpoints=["/a"])
    fetchers["fetch_endpoints"] = boom
    report = run_cem_cycle(state, now=_ts(10), snapshot_store=store, scheduler=scheduler,
                           fetchers=fetchers, scope_entries=SCOPE)
    assert report["observed"][0]["snapshot_hash"]


def test_state_roundtrip_and_corruption(tmp_path: Path) -> None:
    state = new_cem_state(targets=["app.example.com"])
    state["cycle_count"] = 7
    save_cem_state(state, tmp_path / "cem_state.json")
    reloaded = load_cem_state(tmp_path / "cem_state.json")
    assert reloaded["cycle_count"] == 7
    assert reloaded["targets"]["app.example.com"]["enabled"] is True

    (tmp_path / "cem_state.json").write_text("{junk", encoding="utf-8")
    assert load_cem_state(tmp_path / "cem_state.json")["cycle_count"] == 0


def test_reactor_hook_receives_diff_and_can_propose(tmp_path: Path) -> None:
    store, scheduler = _fresh(tmp_path)
    state = new_cem_state(targets=["app.example.com"])
    seen: list[str] = []

    class FakeReactor:
        def propose(self, diff, *, now):
            seen.append(diff["top_signal"])
            return [{"kind": "custom", "advisory": True}] if diff["top_signal"] != "noise" else []

    run_cem_cycle(state, now=_ts(10), snapshot_store=store, scheduler=scheduler,
                  fetchers=_fetchers(subdomains=["app.example.com"]), scope_entries=SCOPE,
                  reactor=FakeReactor())
    report = run_cem_cycle(state, now=_ts(11), snapshot_store=store, scheduler=scheduler,
                           fetchers=_fetchers(subdomains=["app.example.com", "x.example.com"]),
                           scope_entries=SCOPE, reactor=FakeReactor())
    assert seen[-1] == "critical"
    assert any(p["kind"] == "custom" for p in report["proposals"])


    class Exploding:
        def propose(self, diff, *, now):
            raise RuntimeError("reactor down")

    report = run_cem_cycle(state, now=_ts(12), snapshot_store=store, scheduler=scheduler,
                           fetchers=_fetchers(), scope_entries=SCOPE, reactor=Exploding())
    assert report["observed"]


def test_simulation_72_hours_12_cycles_state_stays_bounded(tmp_path: Path) -> None:
    """The declared stand-in for the operator's 72-hour run criterion."""
    store, scheduler = _fresh(tmp_path)
    state_path = tmp_path / "cem_state.json"
    state = new_cem_state(targets=["app.example.com", "shop.example.com"])
    start = datetime(2023, 11, 14, 8, tzinfo=timezone.utc)

    scenario = []
    for cycle in range(12):
        # quiet, quiet, one new subdomain (critical), then noise, ...
        if cycle == 2:
            scenario.append(_fetchers(subdomains=["app.example.com", "extra.example.com"]))
        elif cycle == 5:
            scenario.append(_fetchers(endpoints=["/api/v2"]))
        else:
            scenario.append(_fetchers(subdomains=["app.example.com"]))

    proposals = 0
    for cycle in range(12):
        now = (start + timedelta(hours=6) * cycle).timestamp()
        report = run_cem_cycle(
            state, now=now, snapshot_store=store, scheduler=scheduler,
            fetchers=scenario[cycle], scope_entries=SCOPE,
        )
        assert not report["skipped"]
        proposals += len(report["proposals"])
    save_cem_state(state, state_path)

    assert state["cycle_count"] == 12
    assert proposals >= 1  # the change was noticed
    assert len(store.per_target_counts()) == 2
    assert all(v <= 64 for v in store.per_target_counts().values())
    on_disk = json.loads(state_path.read_text(encoding="utf-8"))
    assert len(on_disk["targets"]) == 2
    # the snapshot file is bounded on disk too
    snap_on_disk = json.loads((tmp_path / "snap.json").read_text(encoding="utf-8"))
    assert all(len(v) <= 64 for v in snap_on_disk.values())


def test_cycle_idempotent_on_unchanged_target(tmp_path: Path) -> None:
    store, scheduler = _fresh(tmp_path)
    state = new_cem_state(targets=["app.example.com"])
    fetchers = _fetchers(subdomains=["app.example.com"], endpoints=["/a"])

    first = run_cem_cycle(state, now=_ts(10), snapshot_store=store, scheduler=scheduler,
                          fetchers=fetchers, scope_entries=SCOPE)
    second = run_cem_cycle(state, now=_ts(11), snapshot_store=store, scheduler=scheduler,
                           fetchers=fetchers, scope_entries=SCOPE)
    assert first["proposals"] == [] == second["proposals"]
    assert second["observed"][0]["diff"]["change_count"] == 0


def test_cycle_spends_only_what_scheduler_granted(tmp_path: Path) -> None:
    """RT83-1: the declared spend never exceeds what the scheduler granted."""
    store = SnapshotStore(tmp_path / "snap.json")
    scheduler = PoliteScheduler(
        tmp_path / "sched.json", active_hours="00:00-23:59", daily_request_cap=30
    )
    state = new_cem_state(targets=["a.example.com", "b.example.com"])
    report = run_cem_cycle(
        state, now=_ts(10), snapshot_store=store, scheduler=scheduler,
        fetchers=_fetchers(subdomains=["a.example.com"]),
        scope_entries=SCOPE,
        requests_per_observation=20,
    )
    # two targets x 20 requested = 40, but the daily cap grants only 30:
    # the first observation (20) runs, the second cannot fit whole
    assert report["permission"]["granted"] == 30
    assert report["spend"] == 20
    # the second target could not afford its observation this cycle
    assert "b.example.com" in report["skipped_budget"]
    assert len(report["observed"]) == 1


def test_cycle_skipped_budget_empty_when_budget_fits(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "snap.json")
    scheduler = PoliteScheduler(
        tmp_path / "sched.json", active_hours="00:00-23:59", daily_request_cap=100000
    )
    state = new_cem_state(targets=["a.example.com"])
    report = run_cem_cycle(
        state, now=_ts(10), snapshot_store=store, scheduler=scheduler,
        fetchers=_fetchers(subdomains=["a.example.com"]),
        scope_entries=SCOPE,
    )
    assert report["skipped_budget"] == []
    assert report["spend"] == 20
