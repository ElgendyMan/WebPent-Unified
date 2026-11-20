# tests/test_campaign_scheduler.py
"""PROPOSALS_ULTIMATE_V3 §5 (2026-11-01) test suite: scheduled campaigns.

Covers the ScheduledCampaign record (fail-closed validation: unknown
fields, missing fields, bad schedule, naive timestamps, bad caps), the
JSONL store (append, duplicate refusal, bad-line refusal), the state
file (atomic write readable by the next call, corrupt refusal), due
computation (once/daily/weekly, drift rule), the wake loop (flag gate,
kill-switch refusal before any wake, not-due skip, scope re-check at
every wake with clean stop, cap pre- and post-checks with clean stops,
once-completion, periodic next_due advance, runner error isolation,
per-campaign atomic state write) and the CLI command contract. The
runner is a fake everywhere — the module owns no execution.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from typer.testing import CliRunner

from webpent.scheduler.campaign_scheduler import (
    CampaignRunState,
    CampaignScheduleStore,
    RunOutcome,
    SchedulerError,
    SchedulerStateFile,
    ScheduledCampaign,
    next_due_after,
    parse_iso_utc,
    run_due_campaigns,
)

NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
NOW_ISO = "2026-11-01T12:00:00Z"


def _campaign(**overrides) -> ScheduledCampaign:
    base = dict(
        campaign_id="camp-1",
        target_ref="https://target.example.com",
        schedule="once",
        start_at="2026-11-01T09:00:00Z",
        budget_usd_cap=10.0,
        wallclock_minutes_cap=60.0,
        max_findings_cap=50,
    )
    base.update(overrides)
    return ScheduledCampaign(**base)


def _activated(**extra):
    from webpent.config.settings import Settings, activate_settings

    return activate_settings(Settings(enable_scheduler=True, **extra))


def _ok_runner(spend=1.0, findings=2, minutes=5.0):
    calls: list[str] = []

    def runner(campaign, state):
        calls.append(campaign.campaign_id)
        return RunOutcome(spend_usd=spend, findings_count=findings,
                          wallclock_minutes=minutes)

    runner.calls = calls
    return runner


# ---------------------------------------------------------------------------
# Record validation.
# ---------------------------------------------------------------------------


class TestScheduledCampaign:
    def test_roundtrip(self):
        record = _campaign()
        assert ScheduledCampaign.from_dict(record.to_dict()) == record

    def test_unknown_fields_refused(self):
        with pytest.raises(SchedulerError, match="scheduler_record_unknown_fields"):
            ScheduledCampaign.from_dict({**_campaign().to_dict(), "bounty": "1"})

    def test_missing_fields_refused(self):
        data = _campaign().to_dict()
        del data["start_at"]
        with pytest.raises(SchedulerError, match="scheduler_record_missing_fields"):
            ScheduledCampaign.from_dict(data)

    def test_bad_schedule_refused(self):
        with pytest.raises(SchedulerError, match="scheduler_bad_schedule"):
            _campaign(schedule="hourly")

    def test_naive_timestamp_refused(self):
        with pytest.raises(SchedulerError, match="scheduler_naive_timestamp"):
            _campaign(start_at="2026-11-01T09:00:00")

    def test_bad_caps_refused(self):
        with pytest.raises(SchedulerError, match="scheduler_bad_budget_cap"):
            _campaign(budget_usd_cap=-1)
        with pytest.raises(SchedulerError, match="scheduler_bad_caps"):
            _campaign(max_findings_cap=0)
        with pytest.raises(SchedulerError, match="scheduler_bad_caps"):
            _campaign(wallclock_minutes_cap=0)

    def test_parse_iso_utc_forms(self):
        assert parse_iso_utc("2026-11-01T12:00:00Z") == NOW
        assert parse_iso_utc("2026-11-01T15:00:00+03:00") == NOW
        with pytest.raises(SchedulerError, match="scheduler_bad_timestamp"):
            parse_iso_utc("not-a-time")


# ---------------------------------------------------------------------------
# Stores.
# ---------------------------------------------------------------------------


class TestStores:
    def test_store_roundtrip_and_duplicate_refusal(self, tmp_path):
        store = CampaignScheduleStore(tmp_path / "campaigns.jsonl")
        store.add(_campaign())
        store.add(_campaign(campaign_id="camp-2"))
        assert [c.campaign_id for c in store.list()] == ["camp-1", "camp-2"]
        with pytest.raises(SchedulerError, match="scheduler_duplicate_campaign"):
            store.add(_campaign())

    def test_store_bad_line_refused(self, tmp_path):
        store = CampaignScheduleStore(tmp_path / "campaigns.jsonl")
        store.add(_campaign())
        with store.path.open("a", encoding="utf-8") as fh:
            fh.write('{"campaign_id": "broken"}\n')
        with pytest.raises(SchedulerError, match="scheduler_store_bad_line"):
            store.list()

    def test_state_file_atomic_and_readable_by_next_call(self, tmp_path):
        state_file = SchedulerStateFile(tmp_path / "state.json")
        assert state_file.get("camp-1") is None
        state_file.put(CampaignRunState(campaign_id="camp-1", next_due=NOW_ISO))
        state = state_file.get("camp-1")
        assert state is not None and state.next_due == NOW_ISO
        # atomic: no tmp residue
        assert list(tmp_path.glob(".scheduler-*")) == []

    def test_state_file_corrupt_refused(self, tmp_path):
        state_file = SchedulerStateFile(tmp_path / "state.json")
        state_file.path.write_text("{not json")
        with pytest.raises(SchedulerError, match="scheduler_state_unreadable"):
            state_file.get("camp-1")

    def test_state_from_dict_fail_closed(self):
        with pytest.raises(SchedulerError, match="scheduler_state_missing_fields"):
            CampaignRunState.from_dict({"campaign_id": "x"})


# ---------------------------------------------------------------------------
# Due computation.
# ---------------------------------------------------------------------------


class TestDue:
    def test_once_has_no_next_due(self):
        with pytest.raises(SchedulerError, match="scheduler_bad_schedule"):
            next_due_after(_campaign(), NOW)

    def test_daily_advances_one_day(self):
        assert next_due_after(_campaign(schedule="daily"), NOW) == "2026-11-02T12:00:00Z"

    def test_weekly_advances_one_week(self):
        assert next_due_after(_campaign(schedule="weekly"), NOW) == "2026-11-08T12:00:00Z"

    def test_drift_rule_runs_never_burst(self):
        # a wake that ran 3 hours late (start 09:00, ran 12:00): next due
        # follows the ACTUAL run time, not the stale 09:00 anchor — a
        # stale anchor would already be in the past and cause an
        # immediate back-to-back burst
        late = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)
        assert next_due_after(_campaign(schedule="daily"), late) == "2026-11-02T12:00:00Z"


# ---------------------------------------------------------------------------
# Wake loop.
# ---------------------------------------------------------------------------


class TestWakeLoop:
    def test_flag_off_refuses_before_reading_store(self, tmp_path):
        from webpent.config.settings import Settings, activate_settings

        store = CampaignScheduleStore(tmp_path / "c.jsonl")
        store.add(_campaign())
        with activate_settings(Settings(enable_scheduler=False)):
            with pytest.raises(SchedulerError, match="scheduler_flag_off"):
                run_due_campaigns(
                    store, SchedulerStateFile(tmp_path / "s.json"), runner=_ok_runner()
                )

    def test_kill_switch_engaged_refuses_before_any_wake(self, tmp_path):
        from webpent.safety import kill_switch

        store = CampaignScheduleStore(tmp_path / "c.jsonl")
        store.add(_campaign())
        runner = _ok_runner()
        kill_switch.engage("test")
        try:
            with _activated():
                with pytest.raises(SchedulerError, match="scheduler_kill_switch_engaged"):
                    run_due_campaigns(
                        store, SchedulerStateFile(tmp_path / "s.json"),
                        runner=runner, now=NOW,
                    )
        finally:
            kill_switch.release()
        assert runner.calls == []

    def test_not_due_skipped(self, tmp_path):
        store = CampaignScheduleStore(tmp_path / "c.jsonl")
        store.add(_campaign(start_at="2026-12-01T09:00:00Z"))
        runner = _ok_runner()
        with _activated():
            report = run_due_campaigns(
                store, SchedulerStateFile(tmp_path / "s.json"),
                runner=runner, now=NOW,
            )
        assert report.checked == 1
        assert report.woken == []
        assert report.skipped[0]["reason"] == "not_due"
        assert runner.calls == []

    def test_due_campaign_runs_within_caps(self, tmp_path):
        store = CampaignScheduleStore(tmp_path / "c.jsonl")
        store.add(_campaign())
        runner = _ok_runner(spend=2.0, findings=3, minutes=10.0)
        with _activated():
            report = run_due_campaigns(
                store, SchedulerStateFile(tmp_path / "s.json"),
                runner=runner, now=NOW,
            )
        assert report.woken[0]["action"] == "completed"  # once schedule
        state = SchedulerStateFile(tmp_path / "s.json").get("camp-1")
        assert state.status == "completed"
        assert state.cumulative_spend_usd == 2.0
        assert state.total_findings == 3
        assert state.run_count == 1

    def test_scope_change_stops_cleanly(self, tmp_path):
        store = CampaignScheduleStore(tmp_path / "c.jsonl")
        store.add(_campaign())
        runner = _ok_runner()
        with _activated():
            report = run_due_campaigns(
                store, SchedulerStateFile(tmp_path / "s.json"),
                runner=runner, now=NOW,
                scope_checker=lambda ref: False,
            )
        assert report.woken[0] == {
            "campaign_id": "camp-1", "action": "stopped",
            "stop_reason": "scope_changed",
        }
        assert runner.calls == []
        state = SchedulerStateFile(tmp_path / "s.json").get("camp-1")
        assert state.status == "stopped" and state.stop_reason == "scope_changed"

    def test_budget_cap_clean_stop_not_abort(self, tmp_path):
        store = CampaignScheduleStore(tmp_path / "c.jsonl")
        store.add(_campaign(schedule="daily", budget_usd_cap=3.0))
        runner = _ok_runner(spend=2.0, findings=1, minutes=5.0)
        with _activated():
            report = run_due_campaigns(
                store, SchedulerStateFile(tmp_path / "s.json"),
                runner=runner, now=NOW,
            )
        # first run: cumulative 2.0 <= 3.0 → ran; next day: runs again,
        # 4.0 > 3.0 → stopped cleanly (not an abort of the wake loop)
        assert report.woken[0]["action"] == "ran"
        with _activated():
            report = run_due_campaigns(
                store, SchedulerStateFile(tmp_path / "s.json"),
                runner=runner, now=NOW + timedelta(days=1),
            )
        assert report.woken[0]["action"] == "stopped"
        assert report.woken[0]["stop_reason"] == "budget_cap"
        state = SchedulerStateFile(tmp_path / "s.json").get("camp-1")
        assert state.status == "stopped"
        # campaign 2 unaffected by campaign 1's stop
        store.add(_campaign(campaign_id="camp-2", budget_usd_cap=100.0))
        with _activated():
            report2 = run_due_campaigns(
                store, SchedulerStateFile(tmp_path / "s.json"),
                runner=runner, now=NOW,
            )
        assert report2.woken[0]["campaign_id"] == "camp-2"

    def test_periodic_next_due_written_and_reread(self, tmp_path):
        store = CampaignScheduleStore(tmp_path / "c.jsonl")
        store.add(_campaign(schedule="daily"))
        with _activated():
            run_due_campaigns(
                store, SchedulerStateFile(tmp_path / "s.json"),
                runner=_ok_runner(), now=NOW,
            )
        state_file = SchedulerStateFile(tmp_path / "s.json")
        state = state_file.get("camp-1")
        assert state.next_due == "2026-11-02T12:00:00Z"
        assert state.status == "scheduled"
        # next wake one hour later: not due
        runner = _ok_runner()
        with _activated():
            report = run_due_campaigns(
                store, state_file, runner=runner, now=NOW + timedelta(hours=1)
            )
        assert report.skipped and report.woken == []
        assert runner.calls == []

    def test_findings_cap_clean_stop(self, tmp_path):
        store = CampaignScheduleStore(tmp_path / "c.jsonl")
        store.add(_campaign(schedule="daily", max_findings_cap=3))
        runner = _ok_runner(findings=4)
        with _activated():
            report = run_due_campaigns(
                store, SchedulerStateFile(tmp_path / "s.json"),
                runner=runner, now=NOW,
            )
        assert report.woken[0]["action"] == "stopped"
        assert report.woken[0]["stop_reason"] == "findings_cap"

    def test_runner_error_isolated_state_intact(self, tmp_path):
        store = CampaignScheduleStore(tmp_path / "c.jsonl")
        store.add(_campaign())

        def bad_runner(campaign, state):
            raise RuntimeError("orchestrator down")

        with _activated():
            report = run_due_campaigns(
                store, SchedulerStateFile(tmp_path / "s.json"),
                runner=bad_runner, now=NOW,
            )
        assert report.woken[0]["action"] == "runner_error"
        # no partial state was written for the failed campaign, and the
        # campaign itself is intact in the store for the next wake
        assert SchedulerStateFile(tmp_path / "s.json").get("camp-1") is None
        assert store.find("camp-1") is not None

    def test_stopped_campaign_never_wakes_again(self, tmp_path):
        store = CampaignScheduleStore(tmp_path / "c.jsonl")
        store.add(_campaign())
        state_file = SchedulerStateFile(tmp_path / "s.json")
        state_file.put(CampaignRunState(
            campaign_id="camp-1", next_due=NOW_ISO, status="stopped",
            stop_reason="scope_changed",
        ))
        runner = _ok_runner()
        with _activated():
            report = run_due_campaigns(
                store, state_file, runner=runner, now=NOW,
            )
        assert report.woken == [] and report.skipped == []
        assert runner.calls == []


# ---------------------------------------------------------------------------
# CLI contract.
# ---------------------------------------------------------------------------


class TestCli:
    def test_cli_add_list_run_due(self, tmp_path, monkeypatch):
        from webpent.cli.commands import app
        from webpent.config.settings import Settings, activate_settings

        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        with activate_settings(Settings(
            enable_scheduler=True,
            scheduler_state_path=str(tmp_path / "sched"),
        )):
            result = runner.invoke(app, [
                "scheduler", "add",
                "--campaign-id", "cli-camp",
                "--target-ref", "https://target.example.com",
                "--schedule", "daily",
                "--start-at", "2026-11-01T09:00:00Z",
                "--budget-usd-cap", "5",
            ])
            assert result.exit_code == 0, result.output
            assert "scheduled cli-camp" in result.output

            listed = runner.invoke(app, ["scheduler", "list"])
            assert listed.exit_code == 0
            assert "cli-camp" in listed.output
            assert "next_due=2026-11-01T09:00:00Z" in listed.output

            ran = runner.invoke(app, [
                "scheduler", "run-due", "--now", "2026-11-01T12:00:00Z",
            ])
            assert ran.exit_code == 0, ran.output
            assert "cli-camp" in ran.output

    def test_cli_refuses_when_flag_off(self, tmp_path, monkeypatch):
        from webpent.cli.commands import app
        from webpent.config.settings import Settings, activate_settings

        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        with activate_settings(Settings(enable_scheduler=False)):
            result = runner.invoke(app, ["scheduler", "list"])
            assert result.exit_code == 2
            assert "scheduler disabled" in result.output

    def test_cli_refuses_without_state_path(self, tmp_path, monkeypatch):
        from webpent.cli.commands import app
        from webpent.config.settings import Settings, activate_settings

        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        with activate_settings(Settings(enable_scheduler=True, scheduler_state_path="")):
            result = runner.invoke(app, ["scheduler", "list"])
            assert result.exit_code == 2
            assert "scheduler_state_path" in result.output
