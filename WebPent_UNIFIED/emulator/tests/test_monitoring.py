"""U-EMU-4 — Monitoring + fail2ban tests (5 tests)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from conftest import EMU_DIR, emulator_stack_up
from logparse import analyze


def _load_dashboard():
    spec = importlib.util.spec_from_file_location(
        "dashboard", EMU_DIR / "monitoring" / "dashboard.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


JAIL = (EMU_DIR / "monitoring" / "fail2ban" / "jail.local").read_text()


def test_fail2ban_bans_attacker() -> None:
    assert "enabled = true" in JAIL
    assert "nginx-limit-req" in JAIL
    assert "maxretry = 10" in JAIL
    assert "findtime = 60" in JAIL
    if not emulator_stack_up():
        pytest.skip("docker/emulator not running")
    # the jail fires on error.log limit_req lines; verify the log wiring
    compose_text = (EMU_DIR / "docker-compose.yml").read_text()
    assert "/var/log/nginx/" in compose_text  # shared logs mounted into f2b
    assert "F2B_LOG_TARGET=/var/log/nginx/fail2ban.log" in compose_text


def test_ban_duration_5min() -> None:
    assert "bantime = 300" in JAIL


def test_monitoring_tracks_requests(sample_logs: Path) -> None:
    report = analyze(sample_logs)
    assert report.total_requests == 5
    assert report.requests_per_ip == {"10.0.0.1": 1, "10.0.0.2": 4}
    assert report.blocked_403 == 1
    assert report.throttled_429 == 2
    assert report.top_attackers[0] == ("10.0.0.2", 4)
    assert report.rate_limit_hits == 2  # from error.log limit_req lines


def test_waf_triggers_logged(sample_logs: Path) -> None:
    report = analyze(sample_logs)
    assert report.waf_triggers == 3
    assert report.waf_rules_hit["942100"] == 2
    assert report.waf_rules_hit["941160"] == 1
    text = report.to_markdown()
    assert "942100" in text and "## WAF rules hit" in text


def test_dashboard_shows_data(sample_logs: Path, monkeypatch) -> None:
    dashboard = _load_dashboard()
    monkeypatch.setattr(dashboard, "LOG_DIR", sample_logs)
    data = dashboard.stats()
    assert data["blocked_403"] == 1
    assert data["throttled_429"] == 2
    assert data["top_attackers"][0] == "10.0.0.2"
    assert len(data["ban_events"]) == 1
    assert "Ban 10.0.0.2" in data["ban_events"][0]
