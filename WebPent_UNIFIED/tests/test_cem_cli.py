"""v83 T12 / U-CEM-12: the ``webpent cem`` operator CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from webpent.autonomous.cem.scheduler import KillSwitch
from webpent.cli.commands import app

runner = CliRunner()


@pytest.fixture()
def cem_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state_dir = tmp_path / "cem"
    monkeypatch.setenv("WEBPENT_CEM_DIR", str(state_dir))
    return state_dir


def _invoke(*args: str):
    return runner.invoke(app, ["cem", *args])


def _audit_lines(state_dir: Path) -> list[dict]:
    path = state_dir / "audit_log.jsonl"
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def test_start_registers_target_and_audits(cem_env: Path) -> None:
    result = _invoke("start", "example.com")
    assert result.exit_code == 0, result.output
    state = json.loads((cem_env / "cem_state.json").read_text(encoding="utf-8"))
    assert state["targets"]["example.com"]["enabled"] is True
    entries = _audit_lines(cem_env)
    assert entries and entries[-1]["command"] == "start"
    assert "example.com" in entries[-1]["target"]


def test_start_rejects_empty_target(cem_env: Path) -> None:
    result = _invoke("start", "   ")
    assert result.exit_code == 1
    assert not (cem_env / "audit_log.jsonl").exists() or not _audit_lines(cem_env)


def test_pause_and_resume_round_trip(cem_env: Path) -> None:
    assert _invoke("start", "a.com").exit_code == 0
    assert _invoke("start", "b.com").exit_code == 0
    assert _invoke("pause", "a.com").exit_code == 0
    state = json.loads((cem_env / "cem_state.json").read_text(encoding="utf-8"))
    assert state["targets"]["a.com"]["paused"] is True
    assert state["targets"]["b.com"]["paused"] is False
    assert _invoke("pause").exit_code == 0  # global pause
    state = json.loads((cem_env / "cem_state.json").read_text(encoding="utf-8"))
    assert all(meta["paused"] for meta in state["targets"].values())
    assert _invoke("resume").exit_code == 0
    state = json.loads((cem_env / "cem_state.json").read_text(encoding="utf-8"))
    assert not any(meta["paused"] for meta in state["targets"].values())


def test_kill_engages_kill_switch_file(cem_env: Path) -> None:
    result = _invoke("kill", "leaked credential")
    assert result.exit_code == 0, result.output
    switch = KillSwitch(cem_env / "scheduler_kill.json")
    assert switch.engaged() is True
    entries = _audit_lines(cem_env)
    assert entries[-1]["command"] == "kill"


def test_resume_keeps_kill_switch_engaged_by_default(cem_env: Path) -> None:
    """RT83-11: resume never silently disengages a deliberate kill switch."""
    assert _invoke("kill", "drill").exit_code == 0
    result = _invoke("resume")
    assert result.exit_code == 0
    switch = KillSwitch(cem_env / "scheduler_kill.json")
    assert switch.engaged() is True


def test_resume_clears_kill_switch_only_when_asked(cem_env: Path) -> None:
    assert _invoke("kill", "drill").exit_code == 0
    result = _invoke("resume", "--clear-kill-switch")
    assert result.exit_code == 0
    switch = KillSwitch(cem_env / "scheduler_kill.json")
    assert switch.engaged() is False
    assert "kill switch disengaged" in result.output
    assert _audit_lines(cem_env)[-1]["kill_disengaged"] == "True"


def test_status_reports_bounded_state(cem_env: Path) -> None:
    _invoke("start", "example.com")
    result = _invoke("status")
    assert result.exit_code == 0, result.output
    assert "targets: 1" in result.output
    assert "kill_switch: disengaged" in result.output


def test_digest_writes_markdown_and_json(cem_env: Path) -> None:
    _invoke("start", "example.com")
    result = _invoke("digest")
    assert result.exit_code == 0, result.output
    digest_md = cem_env / "digest" / "digest.md"
    digest_json = cem_env / "digest" / "digest.json"
    assert digest_md.exists() and digest_json.exists()
    payload = json.loads(digest_json.read_text(encoding="utf-8"))
    assert payload["advisory"] is True


def test_findings_degrades_to_empty_without_state(cem_env: Path) -> None:
    result = _invoke("findings")
    assert result.exit_code == 0, result.output
    assert "active: 0" in result.output


def test_audit_log_redacts_secrets_and_is_capped(cem_env: Path) -> None:
    _invoke("kill", "api_key=supersecret1234567890")
    lines = _audit_lines(cem_env)
    blob = json.dumps(lines)
    assert "supersecret1234567890" not in blob
    assert "[REDACTED_SECRET]" in blob

    # force the cap: write a long audit file, run one more command
    audit = cem_env / "audit_log.jsonl"
    audit.write_text("\n".join(json.dumps({"ts": 1, "command": "old"}) for _ in range(1500)) + "\n",
                     encoding="utf-8")
    _invoke("status")
    lines = _audit_lines(cem_env)
    assert len(lines) <= 1000
    assert lines[-1]["command"] == "status"
