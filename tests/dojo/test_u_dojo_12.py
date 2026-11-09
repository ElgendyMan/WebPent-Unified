"""U-DOJO-12: progress ledger and the dojo CLI (plan Task 12)."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from webpent.cli.dojo import dojo_app
from webpent.dojo.progress import ProgressTracker

EXPECTED_COMMANDS = {
    "labs", "scenarios", "practice", "spar", "tournament", "skill",
    "weaknesses", "plan", "case-study", "train", "progress", "status",
}


def test_progress_history_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBPENT_DOJO_DIR", str(tmp_path))
    tracker = ProgressTracker()
    tracker.record({"kind": "practice", "scenario_id": "sqli-01", "score": 97.0})
    tracker.record({"kind": "practice", "scenario_id": "sqli-02", "score": 80.0})
    history = tracker.history()
    assert len(history) == 2
    assert history[0]["scenario_id"] == "sqli-01"
    assert history[1]["score"] == 80.0
    # the ledger is JSONL on disk inside the dojo dir and re-readable
    lines = (tmp_path / "history.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["score"] for line in lines] == [97.0, 80.0]


def test_progress_trends_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBPENT_DOJO_DIR", str(tmp_path))
    tracker = ProgressTracker()
    for score in (50.0, 60.0, 70.0, 80.0):
        tracker.record({"kind": "practice", "score": score})
    assert tracker.trend() == "improving"

    down = ProgressTracker(tmp_path / "declining")
    for score in (80.0, 70.0, 60.0, 50.0):
        down.record({"kind": "practice", "score": score})
    assert down.trend() == "declining"


def test_cli_has_12_commands():
    names = {
        (cmd.name or cmd.callback.__name__.replace("_", "-"))
        for cmd in dojo_app.registered_commands
    }
    assert names == EXPECTED_COMMANDS


def test_cli_status_prints_json(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBPENT_DOJO_DIR", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(dojo_app, ["status", "--dojo-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    from webpent.cli.dojo import PREAMBLE_LINE

    body = result.output.split(PREAMBLE_LINE + "\n", 1)[1]
    payload = json.loads(body)
    assert payload["scenarios"] > 0
    assert "sqli" in payload["families"]


def test_cli_writes_audit_line_capped(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBPENT_DOJO_DIR", str(tmp_path))
    audit = tmp_path / "audit_log.jsonl"
    audit.write_text(
        "\n".join(json.dumps({"n": i}) for i in range(1005)) + "\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(dojo_app, ["status", "--dojo-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    lines = audit.read_text(encoding="utf-8").splitlines()
    assert 0 < len(lines) <= 1000
    assert json.loads(lines[-1])["command"] == "status"
