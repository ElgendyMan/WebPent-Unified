"""U-DOJO-12 CLI edge cases: every command honors preamble, ledger, and JSON."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from webpent.cli.dojo import PREAMBLE_LINE, dojo_app
from webpent.dojo.progress import ProgressTracker

runner = CliRunner()


@pytest.fixture()
def dojo_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBPENT_DOJO_DIR", str(tmp_path))
    return tmp_path


def _invoke(*args, **kwargs):
    result = runner.invoke(dojo_app, list(args), **kwargs)
    assert result.exit_code == 0, result.output
    return result


def _payload(result):
    return json.loads(result.output.split(PREAMBLE_LINE + "\n", 1)[1])


def test_labs_lists_templates(dojo_dir):
    result = _invoke("labs", "--dojo-dir", str(dojo_dir))
    payload = _payload(result)
    assert len(payload["templates"]) >= 5
    ids = {t["template_id"] for t in payload["templates"]}
    assert "flask_sqli_login" in ids


def test_scenarios_filter_by_family(dojo_dir):
    payload = _payload(_invoke("scenarios", "--family", "sqli"))
    assert payload["scenarios"]
    assert all(s["family"] == "sqli" for s in payload["scenarios"])


def test_scenarios_unknown_family_is_empty(dojo_dir):
    payload = _payload(_invoke("scenarios", "--family", "not-a-family"))
    assert payload["scenarios"] == []


def test_practice_records_a_ledger_entry(dojo_dir):
    _invoke("practice", "sqli-01", "--dojo-dir", str(dojo_dir))
    history = ProgressTracker(dojo_dir).history()
    assert len(history) == 1
    assert history[0]["command"] == "practice"
    assert history[0]["scenario_id"] == "sqli-01"


def test_spar_records_the_winner(dojo_dir):
    _invoke("spar", "sqli-01", "--agent", "naive", "--dojo-dir", str(dojo_dir))
    entry = ProgressTracker(dojo_dir).history()[0]
    assert entry["command"] == "spar"
    assert entry["winner"] == "blue"


def test_tournament_reports_four_standings(dojo_dir):
    payload = _payload(_invoke(
        "tournament", "--family", "sqli", "--dojo-dir", str(dojo_dir)
    ))
    assert len(payload["standings"]) == 4


def test_skill_on_empty_ledger_reports_insufficient(dojo_dir):
    payload = _payload(_invoke("skill", "--dojo-dir", str(dojo_dir)))
    assert payload["profiles"]
    assert all(p["sufficient"] is False for p in payload["profiles"])


def test_weaknesses_on_empty_ledger_is_empty(dojo_dir):
    payload = _payload(_invoke("weaknesses", "--dojo-dir", str(dojo_dir)))
    assert payload["weaknesses"] == []


def test_plan_on_empty_ledger_warms_up_only(dojo_dir):
    payload = _payload(_invoke("plan", "--dojo-dir", str(dojo_dir)))
    assert payload["focus"] == []
    assert payload["sparring"] == []
    assert payload["warmup"]


def test_train_writes_session_state(dojo_dir):
    result = _invoke("train", "--family", "sqli", "--dojo-dir", str(dojo_dir))
    assert "session state:" in result.output
    states = list(dojo_dir.glob("trainer_session*.json"))
    assert states


def test_progress_on_empty_ledger_is_flat(dojo_dir):
    payload = _payload(_invoke("progress", "--dojo-dir", str(dojo_dir)))
    assert payload["entries"] == 0
    assert payload["trend"] == "flat"


def test_case_study_writes_a_sanitized_file(dojo_dir):
    _invoke("case-study", "sqli-01", "--dojo-dir", str(dojo_dir))
    studies = list(dojo_dir.glob("case_study_sqli-01.md"))
    assert len(studies) == 1
    text = studies[0].read_text(encoding="utf-8")
    assert text.startswith("# Dojo Case Study: sqli-01")
    assert "Sanitization notice" in text


def test_every_command_opens_with_the_preamble(dojo_dir):
    for args in (
        ["labs"], ["scenarios"], ["progress"], ["status"],
        ["weaknesses"], ["plan"], ["skill"],
    ):
        result = _invoke(*args, "--dojo-dir", str(dojo_dir))
        assert result.output.startswith(PREAMBLE_LINE), f"{args} lost the preamble"


def test_unknown_agent_name_is_rejected(dojo_dir):
    result = runner.invoke(
        dojo_app, ["practice", "sqli-01", "--agent", "ghost", "--dojo-dir",
                   str(dojo_dir)]
    )
    assert result.exit_code != 0
    assert ProgressTracker(dojo_dir).history() == []


def test_audit_log_accumulates_across_commands(dojo_dir):
    _invoke("labs", "--dojo-dir", str(dojo_dir))
    _invoke("progress", "--dojo-dir", str(dojo_dir))
    _invoke("status", "--dojo-dir", str(dojo_dir))
    lines = (dojo_dir / "audit_log.jsonl").read_text(encoding="utf-8").splitlines()
    commands = [json.loads(line)["command"] for line in lines]
    assert commands == ["labs", "progress", "status"]
