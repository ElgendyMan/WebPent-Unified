"""U-JC-12: the Council Dashboard + the ``webpent jc`` operator console."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from typer.testing import CliRunner

from webpent.jc.contracts import CouncilSession, Verdict
from webpent.jc.dashboard import CouncilDashboard, load_jsonl
from webpent.jc.memory import CouncilMemory

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
TS = 1_800_000_000.0
RUNNER = CliRunner()


def make_verdict(action="attack", confidence=0.7):
    return Verdict(action=action, reasoning="r", confidence=confidence,
                   confidence_tier="medium", dissent=[], escalate=False,
                   escalation_reason=None, advocates_summary={},
                   session_id="s1", timestamp=NOW)


def make_session(session_id="s1", context=None):
    return CouncilSession(session_id=session_id, question="q",
                          context=context or {"target_id": "lab-01"},
                          started_at=NOW)


def board(tmp_path, **kwargs):
    return CouncilDashboard(
        memory_path=tmp_path / "memory.jsonl",
        dissent_path=tmp_path / "dissent.jsonl",
        calibration_path=tmp_path / "calibration.jsonl",
        sessions_path=tmp_path / "sessions.jsonl",
        override_path=tmp_path / "overrides.jsonl",
        **kwargs,
    )


def run_cli(tmp_path, *args):
    return RUNNER.invoke(__import__(
        "webpent.cli.jc", fromlist=["jc_app"]).jc_app, list(args),
        env={"WEBPENT_JC_DIR": str(tmp_path)})


def test_empty_dashboard_is_clean(tmp_path):
    snap = board(tmp_path).build(now_ts=TS)
    assert snap["advisory"] is True
    assert snap["n_sessions"] == 0
    assert snap["alerts"] == []
    assert snap["bias_findings"] == []
    assert snap["overrides"]["n_overrides"] == 0


def test_recent_sessions_listed_newest_first(tmp_path):
    memory = CouncilMemory(tmp_path / "memory.jsonl", now_ts=TS)
    for i in range(3):
        memory.record(make_session(session_id=f"s{i}"), make_verdict(),
                      ts=TS + i)
    snap = board(tmp_path).build(now_ts=TS + 100)
    assert snap["n_sessions"] == 3
    assert [s["session_id"] for s in snap["recent_sessions"]] == \
        ["s2", "s1", "s0"]
    assert snap["recent_sessions"][0]["action"] == "attack"


def test_recent_sessions_capped_at_ten(tmp_path):
    memory = CouncilMemory(tmp_path / "memory.jsonl", now_ts=TS)
    for i in range(14):
        memory.record(make_session(session_id=f"s{i:02d}"), make_verdict(),
                      ts=TS + i)
    snap = board(tmp_path).build(now_ts=TS + 100)
    assert len(snap["recent_sessions"]) == 10
    assert snap["n_sessions"] == 14


def test_dissent_section_counts(tmp_path):
    from webpent.jc.contracts import DissentingView
    from webpent.jc.dissent import DissentRegister

    register = DissentRegister(tmp_path / "dissent.jsonl")
    verdict = make_verdict()
    verdict.dissent = [DissentingView(advocate_id="a2", claim="park",
                                      reasoning="kept", confidence=0.6)]
    register.record(verdict, now=TS)
    snap = board(tmp_path).build(now_ts=TS + 100)
    assert snap["dissent"]["n_dissent_records"] == 1
    assert snap["dissent"]["persistent_minority"] == []


def test_drift_raises_alert(tmp_path):
    calibrator_path = tmp_path / "calibration.jsonl"
    from webpent.jc.calibration import MIN_SAMPLES, ConfidenceCalibrator

    calibrator = ConfidenceCalibrator(calibrator_path)
    for i in range(MIN_SAMPLES):
        calibrator.record(0.9, False, ts=TS + i)
    snap = board(tmp_path).build(now_ts=TS + 100)
    assert snap["calibration"]["drift_detected"] is True
    assert any("drift" in a for a in snap["alerts"])


def test_bias_finding_raises_alert(tmp_path):
    sessions = tmp_path / "sessions.jsonl"
    rows = [json.dumps({"session_id": f"s{i}", "ts": TS,
                        "verdict": {"advocates_summary": {
                            "loser": {"score": 1.0, "claim": "x",
                                      "argue_order": 1},
                            "winner": {"score": 2.0, "claim": "y",
                                       "argue_order": 0}}}})
            for i in range(5)]
    sessions.write_text("\n".join(rows) + "\n")
    snap = board(tmp_path).build(now_ts=TS + 100)
    types = {f["bias_type"] for f in snap["bias_findings"]}
    assert "silent_veto" in types
    assert any("bias pattern silent_veto" in a for a in snap["alerts"])


def test_override_stats_and_low_accuracy_alert(tmp_path):
    from webpent.jc.override import OverrideProtocol

    protocol = OverrideProtocol(tmp_path / "overrides.jsonl", now_ts=TS)
    protocol.apply(make_verdict(), "advisory", "first wrong manual call",
                   ts=TS)
    protocol.apply(make_verdict(), "partial", "second wrong manual call",
                   ts=TS)
    protocol.link_outcome("s1", "incorrect", ts=TS + 1)
    snap = board(tmp_path).build(now_ts=TS + 100)
    assert snap["overrides"]["n_overrides"] == 2
    assert snap["overrides"]["modes"] == {"advisory": 1, "partial": 1}
    assert snap["overrides"]["operator_accuracy"] == 0.0
    assert any("override accuracy" in a for a in snap["alerts"])


def test_markdown_sections(tmp_path):
    snap = board(tmp_path).build(now_ts=TS)
    text = board(tmp_path).to_markdown(snap)
    assert "# Judgment Council dashboard" in text
    assert "## Recent sessions" in text
    assert "## Calibration" in text
    assert "## Dissent" in text
    assert "## Bias findings" in text
    assert "## Overrides" in text
    assert "Advisory only (JC-L-1)" in text


def test_markdown_escapes_pipes(tmp_path):
    memory = CouncilMemory(tmp_path / "memory.jsonl", now_ts=TS)
    memory.record(make_session(session_id="s|1"), make_verdict(), ts=TS)
    snap = board(tmp_path).build(now_ts=TS + 100)
    text = board(tmp_path).to_markdown(snap)
    data_rows = [line for line in text.splitlines()
                 if line.startswith("|") and "session |" not in line
                 and "---" not in line]
    assert data_rows and "¦" in data_rows[0]  # raw | never breaks the table


def test_dashboard_deterministic(tmp_path):
    a = board(tmp_path).build(now_ts=TS)
    b = board(tmp_path).build(now_ts=TS)
    assert a == b


def test_load_jsonl_corrupt_lines_ignored(tmp_path):
    path = tmp_path / "x.jsonl"
    path.write_text('{"a": 1}\ngarbage\n{"b": 2}\n')
    rows = load_jsonl(path)
    assert rows == [{"a": 1}, {"b": 2}]
    assert load_jsonl(tmp_path / "missing.jsonl") == []


# ------------------------------------------------------------------- CLI
def test_cli_sessions(tmp_path):
    (tmp_path / "sessions.jsonl").write_text(
        json.dumps({"session_id": "s1", "ts": TS}) + "\n")
    result = run_cli(tmp_path, "sessions")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["count"] == 1 and payload["advisory"] is True


def test_cli_verdicts(tmp_path):
    memory = CouncilMemory(tmp_path / "memory.jsonl", now_ts=TS)
    memory.record(make_session(), make_verdict(), ts=TS)
    result = run_cli(tmp_path, "verdicts")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["count"] == 1
    assert payload["verdicts"][0]["action"] == "attack"


def test_cli_calibration(tmp_path):
    result = run_cli(tmp_path, "calibration")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["n_samples"] == 0
    assert payload["advisory"] is True


def test_cli_dashboard_markdown(tmp_path):
    result = run_cli(tmp_path, "dashboard", "--markdown")
    assert result.exit_code == 0, result.output
    assert "Judgment Council dashboard" in result.output


def test_cli_digest(tmp_path):
    result = run_cli(tmp_path, "digest")
    assert result.exit_code == 0, result.output
    assert "Judgment Council digest" in result.output
    assert "Advisory only (JC-L-1)" in result.output


def test_cli_override_records(tmp_path):
    memory = CouncilMemory(tmp_path / "memory.jsonl", now_ts=TS)
    memory.record(make_session(), make_verdict(), ts=TS)
    result = run_cli(tmp_path, "override", "s1", "--mode", "advisory",
                     "--reason", "noted, no action taken")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["recorded"] is True
    assert (tmp_path / "overrides.jsonl").exists()


def test_cli_override_rejects_short_reason(tmp_path):
    memory = CouncilMemory(tmp_path / "memory.jsonl", now_ts=TS)
    memory.record(make_session(), make_verdict(), ts=TS)
    result = run_cli(tmp_path, "override", "s1", "--mode", "advisory",
                     "--reason", "nope")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["recorded"] is False
    assert "reason" in payload["error"]


def test_cli_override_unknown_session(tmp_path):
    result = run_cli(tmp_path, "override", "missing", "--mode", "advisory",
                     "--reason", "noted, no action taken")
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["recorded"] is False


def test_cli_audit_log_written_and_capped(tmp_path):
    from webpent.cli.jc import AUDIT_LIMIT

    for i in range(AUDIT_LIMIT + 5):
        (tmp_path / "audit.jsonl").open("a").write(
            json.dumps({"ts": TS + i, "command": "jc old"}) + "\n")
    result = run_cli(tmp_path, "sessions")
    assert result.exit_code == 0, result.output
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert len(lines) == AUDIT_LIMIT
    assert json.loads(lines[-1])["command"] == "jc sessions"
