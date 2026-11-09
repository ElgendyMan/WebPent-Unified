"""U-APEX-11 — The Operator Dashboard + CLI (v87).

Every apex CLI command prints the preamble first and appends a capped
audit line (max 1000). The dashboard renders all five sections from a
snapshot. `tools install` is advisory: it prints the vetted install
command and executes nothing (APEX-L-9). Mirrors cli/dojo.py house style.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from webpent.cli.apex import apex_app

WORK = Path(__file__).resolve().parents[2]
PREAMBLE_PREFIX = "advisory:"

runner = CliRunner()


@pytest.fixture()
def apex_dir(tmp_path: Path) -> Path:
    return tmp_path / "apex-state"


def _invoke(args: list[str], apex_dir: Path):
    return runner.invoke(
        apex_app, args + ["--apex-dir", str(apex_dir)],
        env={"WEBPENT_APEX_WORKDIR": str(WORK)},
    )


def test_all_cli_commands_emit_preamble_and_audit(apex_dir: Path) -> None:
    build = _invoke(
        ["chain", "build", "--hypothesis", "xss", "--target", "t.test"],
        apex_dir,
    )
    assert build.exit_code == 0, build.output
    chain_id = json.loads(build.output.splitlines()[-1])["chain_id"]

    commands = [
        ["status"],
        ["tools", "list"],
        ["tools", "list", "--category", "recon"],
        ["tools", "install", "httpx"],
        ["chain", "run", chain_id],
        ["findings", "fused"],
        ["dashboard"],
        ["mcp", "serve"],
        ["learn"],
    ]
    for argv in commands:
        result = _invoke(argv, apex_dir)
        assert result.exit_code == 0, f"{argv}: {result.output}"
        lines = result.output.splitlines()
        assert lines[0].startswith(PREAMBLE_PREFIX), (
            f"{argv} must print the preamble first: {lines[:2]}"
        )
    # every command appended its audit line to the same capped file
    audit = json.loads(
        (apex_dir / "audit.jsonl").read_text().splitlines()[-1]
    )
    assert "command" in audit


def test_chain_run_dry_run_reports_plan_not_execution(apex_dir: Path) -> None:
    build = _invoke(
        ["chain", "build", "--hypothesis", "xss", "--target", "t.test"],
        apex_dir,
    )
    chain_id = json.loads(build.output.splitlines()[-1])["chain_id"]
    result = _invoke(["chain", "run", chain_id], apex_dir)
    payload = json.loads(result.output.splitlines()[-1])
    assert payload["mode"] == "dry-run"
    assert [s["tool_id"] for s in payload["steps"]] == ["gau", "dalfox"]
    assert all(s["executed"] is False for s in payload["steps"])


def test_dashboard_renders_all_sections(apex_dir: Path) -> None:
    result = _invoke(["dashboard"], apex_dir)
    for section in ("Chains", "Tool usage", "Speed", "Findings", "Resources"):
        assert section in result.output, f"dashboard missing section {section}"
    # with a recorded run the dashboard reflects it
    _invoke(["chain", "build", "--hypothesis", "xss", "--target", "t.test"], apex_dir)
    build = _invoke(
        ["chain", "build", "--hypothesis", "xss", "--target", "t.test"],
        apex_dir,
    )
    chain_id = json.loads(build.output.splitlines()[-1])["chain_id"]
    # RT-03: dry-run fabricates nothing, so tool usage only fills after a
    # real --execute run (exit codes may be non-zero; binaries absent here).
    _invoke(["chain", "run", chain_id, "--execute"], apex_dir)
    again = _invoke(["dashboard"], apex_dir)
    assert "gau" in again.output, "tool usage section must list run tools"


def test_findings_fused_lists_consensus(apex_dir: Path) -> None:
    findings = [
        {
            "tool_id": "nuclei",
            "findings": [
                {
                    "vuln_class": "sqli", "endpoint": "/api/x",
                    "severity": "high", "confidence": 0.8, "detail": "d1",
                }
            ],
        },
        {
            "tool_id": "sqlmap",
            "findings": [
                {
                    "vuln_class": "sqli", "endpoint": "/api/x",
                    "severity": "high", "confidence": 0.7, "detail": "d2",
                }
            ],
        },
    ]
    (apex_dir / "findings.jsonl").parent.mkdir(parents=True, exist_ok=True)
    for row in findings:
        with (apex_dir / "findings.jsonl").open("a") as fh:
            fh.write(json.dumps(row) + "\n")
    result = _invoke(["findings", "fused"], apex_dir)
    payload = json.loads(result.output.splitlines()[-1])
    assert payload["count"] == 1
    finding = payload["findings"][0]
    assert finding["consensus"] == pytest.approx(1.0)  # both tools agree
    assert sorted(finding["sources"]) == ["nuclei", "sqlmap"]


def test_audit_log_capped_at_1000(apex_dir: Path) -> None:
    audit = apex_dir / "audit.jsonl"
    audit.parent.mkdir(parents=True, exist_ok=True)
    for i in range(1000):
        with audit.open("a") as fh:
            fh.write(json.dumps({"command": f"old-{i}"}) + "\n")
    result = _invoke(["status"], apex_dir)
    assert result.exit_code == 0
    lines = audit.read_text().splitlines()
    assert len(lines) == 1000, "audit must stay capped at 1000 lines"
    assert json.loads(lines[-1])["command"] == "status"
    assert json.loads(lines[0])["command"] == "old-1", "oldest line evicted"


def test_tools_install_is_advisory(apex_dir: Path) -> None:
    result = _invoke(["tools", "install", "httpx"], apex_dir)
    assert "install_command" in result.output or "go install" in result.output
    payload = json.loads(result.output.splitlines()[-1])
    assert payload["executed"] is False, "install must never execute here"
    assert payload["advisory"] is True
