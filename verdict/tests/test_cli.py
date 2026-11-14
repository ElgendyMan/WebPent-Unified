"""U-VERDICT-1 — CLI framework tests (10 tests)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from conftest import write_target_yaml
from verdict_tool.cli import cli
from verdict_tool.tracking import Workspace

runner = CliRunner()


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    """An uninitialized workspace: every CLI test here runs init itself."""
    workspace = Workspace(tmp_path / "verdict_ws")
    workspace.ensure_dirs()
    for rel in ("e.png", "shots/f.png", "shots/f1.png"):
        path = workspace.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"png")
    return workspace


def invoke(ws: Workspace, *args: str):
    return runner.invoke(cli, ["--path", str(ws.root), *args])


def make_target(ws: Workspace, name: str = "target_a",
                handle: str = "handle_a") -> Path:
    return write_target_yaml(ws.root.parent, name=name, handle=handle)


def register_five(ws: Workspace, prefix: str = "f") -> list[str]:
    from verdict_tool.classifier import FindingClassifier
    state = ws.load()
    classifier = FindingClassifier(state, ws)
    ids = []
    for i in range(5):
        fid = f"{prefix}-{i}"
        classifier.register(fid, "target_a", "sqli",
                            "high", 0.9)
        classifier.classify(fid, "confirmed",
                            re_test_evidence=["shots/f.png"],
                            impact_confirmed="data exposure")
        ids.append(fid)
    return ids


def test_init_creates_workspace(ws: Workspace) -> None:
    result = invoke(ws, "init")
    assert result.exit_code == 0, result.output
    assert (ws.root / ".verdict" / "state.json").is_file()
    assert (ws.root / "pre_registration.md").is_file()
    state = ws.load()
    assert state.day_status(0) == "open"


def test_init_twice_fails(ws: Workspace) -> None:
    invoke(ws, "init")
    result = invoke(ws, "init")
    assert result.exit_code != 0
    assert "already initialized" in result.output


def test_status_shows_summary(ws: Workspace) -> None:
    invoke(ws, "init")
    result = invoke(ws, "status")
    assert result.exit_code == 0
    assert "days complete: 0/47" in result.output
    assert "targets: 0" in result.output


def test_day_renders_checklist(ws: Workspace) -> None:
    invoke(ws, "init")
    result = invoke(ws, "day", "0")
    assert result.exit_code == 0
    assert "Day 0 — Setup" in result.output
    assert "[ ]" in result.output
    assert "Objectives:" in result.output
    assert "Required outputs:" in result.output


def test_day_completion_requires_checklist(ws: Workspace) -> None:
    invoke(ws, "init")
    # pre-registration file exists (copied at init) but is not marked done
    result = invoke(ws, "day", "0", "--complete")
    assert result.exit_code != 0
    assert "pre-registration marked done" in result.output
    result = invoke(ws, "pre-registration", "done")
    assert result.exit_code == 0
    result = invoke(ws, "day", "0", "--complete")
    assert result.exit_code == 0, result.output
    state = ws.load()
    assert state.day_status(0) == "complete"


def test_day_out_of_range(ws: Workspace) -> None:
    result = invoke(ws, "day", "47")
    assert result.exit_code != 0


def test_select_requires_five_confirmed(ws: Workspace) -> None:
    invoke(ws, "init")
    ids = register_five(ws)
    # too few arguments
    result = invoke(ws, "select", ids[0], ids[1])
    assert result.exit_code != 0
    # unknown id
    result = invoke(ws, "select", *ids[:4], "ghost-9")
    assert result.exit_code != 0
    result = invoke(ws, "select", *ids)
    assert result.exit_code == 0, result.output
    state = ws.load()
    assert state.selection == ids


def test_watch_requires_submissions(ws: Workspace) -> None:
    invoke(ws, "init")
    result = invoke(ws, "watch", "start")
    assert result.exit_code != 0
    assert "no submissions" in result.output


def test_run_lifecycle_records_files(ws: Workspace) -> None:
    invoke(ws, "init")
    yaml_path = make_target(ws)
    result = invoke(ws, "targets", "add", str(yaml_path))
    assert result.exit_code == 0, result.output
    result = invoke(ws, "run", "start", "target_a")
    assert result.exit_code == 0, result.output
    result = invoke(ws, "run", "stop", "target_a")
    assert result.exit_code == 0, result.output
    state = ws.load()
    assert state.runs[-1]["stopped_at"] is not None
    assert (ws.root / "runs" / "target_a" / "launch.txt").is_file()
    assert (ws.root / "runs" / "target_a" / "stop.txt").is_file()
    assert (ws.root / "runs" / "target_a" / "backup").is_dir()
    assert (ws.root / "runs" / "target_a" / "checkins.txt").is_file()


def test_export_writes_files(ws: Workspace) -> None:
    invoke(ws, "init")
    result = invoke(ws, "export")
    assert result.exit_code == 0, result.output
    data = json.loads(
        (ws.root / "export" / "verdict_export.json").read_text(
            encoding="utf-8")
    )
    assert "metrics" in data
    assert (ws.root / "export" / "verdict_report.md").is_file()


@pytest.mark.parametrize("keep", [True])  # keep the suite shape explicit
def test_register_then_classify_via_cli(ws: Workspace, keep: bool) -> None:
    invoke(ws, "init")
    result = invoke(ws, "findings", "register", "f-1", "target_a", "sqli",
                    "--severity", "high", "--score", "0.9")
    assert result.exit_code == 0, result.output
    result = invoke(ws, "findings", "classify", "f-1", "-c", "confirmed",
                    "-e", "shots/f1.png", "--impact", "data exposure",
                    "--severity", "high")
    assert result.exit_code == 0, result.output
    state = ws.load()
    assert state.findings[0]["classification"] == "confirmed"
