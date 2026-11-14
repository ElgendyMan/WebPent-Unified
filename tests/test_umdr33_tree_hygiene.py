"""UM-DR-33 — working-tree hygiene regressions.

Release-grade measurement gates refuse a dirty tree (§3.2). Two defects
found during the UM-DR-33 Phase 0/1 suite runs could silently dirty the
repository from inside tests/CLI:

1. ``webpent econ portfolio transition`` (CLI) wrote its transition journal
   to the TRACKED default ``download/econ/portfolio_transitions.jsonl``
   instead of the operator-configured state dir — fixed in
   ``src/webpent/cli/econ.py`` (log_path = ``_state_dir()``/…).

These tests pin the fix: invoking the CLI with ``WEBPENT_ECON_DIR`` set
must never touch the tracked repository default.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from webpent.cli.econ import econ_app

RUNNER = CliRunner()

PORTFOLIO_YAML = """targets:
- target_id: t-1
  program_id: example-corp
  state: WATCHING
  ev_per_hour: 10.0
  total_findings: 0
  total_payout_usd: 0
"""


def _repo_tracked_default() -> Path:
    # resolved against the process CWD (the repository root under pytest)
    return Path("download/econ/portfolio_transitions.jsonl")


def test_cli_transition_writes_state_dir_not_tracked_default(
    tmp_path, monkeypatch
) -> None:
    """The regression: transition journal must land in WEBPENT_ECON_DIR."""
    state = tmp_path / "state"
    state.mkdir()
    monkeypatch.setenv("WEBPENT_ECON_DIR", str(state))
    portfolio = tmp_path / "portfolio.yaml"
    portfolio.write_text(PORTFOLIO_YAML, encoding="utf-8")

    tracked = _repo_tracked_default()
    snapshot = tracked.read_bytes() if tracked.exists() else None

    result = RUNNER.invoke(
        econ_app,
        ["portfolio", "transition", "t-1", "ACTIVE", "--portfolio",
         str(portfolio), "--reason", "hygiene regression"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["moved"] is True

    # the journal went to the state dir…
    journal = state / "portfolio_transitions.jsonl"
    assert journal.exists(), "transition journal missing from state dir"
    assert "t-1" in journal.read_text(encoding="utf-8")

    # …and the tracked repository default is byte-identical (or absent)
    after = tracked.read_bytes() if tracked.exists() else None
    assert after == snapshot, (
        "tracked download/econ/portfolio_transitions.jsonl was modified — "
        "the working tree would be dirtied by a suite run"
    )


def test_cli_plan_uses_state_dir_journal(tmp_path, monkeypatch) -> None:
    """The plan command shares the same isolation (defense in depth)."""
    state = tmp_path / "state"
    state.mkdir()
    monkeypatch.setenv("WEBPENT_ECON_DIR", str(state))
    portfolio = tmp_path / "portfolio.yaml"
    portfolio.write_text(PORTFOLIO_YAML, encoding="utf-8")

    tracked = _repo_tracked_default()
    snapshot = tracked.read_bytes() if tracked.exists() else None

    result = RUNNER.invoke(
        econ_app,
        ["portfolio", "plan", "--portfolio", str(portfolio)],
    )
    assert result.exit_code == 0, result.output

    after = tracked.read_bytes() if tracked.exists() else None
    assert after == snapshot
