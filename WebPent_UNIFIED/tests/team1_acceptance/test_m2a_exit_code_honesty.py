"""WP-I (Dispatch #009-A) — exit-code honesty contract tests (A11/A12).

NF-L0-01 (D-J): the operator surface could exit 0 with an incomplete
production trace — a dead or short-circuited chain was indistinguishable
from a clean no-findings scan. These tests pin the honesty contract:

  * direct-spine surfaces (agent-hunt — the scan/hunt-plan surfaces were
    removed by the v0.32.0 retired-alias window): incomplete or absent
    trace → non-zero exit + loud operator-visible error naming the
    missing stages and pointing at the trace;
  * worker: the research-campaign lane's markers are the completeness
    authority — skip marker or a missing executed-marker → loud
    non-success status;
  * the sweep: every chain-bearing operator path carries the gate
    (source-level pins, R8-style).
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import click
import pytest
from typer.testing import CliRunner

from webpent.cli.commands import (
    _chain_honesty_verdict,
    _enforce_chain_honesty,
    app,
)

TREE_ROOT = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------------------
# Helpers under contract
# ---------------------------------------------------------------------------
def _complete_trace() -> dict:
    return {
        "complete": True,
        "missing_required_stages": [],
        "stages_seen": ["entrypoint_resolve", "promotion_decision"],
    }


def _incomplete_trace() -> dict:
    return {
        "complete": False,
        "missing_required_stages": [
            "bounded_tool_execution",
            "promotion_decision",
        ],
    }


class TestDirectSpineHonestyGate:
    def test_complete_trace_passes(self):
        assert (
            _enforce_chain_honesty(_complete_trace(), surface="X", pointer="p")
            is None
        )

    def test_incomplete_trace_raises_exit_1_with_missing_stages(self):
        with pytest.raises(click.exceptions.Exit) as excinfo:
            _enforce_chain_honesty(
                _incomplete_trace(), surface="HUNT", pointer="the-trace.json"
            )
        assert excinfo.value.exit_code == 1

    def test_absent_trace_fails_closed(self):
        with pytest.raises(click.exceptions.Exit):
            _enforce_chain_honesty(None, surface="HUNT", pointer="p")
        with pytest.raises(click.exceptions.Exit):
            _enforce_chain_honesty({}, surface="HUNT", pointer="p")

    def test_error_message_names_missing_stages_and_pointer(self, capsys):
        with pytest.raises(click.exceptions.Exit):
            _enforce_chain_honesty(
                _incomplete_trace(), surface="HUNT", pointer="the-trace.json"
            )
        # rich console writes to stderr; capture both streams, normalize wrap
        captured = capsys.readouterr()
        output = " ".join((captured.out + captured.err).split())
        assert "bounded_tool_execution" in output
        assert "the-trace.json" in output
        assert "NOT a clean no-findings scan" in output


class TestGraphPathVerdict:
    def test_executed_lane_passes(self):
        assert (
            _chain_honesty_verdict(
                {"research_campaign_executed": True, "research_campaign_result": {}}
            )
            is None
        )

    def test_skip_marker_short_circuits(self):
        verdict = _chain_honesty_verdict(
            {"research_campaign_skipped": "no_hypotheses"}
        )
        assert verdict is not None and "no_hypotheses" in verdict

    def test_missing_markers_fail_closed(self):
        assert _chain_honesty_verdict({}) is not None
        assert _chain_honesty_verdict(None) is not None

    def test_flag_gated_skip_is_named(self):
        verdict = _chain_honesty_verdict(
            {
                "research_campaign_skipped": "multi_principal_execution_flag_gated",
                "research_campaign_executed": False,
            }
        )
        assert verdict is not None and "multi_principal_execution_flag_gated" in verdict


# ---------------------------------------------------------------------------
# CLI end-to-end (hunt --target) through the real Typer app
# ---------------------------------------------------------------------------
_RUNNER = CliRunner()


def _hunt_result(summary: dict) -> dict:
    return {"summary": summary, "state": {}, "artifact_root": "artifacts/x"}


@pytest.fixture()
def scope_file(tmp_path: Path) -> Path:
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "in_scope:\n  - \"https://hunt-target.test\"\n",
        encoding="utf-8",
    )
    return scope


class TestAgentHuntCliExitCodeHonesty:
    def test_incomplete_trace_agent_hunt_exits_non_zero(self, scope_file, monkeypatch):
        import webpent.agents.hunter_runner as hr

        monkeypatch.setattr(
            hr,
            "run_hunter_campaign",
            lambda **kwargs: _hunt_result({"production_trace": _incomplete_trace()}),
        )
        result = _RUNNER.invoke(
            app,
            [
                "agent-hunt",
                "--target",
                "https://hunt-target.test",
                "--scope",
                str(scope_file),
                "--engagement-id",
                "wp-i-contract",
            ],
        )
        assert result.exit_code != 0, (
            "NF-L0-01 REGRESSION: agent-hunt exited 0 with an incomplete trace"
        )
        assert "production trace incomplete" in " ".join(result.output.split())


# Sweep pins (A12): every chain-bearing operator path carries its gate.
# Source-level pins, R8-style (mirrors tests/test_v59_p0_hardening.py).
# ---------------------------------------------------------------------------
class TestSilentZeroExitSweep:
    def _source(self, relpath: str) -> str:
        return (TREE_ROOT / relpath).read_text(encoding="utf-8")

    def test_agent_hunt_gate_present(self):
        src = self._source("src/webpent/cli/commands.py")
        # v0.32.0 retired-alias removal: the scan/hunt-plan surfaces are
        # gone; agent-hunt is the surviving direct-spine surface and must
        # still enforce chain honesty. The unified `hunt` summary path is
        # a declared future-window candidate for its own gate.
        assert src.count("_enforce_chain_honesty(") >= 1, (
            "agent-hunt must enforce chain honesty"
        )

    def test_worker_completed_path_honest(self):
        src = self._source("src/webpent/workers/pentest_worker.py")
        assert "completed_incomplete_chain" in src
        assert "CHAIN SHORT-CIRCUITED" in src
        # the check must live inside the completed branch, after persistence
        persist_at = src.find("Persisted %d finding(s) for thread %s")
        honesty_at = src.find("completed_incomplete_chain")
        assert persist_at != -1 and honesty_at != -1 and persist_at < honesty_at


# ---------------------------------------------------------------------------
# Worker status contract (direct helper-level drive)
# ---------------------------------------------------------------------------
class TestWorkerStatusHonesty:
    def test_worker_reports_incomplete_chain_status(self):
        """The completed-path honesty flip: skip marker → loud non-success."""
        from webpent.workers.pentest_worker import _chain_short_circuit_reason

        assert (
            _chain_short_circuit_reason(
                {"research_campaign_skipped": "no_hypotheses"}
            )
            is not None
        )
        assert _chain_short_circuit_reason({"research_campaign_executed": True}) is None
        assert _chain_short_circuit_reason({}) is not None  # fail-closed
        # and the status string the branch returns is the loud one
        src = (TREE_ROOT / "src/webpent/workers/pentest_worker.py").read_text()
        assert '"status": "completed_incomplete_chain"' in src
