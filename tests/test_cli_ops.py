# tests/test_cli_ops.py
"""CLI tests for the Track 12 read-only ops surface (``webpent ops``).

All commands are status/inspection/export only: no requests sent, no
campaign behavior changed. The tests use temp stores and a seeded local
DB surface only where the command reads it.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from webpent.cli import app

runner = CliRunner()


class TestGovernorCommand:
    def test_table_rendering_exit_zero(self):
        result = runner.invoke(app, ["ops", "governor"])
        assert result.exit_code == 0, result.output
        assert "Concurrency governor" in result.output
        assert "cross-process leases" in result.output

    def test_json_rendering_includes_caps(self):
        result = runner.invoke(app, ["ops", "governor", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output[result.output.index("{") :])
        assert payload["max_global"] >= 0
        assert "active_total" in payload
        assert payload["cross_process_enabled"] in (True, False)


class TestWorkersCommand:
    def test_missing_coord_dir_is_typed_error(self, tmp_path):
        result = runner.invoke(app, ["ops", "workers", "--coord-dir", str(tmp_path / "ghost")])
        assert result.exit_code == 2
        assert "not found" in result.output

    def test_snapshot_and_change_log_tail(self, tmp_path):
        from webpent.production.worker_coordination import WorkerCoordinator

        coord = WorkerCoordinator(tmp_path / "coord", worker_id="cli-test")
        coord.claim_work("client-1", "scope-1", "unit-1")
        coord.release_claim("client-1", "unit-1")
        result = runner.invoke(app, ["ops", "workers", "--coord-dir", str(tmp_path / "coord")])
        assert result.exit_code == 0, result.output
        assert "Worker coordination" in result.output
        assert "claim_acquired" in result.output  # change-log tail rendered

    def test_json_mode(self, tmp_path):
        from webpent.production.worker_coordination import WorkerCoordinator

        WorkerCoordinator(tmp_path / "coord", worker_id="cli-test")
        result = runner.invoke(
            app, ["ops", "workers", "--coord-dir", str(tmp_path / "coord"), "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output[result.output.index("{") :])
        # The reader's own coordinator identity (store-creating workers
        # appear in claims/change log, not as the snapshot reader).
        assert payload["snapshot"]["worker_id"].startswith("worker-")
        assert payload["snapshot"]["active_claims"] == 0


class TestGraphCommand:
    def _seed_findings(self, monkeypatch):
        import uuid as uuid_mod

        from webpent.models.findings import Finding

        findings = [
            Finding(
                id=str(uuid_mod.uuid5(uuid_mod.NAMESPACE_URL, f"f-{i}")),
                title=f"Finding {i}",
                severity="medium",
                description="lab seed",
                tool_name="validator",
                url=f"https://app.example.com/p/{i}",
                vuln_class="xss",
            )
            for i in range(3)
        ]

        class FakeManager:
            def get_all_findings(self):
                return list(findings)

        from webpent.memory import db as db_mod

        monkeypatch.setattr(db_mod, "get_db_manager", lambda: FakeManager())

    def test_empty_db_typed_exit(self, monkeypatch):
        from webpent.memory import db as db_mod

        class Empty:
            def get_all_findings(self):
                return []

        monkeypatch.setattr(db_mod, "get_db_manager", lambda: Empty())
        result = runner.invoke(
            app, ["ops", "graph", "--out", "/tmp/never-written.html"]
        )
        assert result.exit_code == 2
        assert "no findings" in result.output

    def test_html_export_written(self, tmp_path, monkeypatch):
        self._seed_findings(monkeypatch)
        out = tmp_path / "graph.html"
        result = runner.invoke(app, ["ops", "graph", "--out", str(out), "--format", "html"])
        assert result.exit_code == 0, result.output
        assert out.exists()
        content = out.read_text()
        assert content.startswith("<!doctype html>")
        assert "app.example.com" in content

    def test_json_and_dot_exports(self, tmp_path, monkeypatch):
        self._seed_findings(monkeypatch)
        out_json = tmp_path / "g.json"
        result = runner.invoke(app, ["ops", "graph", "--out", str(out_json), "--format", "json"])
        assert result.exit_code == 0, result.output
        data = json.loads(out_json.read_text())
        assert set(data) == {"engagement_id", "nodes", "edges"}
        out_dot = tmp_path / "g.dot"
        result = runner.invoke(app, ["ops", "graph", "--out", str(out_dot), "--format", "dot"])
        assert result.exit_code == 0, result.output
        assert out_dot.read_text().startswith("digraph webpent_findings {")

    def test_invalid_format_refused(self, tmp_path, monkeypatch):
        self._seed_findings(monkeypatch)
        result = runner.invoke(
            app, ["ops", "graph", "--out", str(tmp_path / "x.png"), "--format", "png"]
        )
        assert result.exit_code == 2
        assert "unsupported format" in result.output


class TestCalibrationCommand:
    def test_missing_store_typed_error(self, tmp_path):
        result = runner.invoke(
            app,
            ["ops", "calibration", "--client", "c1", "--store-dir", str(tmp_path / "ghost")],
        )
        assert result.exit_code == 2

    def test_cold_store_renders_neutral_note(self, tmp_path):
        from webpent.production.confidence_calibration import ConfidenceCalibrator

        ConfidenceCalibrator(tmp_path / "cal")
        result = runner.invoke(
            app,
            ["ops", "calibration", "--client", "c1", "--store-dir", str(tmp_path / "cal")],
        )
        assert result.exit_code == 0, result.output
        assert "cold" in result.output or "0" in result.output

    def test_feedback_counts_rendered(self, tmp_path):
        from webpent.production.confidence_calibration import (
            CalibrationRecord,
            ConfidenceCalibrator,
            HumanDecision,
        )

        cal = ConfidenceCalibrator(tmp_path / "cal")
        for _ in range(4):
            cal.record_decision(
                CalibrationRecord(client_id="c1", vuln_class="xss", decision=HumanDecision.ACCEPTED)
            )
        result = runner.invoke(
            app,
            ["ops", "calibration", "--client", "c1", "--store-dir", str(tmp_path / "cal")],
        )
        assert result.exit_code == 0, result.output
        assert "4" in result.output  # accepted count rendered


class TestProtectionCommand:
    def test_posture_lists_refusals(self):
        result = runner.invoke(app, ["ops", "protection"])
        assert result.exit_code == 0, result.output
        assert "Protection controls" in result.output
        assert "ip_rotation" in result.output
        assert "captcha_solving" in result.output
        assert "Never implemented" in result.output

    def test_json_posture(self):
        result = runner.invoke(app, ["ops", "protection", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output[result.output.index("{") :])
        assert "forbidden_evasions" in payload
        assert payload["policy"]["block_or_challenge"].startswith("halt")


class TestFrozenWindowProtocol:
    def test_ops_app_registered_exactly_once(self):
        """The commands.py delta is the documented two-line pattern."""
        from webpent.cli import commands

        count = sum(
            1 for name in commands.app.registered_commands + commands.app.registered_groups
            if getattr(name, "name", "") == "ops"
        )
        assert count == 1
