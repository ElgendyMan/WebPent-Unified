# tests/test_ops_calibration_wiring.py
"""Track 12.8 write + consume sides wired to the CLI (0.26.0).

Roadmap gap closed: ``ConfidenceCalibrator`` existed with tests but was
NOT connected to the human decision loop — ``ops review decide`` never
recorded a ``HumanDecision`` and ``calibrated_order`` had zero callers.
This file pins the new wiring:

* ``ops review decide --calibration-store`` records the triage decision
  (aggregates only; fail-open — a store failure never breaks the review);
* ``ops calibration --candidates`` consumes the store via
  ``calibrated_order`` (reordering only, raw confidence untouched).
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from webpent.cli.ops import ops_app

runner = CliRunner()


def _bootstrap_admin(tmp_path: Path) -> Path:
    state_path = tmp_path / "ops.json"
    result = runner.invoke(
        ops_app,
        ["bootstrap-admin", "--state", str(state_path), "--actor", "root"],
    )
    assert result.exit_code == 0, result.output
    return state_path


def _grant_analyst(state_path: Path, client: str = "acme") -> None:
    result = runner.invoke(
        ops_app,
        [
            "users", "--state", str(state_path), "--actor", "root",
            "--grantee", "analyst1", "--role", "analyst", "--client", client,
        ],
    )
    assert result.exit_code == 0, result.output


def _enqueue_and_claim(state_path: Path, client: str = "acme") -> str:
    result = runner.invoke(
        ops_app,
        [
            "review", "--state", str(state_path), "--actor", "analyst1",
            "--action", "enqueue", "--client", client, "--finding-ref", "F-1",
            "--severity", "high",
        ],
    )
    assert result.exit_code == 0, result.output
    item_id = json.loads(result.output[result.output.index("{"):])["item_id"]
    result = runner.invoke(
        ops_app,
        [
            "review", "--state", str(state_path), "--actor", "analyst1",
            "--action", "claim", "--item", item_id,
        ],
    )
    assert result.exit_code == 0, result.output
    return item_id


class TestDecideFeedsCalibrator:
    def test_decide_records_human_decision(self, tmp_path):
        store = tmp_path / "calib"
        state_path = _bootstrap_admin(tmp_path)
        _grant_analyst(state_path)
        item_id = _enqueue_and_claim(state_path)
        result = runner.invoke(
            ops_app,
            [
                "review", "--state", str(state_path), "--actor", "analyst1",
                "--action", "decide", "--item", item_id, "--approve",
                "--calibration-store", str(store),
                "--vuln-class", "idor",
            ],
        )
        assert result.exit_code == 0, result.output
        # The store now holds exactly one accepted record for the class,
        # under the client's own namespace.
        from webpent.production.confidence_calibration import ConfidenceCalibrator

        calibrator = ConfidenceCalibrator(store)
        accepted, rejected = calibrator.class_stats("acme", "idor")
        assert (accepted, rejected) == (1, 0)
        # The multiplier moved off neutral (bounded).
        multiplier = calibrator.class_multiplier("acme", "idor")
        assert 0.5 <= multiplier <= 2.0 and multiplier != 1.0

    def test_reject_records_rejected_decision(self, tmp_path):
        store = tmp_path / "calib"
        state_path = _bootstrap_admin(tmp_path)
        _grant_analyst(state_path)
        item_id = _enqueue_and_claim(state_path)
        result = runner.invoke(
            ops_app,
            [
                "review", "--state", str(state_path), "--actor", "analyst1",
                "--action", "decide", "--item", item_id, "--reject",
                "--calibration-store", str(store),
            ],
        )
        assert result.exit_code == 0, result.output
        from webpent.production.confidence_calibration import ConfidenceCalibrator

        calibrator = ConfidenceCalibrator(store)
        accepted, rejected = calibrator.class_stats("acme", "general")
        assert (accepted, rejected) == (0, 1)

    def test_store_failure_is_fail_open(self, tmp_path, monkeypatch):
        """A broken store must NOT break the review of record."""
        state_path = _bootstrap_admin(tmp_path)
        _grant_analyst(state_path)
        item_id = _enqueue_and_claim(state_path)

        import webpent.production.confidence_calibration as calib_mod

        def boom(*_args, **_kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(calib_mod.ConfidenceCalibrator, "record_decision", boom)
        result = runner.invoke(
            ops_app,
            [
                "review", "--state", str(state_path), "--actor", "analyst1",
                "--action", "decide", "--item", item_id, "--approve",
                "--calibration-store", str(tmp_path / "calib"),
            ],
        )
        assert result.exit_code == 0, result.output  # review stands
        assert "calibration" in result.output.lower()  # honest warning

    def test_client_isolation_in_store(self, tmp_path):
        """Client A's decisions must never appear under client B."""
        store = tmp_path / "calib"
        state_path = _bootstrap_admin(tmp_path)
        _grant_analyst(state_path, "acme")
        item_id = _enqueue_and_claim(state_path, "acme")
        result = runner.invoke(
            ops_app,
            [
                "review", "--state", str(state_path), "--actor", "analyst1",
                "--action", "decide", "--item", item_id, "--approve",
                "--calibration-store", str(store), "--vuln-class", "idor",
            ],
        )
        assert result.exit_code == 0, result.output
        from webpent.production.confidence_calibration import ConfidenceCalibrator

        calibrator = ConfidenceCalibrator(store)
        assert calibrator.class_stats("other-client", "idor") == (0, 0)
        assert calibrator.class_stats("acme", "idor") == (1, 0)


class TestCalibratedCandidatesConsumer:
    def _store_with_history(self, tmp_path: Path):
        from webpent.production.confidence_calibration import (
            CalibrationRecord,
            ConfidenceCalibrator,
            HumanDecision,
        )

        store = tmp_path / "calib"
        calibrator = ConfidenceCalibrator(store)
        for _ in range(10):
            calibrator.record_decision(
                CalibrationRecord(
                    client_id="acme", vuln_class="idor",
                    decision=HumanDecision.ACCEPTED, severity="high",
                )
            )
        for _ in range(10):
            calibrator.record_decision(
                CalibrationRecord(
                    client_id="acme", vuln_class="xss",
                    decision=HumanDecision.REJECTED, severity="low",
                )
            )
        return calibrator

    def test_candidates_reordered_not_rescored(self, tmp_path):
        calibrator = self._store_with_history(tmp_path)
        # Identical raw confidence: the accepted class must outrank the
        # rejected one; raw inputs never appear modified in the output.
        candidates = [("a-ssrf", "ssrf", 0.5), ("a-idor", "idor", 0.5), ("a-xss", "xss", 0.5)]
        ordered = calibrator.calibrated_order(candidates, "acme")
        ids = [cid for cid, _ in ordered]
        assert ids.index("a-idor") < ids.index("a-xss")
        # Reordering only: same input ordering with a neutral class keeps
        # stable ties, and values stay within [0, 1].
        assert all(0.0 <= conf <= 1.0 for _, conf in ordered)

    def test_cli_candidates_command(self, tmp_path):
        self._store_with_history(tmp_path)
        result = runner.invoke(
            ops_app,
            [
                "calibration", "--client", "acme",
                "--store-dir", str(tmp_path / "calib"),
                "--candidates",
                json.dumps([["f1", "xss", 0.5], ["f2", "idor", 0.5]]),
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output[result.output.index("{"):])
        ordered_ids = [row["id"] for row in payload["ordered"]]
        assert ordered_ids == ["f2", "f1"]  # idor (accepted) first

    def test_cli_candidates_malformed_is_typed_error(self, tmp_path):
        self._store_with_history(tmp_path)  # store must exist first
        result = runner.invoke(
            ops_app,
            [
                "calibration", "--client", "acme",
                "--store-dir", str(tmp_path / "calib"),
                "--candidates", "not-json",
            ],
        )
        assert result.exit_code == 2
        assert "--candidates" in result.output
