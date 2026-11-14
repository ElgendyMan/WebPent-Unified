"""Integration tests — promotion -> POC wiring (FINAL PREP SPRINT 2026-10-05).

Covers the sprint's core constraint end-to-end: a POC failure must NEVER
block or revert a promotion. Uses the real PersistentFindingLedger (tmp file)
and the real watcher/CLI code paths with the browser factory faked out.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from tests.test_poc_recorder import FakeContext, _factory
from webpent.models.findings import Finding
from webpent.reporter.poc_cli import app
from webpent.reporter.poc_recorder import maybe_record_poc
from webpent.shared.persistent_finding_ledger import PersistentFindingLedger

runner = CliRunner()
ENG = "eng_poc_integration_test"


def _promoted_finding() -> Finding:
    return Finding(
        title="BOLA on /api/v1/orders/7",
        severity="high",
        description="Foreign principal reads owner orders without authorization.",
        tool_name="hunter",
        url="https://lab.example/api/v1/orders/7",
        request_method="GET",
        evidence={"promotion": {"decision": "PROMOTED"}},
    )


@pytest.fixture()
def ledger(tmp_path: Path) -> PersistentFindingLedger:
    led = PersistentFindingLedger(tmp_path / "ledger.sqlite3")
    led.merge(ENG, [_promoted_finding()])
    return led


def _finding_dict(ledger: PersistentFindingLedger) -> dict:
    return dict(ledger.get(ENG)[0])


# ---------------------------------------------------------------------------
# constraint: POC failure -> finding still promoted
# ---------------------------------------------------------------------------
def test_poc_failure_leaves_promotion_untouched(ledger, tmp_path) -> None:
    finding = _finding_dict(ledger)
    assert maybe_record_poc.__doc__ is not None  # fail-soft contract documented

    def exploding_factory(record_dir: Path) -> FakeContext:
        raise OSError("no display server, no chromium")

    result = maybe_record_poc(
        finding,
        output_dir=tmp_path / "poc",
        owner_token="o",
        foreign_token="f",
        browser_factory=exploding_factory,
    )
    assert result["status"] == "failed"
    # the finding itself is unchanged in the ledger and still promoted
    after = _finding_dict(ledger)
    assert after["evidence"]["promotion"]["decision"] == "PROMOTED"
    assert after["id"] == finding["id"]


# ---------------------------------------------------------------------------
# watcher sweep (once mode) over the real ledger
# ---------------------------------------------------------------------------
def test_watcher_once_records_pending_promotion(ledger, tmp_path, monkeypatch) -> None:
    import scripts.poc_watcher as watcher_mod

    recorded: list[str] = []

    def fake_maybe(finding, **kwargs):
        recorded.append(str(finding.get("id")))
        return {"status": "recorded", "finding_id": str(finding.get("id"))}

    monkeypatch.setattr(watcher_mod, "maybe_record_poc", fake_maybe)
    poc_dir = tmp_path / "poc"
    rc = watcher_mod.watch(
        ENG, once=True, poc_dir=poc_dir,
        ledger=ledger,
    )
    assert rc == 0
    assert len(recorded) == 1
    assert recorded[0] == str(_finding_dict(ledger)["id"])


def test_watcher_once_skips_findings_with_existing_poc(ledger, tmp_path, monkeypatch) -> None:
    import scripts.poc_watcher as watcher_mod

    recorded: list[str] = []
    monkeypatch.setattr(
        watcher_mod, "maybe_record_poc",
        lambda finding, **kw: recorded.append(str(finding.get("id"))) or {"status": "recorded"},
    )
    fid = str(_finding_dict(ledger)["id"])
    poc_dir = tmp_path / "poc"
    poc_dir.mkdir()
    (poc_dir / f"poc_{fid}.webm").write_bytes(b"x")
    rc = watcher_mod.watch(ENG, once=True, poc_dir=poc_dir, ledger=ledger)
    assert rc == 0
    assert recorded == []


def test_watcher_survives_ledger_errors(monkeypatch, tmp_path) -> None:
    import scripts.poc_watcher as watcher_mod

    class BrokenLedger:
        def get(self, engagement_id):
            raise RuntimeError("db locked")

    rc = watcher_mod.watch(ENG, once=True, poc_dir=tmp_path, ledger=BrokenLedger())
    assert rc == 0  # the cycle failed but the watcher continued and exited cleanly


# ---------------------------------------------------------------------------
# CLI surface (webpent-poc)
# ---------------------------------------------------------------------------
def test_cli_record_success(monkeypatch, ledger, tmp_path) -> None:
    fid = str(_finding_dict(ledger)["id"])
    monkeypatch.setattr(
        "webpent.reporter.poc_recorder.playwright_factory",
        _factory(["SAME DATA", "SAME DATA"]),
    )
    result = runner.invoke(
        app,
        ["record", "--finding", fid, "--engagement", ENG,
         "--ledger", str(tmp_path / "ledger.sqlite3"),
         "--output", str(tmp_path / "poc"),
         "--owner-token", "o", "--foreign-token", "f"],
    )
    assert result.exit_code == 0, result.output
    assert "status=recorded" in result.output
    assert (tmp_path / "poc" / f"poc_{fid}.webm").exists()


def test_cli_record_fail_soft_exit_zero(monkeypatch, ledger, tmp_path) -> None:
    fid = str(_finding_dict(ledger)["id"])

    def exploding_factory(record_dir):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "webpent.reporter.poc_recorder.playwright_factory", exploding_factory
    )
    result = runner.invoke(
        app,
        ["record", "--finding", fid, "--engagement", ENG,
         "--ledger", str(tmp_path / "ledger.sqlite3"),
         "--output", str(tmp_path / "poc"),
         "--owner-token", "o", "--foreign-token", "f"],
    )
    assert result.exit_code == 0  # fail-soft: POC failure is not an error exit
    assert "status=failed" in result.output
    assert "RuntimeError" in result.output


def test_cli_export_all_promoted(monkeypatch, ledger, tmp_path) -> None:
    result = runner.invoke(
        app,
        ["export", "--engagement", ENG,
         "--ledger", str(tmp_path / "ledger.sqlite3"),
         "--output", str(tmp_path / "subs"),
         "--poc-dir", str(tmp_path / "poc")],
    )
    assert result.exit_code == 0, result.output
    assert "exported=1" in result.output
    fid = str(_finding_dict(ledger)["id"])
    assert (tmp_path / "subs" / f"{fid}_bugbounty.md").exists()
    sidecar = json.loads((tmp_path / "subs" / f"{fid}_evidence.json").read_text())
    assert sidecar["finding_id"] == fid


def test_cli_record_unknown_finding_fails_with_param_error(ledger, tmp_path) -> None:
    result = runner.invoke(
        app,
        ["record", "--finding", "99999999-9999-4999-8999-999999999999",
         "--engagement", ENG,
         "--ledger", str(tmp_path / "ledger.sqlite3"),
         "--owner-token", "o", "--foreign-token", "f"],
    )
    assert result.exit_code != 0
    assert "not found" in result.output
