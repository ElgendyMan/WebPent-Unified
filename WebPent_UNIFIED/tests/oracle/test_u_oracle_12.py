"""U-ORACLE-12 — the Oracle CLI + Dashboard (v88, plan 2026-10-17-v88-oracle.md)."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest
from typer.testing import CliRunner

from webpent.cli.oracle import oracle_app
from webpent.oracle.dashboard import SECTION_ORDER

WORK = Path(__file__).resolve().parents[2]
RUNNER = CliRunner()
ENV = {"WEBPENT_ORACLE_WORKDIR": str(WORK)}

FINDINGS = {
    "findings": [
        {"source": "github_secret_scanning", "category": "credential",
         "raw_data": {"repo": "org/x", "api_key": {"sha256": "h"}},
         "confidence": 0.9},
        {"source": "crtsh", "category": "subdomain",
         "raw_data": {"subdomain": "dev.target.test"}, "confidence": 0.9},
        {"source": "cloud_buckets", "category": "data_leak",
         "raw_data": {"bucket": "s3://x"}, "confidence": 0.8},
        {"source": "shodan", "category": "tech",
         "raw_data": {"banner": "nginx/1.18.0"}, "confidence": 0.9},
    ]
}


def _run(*args, expect_ok: bool = True):
    result = RUNNER.invoke(
        oracle_app, list(args), env=ENV,
    )
    if expect_ok:
        assert result.exit_code == 0, result.output
    return result


def _gather(state: Path, tmp_path: Path) -> dict:
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(FINDINGS), encoding="utf-8")
    result = _run(
        "gather", "--target", "target.test",
        "--findings-json", str(findings_file),
        "--oracle-dir", str(state),
    )
    return json.loads(result.output.splitlines()[-1])


# -- spec test 1: the oracle sub-app is registered in the main CLI -------------------

def test_oracle_cli_registered_in_main_cli(tmp_path: Path) -> None:
    from webpent.cli.commands import app as main_app

    result = RUNNER.invoke(
        main_app,
        ["oracle", "status", "--oracle-dir", str(tmp_path / "s")],
        env=ENV,
    )
    assert result.exit_code == 0, result.output
    assert result.output.splitlines()[0].startswith("advisory:")


# -- spec test 2: the full passive pipeline runs advisory-only, zero-touch -----------

def test_full_pipeline_advisory_and_zero_touch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"

    def _no_socket(*args, **kwargs):
        raise AssertionError("the oracle CLI opened a socket")

    monkeypatch.setattr(socket, "socket", _no_socket)
    payload = _gather(state, tmp_path)
    assert payload["findings"] == 4
    assert payload["zero_touch_proof"]["active"] is True

    for command in (
        "infer-stack", "signals", "graph", "predict", "compose",
        "simulate", "perspectives", "impact",
    ):
        result = _run(command, "--oracle-dir", str(state))
        assert result.output.splitlines()[0].startswith("advisory:"), command

    sim = _run("simulate", "--oracle-dir", str(state))
    assert json.loads(sim.output.splitlines()[-1])["executed"] is False

    rep = _run("report", "--format", "json", "--oracle-dir", str(state))
    doc = json.loads(rep.output.splitlines()[-1])
    assert len(doc["sections"]) == 7


# -- spec test 3: the dashboard renders six fixed sections ---------------------------

def test_dashboard_sections_render(tmp_path: Path) -> None:
    state = tmp_path / "state"
    _gather(state, tmp_path)
    _run("graph", "--oracle-dir", str(state))
    result = _run("status", "--oracle-dir", str(state))
    for section in SECTION_ORDER:
        assert f"== {section} ==" in result.output, section
    payload = json.loads(result.output.splitlines()[-1])
    assert payload["target_id"] == "target.test"
    assert payload["counts"]["findings"] == 4
    assert payload["stages"]["report"] is True
    assert payload["advisory"] is True


# -- spec test 4: no accuracy claim without samples (ORACLE-L-8 via CLI) --------------

def test_validate_gates_accuracy_claim(tmp_path: Path) -> None:
    state = tmp_path / "state"
    _gather(state, tmp_path)
    _run("predict", "--oracle-dir", str(state))

    empty = json.loads(
        _run("validate", "--oracle-dir", str(state)).output.splitlines()[-1]
    )
    assert empty["accuracy_claim"] is None

    for i in range(10):
        _run("validate", "--record", f"p-{i}", "--kind", "path_prediction",
             "--oracle-dir", str(state))
    for i in range(7):
        _run("validate", "--outcome", f"p-{i}", "--result", "confirmed",
             "--oracle-dir", str(state))
    for i in range(7, 10):
        _run("validate", "--outcome", f"p-{i}", "--result", "refuted",
             "--oracle-dir", str(state))
    claimed = json.loads(
        _run("validate", "--oracle-dir", str(state)).output.splitlines()[-1]
    )
    assert claimed["accuracy_claim"] is not None
    assert claimed["accuracy_claim"]["samples"] == 10
    assert claimed["accuracy_claim"]["accuracy"] == pytest.approx(0.7)


# -- spec test 5: markdown and pdf reports written to disk ----------------------------

def test_report_writes_md_and_pdf(tmp_path: Path) -> None:
    state = tmp_path / "state"
    _gather(state, tmp_path)
    md_out = tmp_path / "oracle_report.md"
    _run("report", "--format", "md", "--out", str(md_out),
         "--oracle-dir", str(state))
    text = md_out.read_text(encoding="utf-8")
    assert "1. Executive Summary" in text
    assert "7. Perspectives, Impact and Validation" in text

    pdf_out = tmp_path / "oracle_report.pdf"
    _run("report", "--format", "pdf", "--out", str(pdf_out),
         "--oracle-dir", str(state))
    content = pdf_out.read_bytes()
    assert content.startswith(b"%PDF")
    assert len(content) > 1000


# -- guards ---------------------------------------------------------------------------

def test_every_command_prints_preamble_first(tmp_path: Path) -> None:
    state = tmp_path / "state"
    _gather(state, tmp_path)
    for command in (
        "status", "infer-stack", "signals", "graph", "predict",
        "compose", "simulate", "perspectives", "impact", "validate",
    ):
        result = _run(command, "--oracle-dir", str(state))
        assert result.output.splitlines()[0].startswith("advisory:"), command


def test_gather_requires_operator_data(tmp_path: Path) -> None:
    result = _run("gather", "--target", "target.test",
                  "--oracle-dir", str(tmp_path / "s"), expect_ok=False)
    assert result.exit_code != 0


def test_fetcher_module_injection(tmp_path: Path) -> None:
    """Operator-injected fetchers are the only network path (ORACLE-L-2)."""
    state = tmp_path / "state"
    module = tmp_path / "fetchers.py"
    module.write_text(
        "FETCHERS = {\n"
        "    'crtsh': lambda source_id, host, key, guard: "
        "[{'subdomain': f'api.{host}'}],\n"
        "}\n",
        encoding="utf-8",
    )
    result = _run(
        "gather", "--target", "target.test",
        "--fetcher-module", str(module), "--oracle-dir", str(state),
    )
    payload = json.loads(result.output.splitlines()[-1])
    assert payload["coverage"]["crtsh"] == "success"
    assert payload["findings"] == 1
    assert payload["zero_touch_proof"]["active"] is True


def test_audit_log_capped(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    (state / "audit.jsonl").write_text(
        "\n".join(
            json.dumps({"command": "old", "ts": 1.0}) for _ in range(1000)
        ) + "\n",
        encoding="utf-8",
    )
    _run("status", "--oracle-dir", str(state))
    lines = (state / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1000
    assert json.loads(lines[-1])["command"] == "status"


def test_pipeline_requires_gathered_report(tmp_path: Path) -> None:
    result = _run("graph", "--oracle-dir", str(tmp_path / "s"),
                  expect_ok=False)
    assert result.exit_code != 0
    assert "gather" in str(result.exception)
