"""U-EMU-5 — Emulator CLI tests (5 tests)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import emulator_cli
import pytest
from click.testing import CliRunner
from emulator_cli import cli

runner = CliRunner()


@pytest.fixture
def fake_compose(monkeypatch) -> list[list[str]]:
    """Replace the docker layer with a recorder; returns the calls."""
    calls: list[list[str]] = []

    def fake_run(args: list[str]) -> subprocess.CompletedProcess:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(emulator_cli, "run_compose", fake_run)
    monkeypatch.setattr(emulator_cli, "docker_available", lambda: True)
    return calls


def test_emulator_start(fake_compose) -> None:
    result = runner.invoke(cli, ["start"])
    assert result.exit_code == 0, result.output
    assert fake_compose[0] == ["up", "-d", "--build"]
    assert "localhost:3000" in result.output
    assert "localhost:9090" in result.output


def test_status_accurate(monkeypatch) -> None:
    monkeypatch.setattr(emulator_cli, "docker_available", lambda: False)
    result = runner.invoke(cli, ["status"])
    assert result.exit_code == 0
    assert "down" in result.output

    monkeypatch.setattr(emulator_cli, "docker_available", lambda: True)

    def fake_run(args):
        payload = '{"Service":"waf","State":"running"}\n' \
                  '{"Service":"juice-shop","State":"exited"}\n'
        return subprocess.CompletedProcess(args, 0, stdout=payload,
                                           stderr="")

    monkeypatch.setattr(emulator_cli, "run_compose", fake_run)
    result = runner.invoke(cli, ["status"])
    assert result.exit_code == 0
    assert "waf" in result.output and "running" in result.output
    assert "juice-shop" in result.output and "exited" in result.output


def test_logs_accessible(monkeypatch) -> None:
    monkeypatch.setattr(emulator_cli, "docker_available", lambda: False)
    result = runner.invoke(cli, ["logs"])
    assert result.exit_code != 0
    assert "docker is not available" in result.output

    monkeypatch.setattr(emulator_cli, "docker_available", lambda: True)

    def fake_run(args):
        assert args[:2] == ["logs", "--tail"]
        return subprocess.CompletedProcess(args, 0,
                                           stdout="waf  | audit log line\n",
                                           stderr="")

    monkeypatch.setattr(emulator_cli, "run_compose", fake_run)
    result = runner.invoke(cli, ["logs", "--tail", "5"])
    assert result.exit_code == 0
    assert "audit log line" in result.output


def test_analyze_produces_report(sample_logs: Path, monkeypatch) -> None:
    monkeypatch.setattr(emulator_cli, "LOG_DIR", sample_logs)
    result = runner.invoke(cli, ["analyze"])
    assert result.exit_code == 0, result.output
    report = sample_logs.parent / "attack_report.md"
    assert report.is_file()
    text = report.read_text()
    assert "# Emulator Attack Report" in text
    assert "Top attackers" in text
    assert "10.0.0.2" in text


def test_targets_list() -> None:
    result = runner.invoke(cli, ["targets"])
    assert result.exit_code == 0
    for url in ("http://localhost:3000", "http://localhost:8080",
                "http://localhost:9000", "http://localhost:80",
                "http://localhost:8000", "http://localhost:9090"):
        assert url in result.output
