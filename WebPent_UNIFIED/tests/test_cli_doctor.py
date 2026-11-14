# tests/test_cli_doctor.py
"""Tests for the ONE ``webpent doctor`` command (Track 8.4/3.6, 0.26.0).

Roadmap contract: a single command that checks the local database, the
LLM provider, and the external tools, and shows missing items clearly.

The tests pin the environment to a deterministic, offline posture:
temporary sqlite DB, LLM disabled (deterministic path), and the real
``shutil.which`` results for external tools (advisory WARN area).
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from webpent.cli import app

runner = CliRunner()


@pytest.fixture()
def deterministic_env(monkeypatch, tmp_path):
    """Force the offline/deterministic posture the doctor expects as OK."""
    monkeypatch.setenv("LLM_ENABLED", "false")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'doctor_test.db'}")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


class TestDoctorCommand:
    def test_registered_on_main_app(self):
        """The dangling-reference fix: `webpent doctor` must exist."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0, result.output
        assert "doctor" in result.output

    def test_deterministic_posture_exits_zero(self, deterministic_env):
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0, result.output
        assert "OK" in result.output
        assert "database" in result.output
        assert "deterministic path is the plan" in result.output
        assert "usable" in result.output

    def test_missing_external_tools_listed_clearly(self, deterministic_env, monkeypatch):
        """Roadmap wording: 'shows missing items clearly' — even a machine
        with zero external tools must name every one of them."""
        import shutil as _shutil

        monkeypatch.setattr(_shutil, "which", lambda name: None)
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0, result.output  # tools are advisory
        for tool in ("nuclei", "subfinder", "httpx-pd", "katana", "dalfox", "sqlmap"):
            assert tool in result.output
        assert "missing" in result.output

    def test_broken_database_fails_closed(self, monkeypatch, tmp_path):
        """A DB the manager refuses to open must FAIL the doctor (exit 1)."""
        monkeypatch.setenv("LLM_ENABLED", "false")
        monkeypatch.setenv("DATABASE_URL", "file:/definitely/not/sqlite.db")
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 1, result.output
        assert "FAIL" in result.output
        assert "database" in result.output
        assert "blocking gaps" in result.output

    def test_llm_enabled_without_keys_fails(self, monkeypatch, tmp_path):
        """scripts/doctor.py policy inherited: LLM enabled + zero providers
        configured = blocking gap, not a silent degradation."""
        monkeypatch.setenv("LLM_ENABLED", "true")
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'llm_gap.db'}")
        for key in (
            "GROQ_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "OPENROUTER_API_KEY",
            "GITHUB_API_KEY",
            "CEREBRAS_API_KEY",
            "MISTRAL_API_KEY",
            "GEMINI_API_KEY",
            "COHERE_API_KEY",
            "ZAI_API_KEY",
            "CLOUDFLARE_API_KEY",
            "CLOUDFLARE_ACCOUNT_ID",
        ):
            monkeypatch.delenv(key, raising=False)
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 1, result.output
        assert "no provider key configured" in result.output

    def test_json_report_shape(self, deterministic_env):
        result = runner.invoke(app, ["doctor", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output[result.output.index("{") :])
        assert payload["status"] == "ok"
        areas = {c["area"] for c in payload["checks"]}
        assert {"version", "database", "llm", "tools", "knowledge", "playwright"} <= areas
        assert isinstance(payload["missing"], list)

    def test_all_tools_present_is_ok(self, deterministic_env, monkeypatch):
        import shutil as _shutil

        monkeypatch.setattr(_shutil, "which", lambda name: "/usr/local/bin/" + name)
        result = runner.invoke(app, ["doctor", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output[result.output.index("{") :])
        tools = next(c for c in payload["checks"] if c["area"] == "tools")
        assert tools["status"] == "ok"
        assert tools["missing"] == []

    def test_command_registered_exactly_once(self):
        """Guard against double registration (the register_doctor helper
        must be idempotent at import time — the app is built once)."""
        from webpent.cli.commands import app as main_app

        registered = [
            c.name for c in main_app.registered_commands if c.name == "doctor"
        ]
        assert registered == ["doctor"]
