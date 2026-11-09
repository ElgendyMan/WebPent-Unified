"""TEAM-1 Phase 8 — tool scope consistency acceptance tests.

The scope law: sqlmap/dalfox obey the SAME fail-closed engagement-scope
preflight model as ffuf/katana/nuclei:

  * an in-scope URL executes,
  * an out-of-scope URL is DENIED deterministically (ToolExecutionError,
    no subprocess spawned),
  * redirects cannot bypass scope (sqlmap --scope regex; dalfox
    --follow-redirects only for declared hosts),
  * malformed URLs / malformed (empty) scope fail closed.
"""

from __future__ import annotations

import pytest

from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.shared.exceptions import ToolExecutionError


@pytest.fixture()
def declared_scope():
    """Declare one lab target host for the duration of a test."""
    token = set_engagement_target_hosts("https://lab-a.internal")
    try:
        yield {"host": "lab-a.internal"}
    finally:
        clear_engagement_target_hosts(token)


def _scoped_dalfox(monkeypatch):
    from webpent.tools.exploitation import dalfox

    class Settings:
        dalfox_path = "dalfox"
        dalfox_timeout = 5

    calls = {}
    monkeypatch.setattr(dalfox, "get_settings", lambda: Settings())
    monkeypatch.setattr(
        dalfox,
        "run_command",
        lambda command, timeout: calls.update(command=command) or "ok",
    )
    return dalfox, calls


def _scoped_sqlmap(monkeypatch):
    from webpent.tools.exploitation import sqlmap

    class Settings:
        sqlmap_path = "sqlmap"
        sqlmap_timeout = 5

    calls = {}
    monkeypatch.setattr(sqlmap, "get_settings", lambda: Settings())
    monkeypatch.setattr(
        sqlmap,
        "run_command",
        lambda command, timeout: calls.update(command=command) or "sqlmap output",
    )
    return sqlmap, calls


def test_in_scope_url_executes(monkeypatch, declared_scope) -> None:
    dalfox, calls = _scoped_dalfox(monkeypatch)
    result = dalfox.run_dalfox("https://lab-a.internal/search?q=1")
    assert result == "ok"
    assert "url" in calls["command"]

    sqlmap, calls2 = _scoped_sqlmap(monkeypatch)
    result2 = sqlmap.run_sqlmap("https://lab-a.internal/item?id=1")
    assert result2 == "sqlmap output"
    assert calls2["command"]


def test_out_of_scope_url_denied_deterministically(monkeypatch, declared_scope) -> None:
    dalfox, calls = _scoped_dalfox(monkeypatch)
    with pytest.raises(ToolExecutionError) as exc_dalfox:
        dalfox.run_dalfox("https://evil.example.com/x?q=1")
    assert "scope" in str(exc_dalfox.value).lower()
    assert calls == {}, "out-of-scope dalfox must never spawn a subprocess"

    sqlmap, calls2 = _scoped_sqlmap(monkeypatch)
    with pytest.raises(ToolExecutionError) as exc_sqlmap:
        sqlmap.run_sqlmap("https://169.254.169.254/item?id=1")
    assert "scope" in str(exc_sqlmap.value).lower()
    assert calls2 == {}, "out-of-scope sqlmap must never spawn a subprocess"


def test_malformed_url_fails_closed(monkeypatch, declared_scope) -> None:
    dalfox, calls = _scoped_dalfox(monkeypatch)
    with pytest.raises(ToolExecutionError):
        dalfox.run_dalfox("not-a-url")
    assert calls == {}

    sqlmap, calls2 = _scoped_sqlmap(monkeypatch)
    with pytest.raises(ToolExecutionError):
        sqlmap.run_sqlmap("http:///no-host")
    assert calls2 == {}


def test_malformed_empty_scope_is_fail_closed(monkeypatch) -> None:
    """With NO engagement scope declared, nothing may execute."""
    dalfox, _calls = _scoped_dalfox(monkeypatch)
    with pytest.raises(ToolExecutionError):
        dalfox.run_dalfox("https://lab-a.internal/search?q=1")
    sqlmap, _calls2 = _scoped_sqlmap(monkeypatch)
    with pytest.raises(ToolExecutionError):
        sqlmap.run_sqlmap("https://lab-a.internal/item?id=1")


def test_redirects_cannot_bypass_scope(monkeypatch, declared_scope) -> None:
    """sqlmap embeds a --scope regex pinned to declared hosts; dalfox only
    ever enables --follow-redirects for an in-scope (declared) host."""
    sqlmap, calls = _scoped_sqlmap(monkeypatch)
    sqlmap.run_sqlmap("https://lab-a.internal/item?id=1")
    command = calls["command"]
    assert "--scope" in command, "sqlmap must pin redirects with --scope"
    scope_regex = command[command.index("--scope") + 1]
    assert "lab-a\\.internal".replace("\\", "") in scope_regex.replace("\\\\", "\\") or "lab" in scope_regex
    assert "evil" not in scope_regex

    dalfox, dalcalls = _scoped_dalfox(monkeypatch)
    dalfox.run_dalfox("https://lab-a.internal/search?q=1")
    assert "--follow-redirects" in dalcalls["command"]

    # A redirect-target host that is NOT declared is rejected outright if
    # handed to the tool as a scan target.
    with pytest.raises(ToolExecutionError):
        dalfox.run_dalfox("https://redirect-victim.internal/x")


def test_scope_regex_covers_declared_hosts(monkeypatch) -> None:
    from webpent.tools.exploitation.sqlmap import _engagement_scope_regex

    token = set_engagement_target_hosts("https://lab-a.internal", "http://lab-b.internal:8080")
    try:
        regex = _engagement_scope_regex()
        assert regex is not None
        # re.escape escapes dots/dashes; normalise for the assertion.
        plain = regex.replace("\\-", "-").replace("\\.", ".")
        assert "lab-a.internal" in plain and "lab-b.internal" in plain
        assert regex.startswith("^https?://")
    finally:
        clear_engagement_target_hosts(token)
