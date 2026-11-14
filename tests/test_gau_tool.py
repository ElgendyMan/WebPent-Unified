"""Tests for the gau archive-discovery tool wrapper (Ultimate plan
2026-10-27, proposal 5 phase 2).

Mirrors ``tests/test_vip_arjun_parameter_discovery.py`` — the closest
precedent for a bounded, scope-gated, settings-flagged recon tool
wrapper. No network, no gau binary: every execution path is driven by
monkeypatching ``run_command``; every refusal path is proven to fire
BEFORE any subprocess could spawn.
"""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

import webpent.tools.recon.gau as gau
from webpent.shared.exceptions import ToolExecutionError

# Realistic gau stdout: http(s) URLs one per line, plus junk lines gau
# sometimes emits (blank lines, non-URL status text) and duplicates.
FAKE_GAU_STDOUT = "\n".join(
    [
        "https://target.test/",
        "http://target.test/old/admin?debug=1",
        "https://target.test/",
        "ftp://target.test/not-http",
        "not a url at all",
        "",
        "https://target.test/legacy/api/v1",
        "https://target.test/legacy/api/v1",
    ]
)


def _in_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gau, "is_engagement_target_host", lambda host: True)


def _enabled_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gau,
        "get_settings",
        lambda: SimpleNamespace(enable_archive_discovery=True),
    )


# ---------------------------------------------------------------------------
# registration + gates (all before any subprocess)
# ---------------------------------------------------------------------------


def test_gau_registers_in_the_tool_registry():
    # auto_discover() uses a hash-pinned hardcoded module list, so the
    # wrapper registers on import — reload to be robust against a
    # registry cleared by an earlier test.
    importlib.reload(gau)
    from webpent.tools.registry import get_tool

    entry = get_tool("gau")
    assert entry is not None
    assert entry.category == "recon"


def test_gau_refuses_when_settings_flag_disabled(monkeypatch):
    _in_scope(monkeypatch)
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("subprocess must not run when the flag is off")

    monkeypatch.setattr(gau, "run_command", fail_if_called)
    # Real settings object: the flag defaults to False (explicit
    # operator opt-in per the plan).
    assert gau.get_settings().enable_archive_discovery is False
    with pytest.raises(ToolExecutionError, match="enable_archive_discovery"):
        gau.run_gau("target.test")
    assert called is False


def test_gau_refuses_out_of_scope_domain_before_subprocess(monkeypatch):
    monkeypatch.setattr(gau, "is_engagement_target_host", lambda host: False)
    _enabled_settings(monkeypatch)
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("subprocess must not run out of scope")

    monkeypatch.setattr(gau, "run_command", fail_if_called)
    with pytest.raises(ToolExecutionError, match="out-of-scope"):
        gau.run_gau("outsider.test")
    assert called is False


def test_gau_rejects_url_instead_of_bare_domain():
    with pytest.raises(ValueError, match="bare domain"):
        gau.run_gau("https://target.test/")


def test_gau_rejects_unknown_providers(monkeypatch):
    _in_scope(monkeypatch)
    _enabled_settings(monkeypatch)
    with pytest.raises(ValueError, match="providers"):
        gau.run_gau("target.test", providers="wayback,reddit")


def test_gau_rejects_out_of_range_timeout_and_max_urls(monkeypatch):
    _in_scope(monkeypatch)
    _enabled_settings(monkeypatch)
    with pytest.raises(ValueError, match="timeout"):
        gau.run_gau("target.test", timeout=0)
    with pytest.raises(ValueError, match="max_urls"):
        gau.run_gau("target.test", max_urls=0)


# ---------------------------------------------------------------------------
# command shape + parsing (run_command monkeypatched — never executed)
# ---------------------------------------------------------------------------


def test_gau_builds_the_documented_bounded_command():
    cmd = gau._build_gau_command("gau", "target.test", providers="wayback,otx", threads=5)
    assert cmd == ["gau", "--providers", "wayback,otx", "--threads", "5", "target.test"]


def test_gau_parses_dedupes_and_bounds_urls(monkeypatch):
    _in_scope(monkeypatch)
    _enabled_settings(monkeypatch)
    seen_cmds: list[list[str]] = []

    def fake_run_command(cmd, timeout=None):
        seen_cmds.append(cmd)
        return FAKE_GAU_STDOUT

    monkeypatch.setattr(gau, "run_command", fake_run_command)

    result = gau.run_gau("target.test", max_urls=2)
    assert result == {
        "urls": [
            "https://target.test/",
            "http://target.test/old/admin?debug=1",
        ],
        "count": 2,
        "truncated": True,  # a third unique URL existed but was dropped
    }
    assert seen_cmds == [
        ["gau", "--providers", "wayback,commoncrawl,otx", "--threads", "5", "target.test"]
    ]


def test_gau_no_truncation_flag_when_under_the_cap(monkeypatch):
    _in_scope(monkeypatch)
    _enabled_settings(monkeypatch)
    monkeypatch.setattr(gau, "run_command", lambda cmd, timeout=None: FAKE_GAU_STDOUT)
    result = gau.run_gau("target.test", max_urls=500)
    assert result["count"] == 3  # three unique http(s) URLs
    assert result["truncated"] is False
    assert "ftp://target.test/not-http" not in result["urls"]


def test_gau_empty_output_is_not_an_error(monkeypatch):
    _in_scope(monkeypatch)
    _enabled_settings(monkeypatch)
    monkeypatch.setattr(gau, "run_command", lambda cmd, timeout=None: "")
    assert gau.run_gau("target.test") == {"urls": [], "count": 0, "truncated": False}
    monkeypatch.setattr(gau, "run_command", lambda cmd, timeout=None: "\n \n")
    assert gau.run_gau("target.test") == {"urls": [], "count": 0, "truncated": False}


def test_gau_parse_output_handles_bytes_and_junk():
    parsed = gau._parse_gau_output(b"https://target.test/a\njunk\n", max_urls=10)
    assert parsed == {"urls": ["https://target.test/a"], "count": 1, "truncated": False}
    assert gau._parse_gau_output(None) == {"urls": [], "count": 0, "truncated": False}
