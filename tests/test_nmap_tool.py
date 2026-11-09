"""Tests for the bounded, double-gated nmap infrastructure probe
wrapper (Ultimate plan 2026-10-27, proposal 5 phase 3).

Mirrors ``tests/test_vip_arjun_parameter_discovery.py``. No network,
no nmap binary: every execution path is driven by monkeypatching
``run_command``; every refusal path (scope, settings flag, explicit
infra-scope confirmation) is proven to fire BEFORE any subprocess
could spawn. The command-shape tests pin the hard safety rules: never
``-sS``, never ``--script``.
"""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

import webpent.tools.recon.nmap as nmap
from webpent.shared.exceptions import ToolExecutionError

FAKE_NMAP_STDOUT = "\n".join(
    [
        "Starting Nmap 7.94 ( https://nmap.org )",
        "Nmap scan report for target.test (203.0.113.10)",
        "Host is up (0.0010s latency).",
        "Not shown: 98 closed tcp ports (conn-refused)",
        "PORT     STATE SERVICE",
        "22/tcp   open  ssh",
        "80/tcp   open  http",
        "443/tcp  open  https",
        "8080/tcp closed http-proxy",
        "",
        "Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds",
    ]
)


def _in_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nmap, "is_engagement_target_host", lambda host: True)


def _enabled_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        nmap,
        "get_settings",
        lambda: SimpleNamespace(
            enable_infra_scan=True, nmap_top_ports=100, nmap_path="nmap"
        ),
    )


# ---------------------------------------------------------------------------
# registration + gates (all before any subprocess)
# ---------------------------------------------------------------------------


def test_nmap_registers_in_the_tool_registry():
    # auto_discover() uses a hash-pinned hardcoded module list, so the
    # wrapper registers on import — reload to be robust against a
    # registry cleared by an earlier test.
    importlib.reload(nmap)
    from webpent.tools.registry import get_tool

    entry = get_tool("nmap")
    assert entry is not None
    assert entry.category == "recon"


def test_nmap_refuses_when_settings_flag_off_even_with_confirmation(monkeypatch):
    _in_scope(monkeypatch)
    # Real settings object: enable_infra_scan defaults to False.
    assert nmap.get_settings().enable_infra_scan is False
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("subprocess must not run when the settings gate is off")

    monkeypatch.setattr(nmap, "run_command", fail_if_called)
    with pytest.raises(ToolExecutionError, match="enable_infra_scan"):
        nmap.run_nmap("target.test", infra_scope_confirmed=True)
    assert called is False


def test_nmap_refuses_without_explicit_infra_scope_confirmation(monkeypatch):
    _in_scope(monkeypatch)
    _enabled_settings(monkeypatch)
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("subprocess must not run without explicit confirmation")

    monkeypatch.setattr(nmap, "run_command", fail_if_called)
    # The error must explain BOTH gates (settings flag + confirmation).
    with pytest.raises(ToolExecutionError, match="infra_scope_confirmed"):
        nmap.run_nmap("target.test")  # infra_scope_confirmed defaults to False
    assert called is False


def test_nmap_refuses_out_of_scope_host_before_subprocess(monkeypatch):
    monkeypatch.setattr(nmap, "is_engagement_target_host", lambda host: False)
    _enabled_settings(monkeypatch)
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("subprocess must not run out of scope")

    monkeypatch.setattr(nmap, "run_command", fail_if_called)
    with pytest.raises(ToolExecutionError, match="out-of-scope"):
        nmap.run_nmap("outsider.test", infra_scope_confirmed=True)
    assert called is False


def test_nmap_rejects_malformed_port_specs(monkeypatch):
    _in_scope(monkeypatch)
    _enabled_settings(monkeypatch)
    with pytest.raises(ValueError, match="ports"):
        nmap.run_nmap("target.test", ports="80;rm -rf /", infra_scope_confirmed=True)
    with pytest.raises(ValueError, match="ports"):
        nmap.run_nmap("target.test", ports="99999", infra_scope_confirmed=True)
    with pytest.raises(ValueError, match="timeout"):
        nmap.run_nmap("target.test", timeout=1, infra_scope_confirmed=True)


def test_nmap_rejects_hostless_target():
    with pytest.raises(ValueError, match="host"):
        nmap.run_nmap("")


# ---------------------------------------------------------------------------
# command shape (hard safety rules)
# ---------------------------------------------------------------------------


def test_nmap_command_never_uses_syn_scan_or_scripts():
    top_ports_cmd = nmap._build_nmap_command(
        "nmap", "target.test", top_ports=100, ports=None, timeout=300
    )
    ports_cmd = nmap._build_nmap_command(
        "nmap", "target.test", top_ports=100, ports="80,443", timeout=300
    )
    for cmd in (top_ports_cmd, ports_cmd):
        assert "-sS" not in cmd  # never raw-socket SYN scan (needs root)
        assert "--script" not in cmd  # never NSE (exploit-adjacent)
        assert "-sT" in cmd
        assert "--max-retries" in cmd
    assert top_ports_cmd == [
        "nmap", "-Pn", "-sT", "--top-ports", "100",
        "--max-retries", "2", "--host-timeout", "300s", "target.test",
    ]
    assert ports_cmd == [
        "nmap", "-Pn", "-sT", "-sV", "-p", "80,443",
        "--max-retries", "2", "--host-timeout", "300s", "target.test",
    ]


def test_nmap_extracts_host_from_url_input():
    assert nmap._extract_host("https://target.test/path") == "target.test"
    assert nmap._extract_host("TARGET.test") == "target.test"
    assert nmap._extract_host("") == ""


# ---------------------------------------------------------------------------
# execution + parsing (run_command monkeypatched — never executed)
# ---------------------------------------------------------------------------


def test_nmap_parses_open_ports_from_realistic_output(monkeypatch):
    _in_scope(monkeypatch)
    _enabled_settings(monkeypatch)
    seen_cmds: list[list[str]] = []

    def fake_run_command(cmd, timeout=None):
        seen_cmds.append(cmd)
        return FAKE_NMAP_STDOUT

    monkeypatch.setattr(nmap, "run_command", fake_run_command)
    result = nmap.run_nmap("target.test", infra_scope_confirmed=True)
    assert result == {
        "host": "target.test",
        "open_ports": [
            {"port": 22, "protocol": "tcp", "service": "ssh"},
            {"port": 80, "protocol": "tcp", "service": "http"},
            {"port": 443, "protocol": "tcp", "service": "https"},
        ],
        "count": 3,  # the closed 8080 line must NOT be parsed
    }
    assert seen_cmds and "--top-ports" in seen_cmds[0]


def test_nmap_unparseable_output_returns_empty_with_raw_flag(monkeypatch):
    _in_scope(monkeypatch)
    _enabled_settings(monkeypatch)
    monkeypatch.setattr(nmap, "run_command", lambda cmd, timeout=None: "total garbage")
    result = nmap.run_nmap("target.test", infra_scope_confirmed=True)
    assert result["open_ports"] == []
    assert result["count"] == 0
    assert result["raw_available"] is True


def test_nmap_empty_output_returns_empty_without_raw_flag(monkeypatch):
    _in_scope(monkeypatch)
    _enabled_settings(monkeypatch)
    monkeypatch.setattr(nmap, "run_command", lambda cmd, timeout=None: "")
    result = nmap.run_nmap("target.test", infra_scope_confirmed=True)
    assert result == {"host": "target.test", "open_ports": [], "count": 0}


def test_nmap_explicit_ports_run_service_detection(monkeypatch):
    _in_scope(monkeypatch)
    _enabled_settings(monkeypatch)
    seen_cmds: list[list[str]] = []
    monkeypatch.setattr(
        nmap,
        "run_command",
        lambda cmd, timeout=None: seen_cmds.append(cmd) or "443/tcp open  https",
    )
    result = nmap.run_nmap(
        "target.test", ports="443", infra_scope_confirmed=True
    )
    assert result["count"] == 1
    assert seen_cmds[0][3:5] == ["-sV", "-p"] or "-sV" in seen_cmds[0]
    assert "--top-ports" not in seen_cmds[0]
