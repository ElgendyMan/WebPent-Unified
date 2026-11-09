"""E2E Wave R-3 regression lock: dalfox v3 ``--url`` required-flag fallback.

Runtime proof (2026-09-15) showed dalfox v3.2.2 exits with clap error code 2
("required arguments were not provided: --url") when invoked with the dalfox
2.x positional-target argv, and exits code 1 with findings JSON when it DOES
find issues. The wrapper must transparently retry with the v3 argv and
tolerate the findings exit code — while never inventing output.

These locks pin:
  L1  clap-required-args error  -> retry with `--url <target>` argv (positional dropped)
  L2  v3 exit 1 with findings stdout -> captured as output (not raised)
  L3  v3 usage error with EMPTY stdout -> still raises (fail closed)
  L4  output passthrough unchanged for dalfox 2.x positional success
"""
from __future__ import annotations

import pytest

from webpent.shared.exceptions import ToolExecutionError
from webpent.tools.exploitation import dalfox as dalfox_mod


class _FakeRunner:
    def __init__(self, script):
        self.script = script  # list of (effect) callables
        self.calls: list[list[str]] = []

    def __call__(self, cmd, timeout=None):
        self.calls.append(list(cmd))
        idx = len(self.calls) - 1
        if idx >= len(self.script):
            raise AssertionError("unexpected extra run_command call")
        effect = self.script[idx]
        if isinstance(effect, ToolExecutionError):
            raise effect
        return effect


def _clap_required_url_error(cmd: list[str]) -> ToolExecutionError:
    return ToolExecutionError(
        cmd,
        returncode=2,
        message=(
            "error: the following required arguments were not provided:\n"
            "  --url <URL>"
        ),
        stdout="",
        stderr="error: the following required arguments were not provided:\n  --url <URL>\n\nUsage: dalfox url --url <URL> <TARGET>...",
    )


@pytest.fixture()
def _scoped(monkeypatch):
    monkeypatch.setattr(
        dalfox_mod, "get_settings",
        lambda: type("S", (), {"dalfox_path": "dalfox", "dalfox_timeout": 5})(),
    )
    from webpent.shared.engagement_scope import set_engagement_target_hosts

    set_engagement_target_hosts("127.0.0.1")


def test_l1_v3_required_url_flag_retries_with_url_argv(monkeypatch, _scoped):
    """L1: positional argv fails with clap error -> retry must use --url and drop positional."""
    runner = _FakeRunner([
        _clap_required_url_error(["dalfox", "url", "http://127.0.0.1:9/x?name=a"]),
        '{"meta": {"findings_count": 0}}',
    ])
    monkeypatch.setattr(dalfox_mod, "run_command", runner)
    out = dalfox_mod.run_dalfox("http://127.0.0.1:9/x?name=a")
    assert '"findings_count": 0' in out
    assert len(runner.calls) == 2
    v3 = runner.calls[1]
    assert v3[1] == "url" and "--url" in v3
    # positional target dropped, url carried exactly once
    assert v3.count("http://127.0.0.1:9/x?name=a") == 1
    assert v3[v3.index("--url") + 1] == "http://127.0.0.1:9/x?name=a"


def test_l2_v3_findings_exit_code_tolerated(monkeypatch, _scoped):
    """L2: v3 exit 1 WITH findings stdout is evidence, not failure."""
    err = ToolExecutionError(
        ["dalfox", "url", "--url", "u"],
        returncode=1,
        message="exit 1",
        stdout='{"results": [{"type": "V"}]}',
        stderr="",
    )
    runner = _FakeRunner([
        _clap_required_url_error(["dalfox", "url", "u"]),
        err,  # v3 argv raises with findings stdout
    ])
    monkeypatch.setattr(dalfox_mod, "run_command", runner)
    out = dalfox_mod.run_dalfox("http://127.0.0.1:9/x?name=a")
    assert '"type": "V"' in out


def test_l3_v3_empty_stdout_failure_still_raises(monkeypatch, _scoped):
    """L3: v3 failure with empty stdout must still fail closed."""
    err = ToolExecutionError(
        ["dalfox", "url", "--url", "u"],
        returncode=1,
        message="panic: runtime error",
        stdout="",
        stderr="panic: runtime error",
    )
    runner = _FakeRunner([
        _clap_required_url_error(["dalfox", "url", "u"]),
        err,
    ])
    monkeypatch.setattr(dalfox_mod, "run_command", runner)
    with pytest.raises(ToolExecutionError):
        dalfox_mod.run_dalfox("http://127.0.0.1:9/x?name=a")


def test_l4_v2_positional_success_unchanged(monkeypatch, _scoped):
    """L4: dalfox 2.x positional argv keeps working with zero retries."""
    runner = _FakeRunner(["clean 2.x output"])
    monkeypatch.setattr(dalfox_mod, "run_command", runner)
    out = dalfox_mod.run_dalfox("http://127.0.0.1:9/x?name=a")
    assert out == "clean 2.x output"
    assert len(runner.calls) == 1
    assert runner.calls[0][1] == "url"
    assert runner.calls[0][2] == "http://127.0.0.1:9/x?name=a"
