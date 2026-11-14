"""v87 red-team regressions (RT-01..RT-11, plan 2026-10-17-v87-red-team.md).

Each test clones a confirmed defect first (red), then the root-cause fix
turns it green. Red-team evidence lives in the plan's findings table.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from webpent.apex.executor import ToolExecutor, UnknownToolForExecutionError
from webpent.apex.learning import ApexLearning
from webpent.apex.mcp_server import ApexMcpServer
from webpent.apex.parallel_runner import ChainRunResult, ParallelRunner, StepResult
from webpent.apex.sandbox import LocalSandbox, SandboxConfig
from webpent.apex.tool_chain_builder import ChainStep, ToolChain, ToolChainBuilder
from webpent.apex.tool_registry import ToolRegistry
from webpent.cli.apex import apex_app

WORK = Path(__file__).resolve().parents[2]
REGISTRY_PATH = WORK / "config" / "apex" / "tools.yaml"
CHAINS_PATH = WORK / "config" / "apex" / "chains.yaml"
RUNNER = CliRunner()


def _build_chain(state: Path, hyp: str = "xss") -> str:
    build = RUNNER.invoke(
        apex_app,
        ["chain", "build", "--hypothesis", hyp, "--target", "t.test",
         "--apex-dir", str(state)],
        env={"WEBPENT_APEX_WORKDIR": str(WORK)},
    )
    assert build.exit_code == 0, build.output
    return json.loads(build.output.splitlines()[-1])["chain_id"]


def _last_run_line(state: Path) -> dict:
    return json.loads(
        (state / "runs.jsonl").read_text(encoding="utf-8").splitlines()[-1]
    )


# -- RT-01: the apex CLI must actually be reachable --------------------------

def test_apex_cli_registered_in_main_cli(tmp_path: Path) -> None:
    from webpent.cli.commands import app as main_app

    result = RUNNER.invoke(
        main_app,
        ["apex", "status", "--apex-dir", str(tmp_path / "s")],
        env={"WEBPENT_APEX_WORKDIR": str(WORK)},
    )
    assert result.exit_code == 0, result.output
    assert result.output.splitlines()[0].startswith("advisory:")


def test_module_entry_point_runs(tmp_path: Path, monkeypatch) -> None:
    import contextlib
    import io

    from webpent.cli import apex as apex_cli

    buf = io.StringIO()
    monkeypatch.setattr(
        "sys.argv", ["apex", "status", "--apex-dir", str(tmp_path / "s")]
    )
    with contextlib.redirect_stdout(buf):
        try:
            apex_cli.main()
        except SystemExit as exc:  # typer exits 0 on success
            assert exc.code == 0, exc
    out = buf.getvalue()
    assert out.splitlines()[0].startswith("advisory:"), out


# -- RT-02 + RT-10: the timeout must reach the backend -----------------------

def test_execute_with_timeout_passes_timeout_to_backend() -> None:
    seen: dict = {}

    class RecordingSandbox:
        def execute(self, container_id, command, timeout_seconds=3600):
            seen["timeout_seconds"] = timeout_seconds

            from webpent.apex.sandbox import ExecOutcome

            return ExecOutcome(
                exit_code=0, stdout=b"", stderr=b"", duration_seconds=0.0,
                timed_out=False,
            )

    registry = ToolRegistry.load(REGISTRY_PATH)
    executor = ToolExecutor(registry)
    executor.execute_with_timeout(
        "httpx", ["httpx", "-u", "x"], RecordingSandbox(), timeout=7
    )
    assert seen["timeout_seconds"] == 7, "caller timeout was dropped"


def test_local_sandbox_uses_config_timeout(monkeypatch) -> None:
    seen: dict = {}

    def fake_run(*args, **kwargs):
        seen["timeout"] = kwargs.get("timeout")

        class R:
            returncode = 0
            stdout = b""
            stderr = b""

        return R()

    monkeypatch.setattr("subprocess.run", fake_run)
    sandbox = LocalSandbox(config=SandboxConfig(timeout_seconds=7))
    sandbox.execute("", ["true"])
    assert seen["timeout"] == 7, "SandboxConfig.timeout_seconds ignored"


def test_execute_unknown_tool_raises() -> None:
    registry = ToolRegistry.load(REGISTRY_PATH)

    class NullSandbox:
        def execute(self, container_id, command, timeout_seconds=3600):
            raise AssertionError("must not be reached")

    executor = ToolExecutor(registry)
    with pytest.raises(UnknownToolForExecutionError):
        executor.execute("definitely-not-a-tool", ["x"], NullSandbox())


# -- RT-03: the runs ledger must not lie -------------------------------------

def test_dry_run_writes_no_fabricated_metrics(tmp_path: Path) -> None:
    state = tmp_path / "state"
    chain_id = _build_chain(state)
    run = RUNNER.invoke(
        apex_app, ["chain", "run", chain_id, "--apex-dir", str(state)],
        env={"WEBPENT_APEX_WORKDIR": str(WORK)},
    )
    assert run.exit_code == 0, run.output
    line = _last_run_line(state)
    assert line["dry_run"] is True
    assert line["step_results"] == [], "dry-run must record no step results"
    assert line["measured_speedup"] is None
    assert line["completed"] == 0
    payload = json.loads(run.output.splitlines()[-1])
    assert payload["mode"] == "dry-run"
    assert all(s["executed"] is False for s in payload["steps"])


def test_execute_mode_records_honest_results(tmp_path: Path) -> None:
    state = tmp_path / "state"
    chain_id = _build_chain(state)
    run = RUNNER.invoke(
        apex_app,
        ["chain", "run", chain_id, "--execute", "--apex-dir", str(state)],
        env={"WEBPENT_APEX_WORKDIR": str(WORK)},
    )
    assert run.exit_code == 0, run.output
    line = _last_run_line(state)
    assert line["dry_run"] is False
    assert line["step_results"], "execute mode must record real step results"
    assert line["measured_speedup"] is None or line["measured_speedup"] >= 0.0
    # no tool binaries exist here: honest non-zero exits, no fabricated 0s
    assert all(r["exit_code"] != 0 for r in line["step_results"])


# -- RT-04: chain id must move when the config moves --------------------------

def test_chain_id_stable_for_same_inputs() -> None:
    registry = ToolRegistry.load(REGISTRY_PATH)
    a = ToolChainBuilder.load(CHAINS_PATH, registry).build("xss", "t.test")
    b = ToolChainBuilder.load(CHAINS_PATH, registry).build("xss", "t.test")
    assert a.chain_id == b.chain_id


def test_chain_id_changes_when_config_changes(tmp_path: Path) -> None:
    registry = ToolRegistry.load(REGISTRY_PATH)
    base = ToolChainBuilder.load(CHAINS_PATH, registry).build("xss", "t.test")
    modified = tmp_path / "chains.yaml"
    modified.write_text(
        CHAINS_PATH.read_text(encoding="utf-8") + "\n", encoding="utf-8"
    )
    other = ToolChainBuilder.load(modified, registry).build("xss", "t.test")
    assert other.chain_id != base.chain_id


# -- RT-05: skipping must reach the grandchildren -----------------------------

def test_grandchildren_scheduled_when_mid_node_fails() -> None:
    steps = [
        ChainStep(step_id="a", tool_id="a", capability="c", after=[]),
        ChainStep(step_id="b", tool_id="b", capability="c", after=["a"]),
        ChainStep(step_id="c", tool_id="c", capability="c", after=["b"]),
    ]
    chain = ToolChain(
        chain_id="rt5", hypothesis_type="x", target="t.test", steps=steps
    )

    def runner(step):
        if step.step_id == "b":
            return {"tool_id": step.tool_id, "exit_code": 1,
                    "stdout": "", "stderr": "boom", "findings": []}
        return {"tool_id": step.tool_id, "exit_code": 0,
                "stdout": "", "stderr": "", "findings": []}

    result = ParallelRunner().run(chain, runner)
    by_step = {r.step_id: r for r in result.step_results}
    assert by_step["a"].exit_code == 0
    assert by_step["b"].exit_code == 1
    assert by_step["c"].skipped, (
        "grandchild of a failed parent must be explicitly skipped, "
        f"got skipped={by_step['c'].skipped!r} exit={by_step['c'].exit_code!r}"
    )


# -- RT-06: local-only bind must not be spoofable -----------------------------

def test_local_only_rejects_spoofed_bind() -> None:
    registry = ToolRegistry.load(REGISTRY_PATH)
    builder = ToolChainBuilder.load(CHAINS_PATH, registry)
    with pytest.raises(ValueError):
        ApexMcpServer(builder=builder, token="t",
                      bind="127.0.0.1.evil.com:8080")
    server = ApexMcpServer(builder=builder, token="t", bind="127.0.0.1:9090")
    assert server.manifest()["server"]["local_only"] is True


# -- RT-07 + RT-08: learning ledger cap and ordering --------------------------

def test_tool_result_lines_capped(tmp_path: Path) -> None:
    learn = ApexLearning.load(tmp_path / "l.jsonl")
    for i in range(ApexLearning.MAX_OUTCOMES + 50):
        learn.record_tool_result(f"tool-{i}", success=True)
    assert len((tmp_path / "l.jsonl").read_text(
        encoding="utf-8").splitlines()) <= ApexLearning.MAX_OUTCOMES


def test_ledger_preserves_recording_order(tmp_path: Path) -> None:
    learn = ApexLearning.load(tmp_path / "l.jsonl")
    learn.record_tool_result("first", success=True)
    chain = ToolChain(
        chain_id="chain-xss", hypothesis_type="xss", target="t.test",
        steps=[ChainStep(tool_id="gau", capability="c", step_id="gau")],
    )
    run = ChainRunResult(
        chain_id="chain-xss",
        step_results=[StepResult(step_id="gau", tool_id="gau", exit_code=0)],
        total_duration_seconds=1.0,
        sum_step_durations=1.0,
    )
    learn.record_chain_outcome(chain, run, target="t.test")
    learn.record_tool_result("last", success=True)
    lines = (tmp_path / "l.jsonl").read_text(encoding="utf-8").splitlines()
    kinds = [json.loads(line).get("kind") for line in lines]
    assert kinds == ["tool_result", "outcome", "tool_result"], (
        f"recording order distorted: {kinds}"
    )


# -- RT-09: dashboard honors max_recent_chains --------------------------------

def test_dashboard_honors_max_recent_chains(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEBPENT_APEX_WORKDIR", str(WORK))
    state = tmp_path / "state"
    for hyp in ("xss", "sqli"):
        chain_id = _build_chain(state, hyp=hyp)
        res = RUNNER.invoke(
            apex_app, ["chain", "run", chain_id, "--apex-dir", str(state)]
        )
        assert res.exit_code == 0, res.output
    ui = tmp_path / "ui.yaml"
    ui.write_text(
        "dashboard:\n  max_recent_chains: 1\n  max_findings: 20\n",
        encoding="utf-8",
    )
    import webpent.cli.apex as apex_cli

    monkeypatch.setattr(apex_cli, "_config_dir", lambda: tmp_path)
    result = RUNNER.invoke(apex_app, ["dashboard", "--apex-dir", str(state)])
    assert result.exit_code == 0, result.output
    section = result.output.split("Chains")[1].split("Tool usage")[0]
    rows = [row for row in section.splitlines() if row.strip().startswith("-")]
    assert len(rows) == 1, f"max_recent_chains ignored: {rows}"


# -- RT-11: clean error for unknown tool install ------------------------------

def test_tools_install_unknown_id_clean_error(tmp_path: Path) -> None:
    result = RUNNER.invoke(
        apex_app,
        ["tools", "install", "no-such-tool", "--apex-dir", str(tmp_path)],
        env={"WEBPENT_APEX_WORKDIR": str(WORK)},
    )
    assert result.exit_code == 2, (
        f"expected clean typer error, got exit {result.exit_code}: "
        f"{result.output[:200]} exception={result.exception!r}"
    )
