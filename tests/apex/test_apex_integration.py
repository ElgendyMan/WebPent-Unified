"""Apex integration (v87): the whole predator, laws and all.

Full cycle under a socket AND subprocess ban: decision → chain → parallel
run → fusion → learning → dashboard. The step runner is injected, so no
real tool ever executes; the patch proves no apex code path opens a
socket or spawns a process in tests (APEX-L-4/L-8). L-9 advisory proof:
no apex module imports network or send primitives. State isolation: every
CLI invocation writes only under its own --apex-dir.
"""

from __future__ import annotations

import ast
import json
import socket
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from webpent.apex.dashboard import DashboardSnapshot, render
from webpent.apex.learning import ApexLearning
from webpent.apex.orchestrator import AdaptiveOrchestrator, BrainDecision, Target
from webpent.apex.parallel_runner import ParallelRunner
from webpent.apex.result_fusion import Evidence, ExecResult, ResultFusion
from webpent.apex.tool_chain_builder import ToolChainBuilder
from webpent.apex.tool_registry import ToolRegistry
from webpent.cli.apex import apex_app

WORK = Path(__file__).resolve().parents[2]
REGISTRY_PATH = WORK / "config" / "apex" / "tools.yaml"
CHAINS_PATH = WORK / "config" / "apex" / "chains.yaml"
RUNNER = CliRunner()


@pytest.fixture()
def builder() -> ToolChainBuilder:
    return ToolChainBuilder.load(
        CHAINS_PATH, ToolRegistry.load(REGISTRY_PATH)
    )


def _fake_runner(step):
    return {
        "tool_id": step.tool_id,
        "exit_code": 0,
        "findings": [
            {
                "vuln_class": "xss",
                "endpoint": "/search",
                "severity": "high",
                "confidence": 0.9,
                "detail": f"reflected payload at {step.tool_id}",
            }
        ],
    }


class ForbiddenError(Exception):
    pass


def _ban_sockets_and_processes():
    def _no_socket(*args, **kwargs):
        raise ForbiddenError("apex must never open a socket in tests")

    def _no_process(*args, **kwargs):
        raise ForbiddenError("apex must never spawn a process in tests")

    original_socket = socket.socket
    socket.socket = _no_socket
    originals = (
        subprocess.Popen,
        subprocess.run,
        subprocess.call,
        subprocess.check_call,
        subprocess.check_output,
    )
    subprocess.Popen = _no_process
    subprocess.run = _no_process
    subprocess.call = _no_process
    subprocess.check_call = _no_process
    subprocess.check_output = _no_process
    return original_socket, originals


def _restore(original_socket, originals) -> None:
    socket.socket = original_socket
    (
        subprocess.Popen,
        subprocess.run,
        subprocess.call,
        subprocess.check_call,
        subprocess.check_output,
    ) = originals


def test_full_cycle_zero_sockets_zero_processes(
    builder, tmp_path: Path
) -> None:
    """decision → chain → parallel run → fusion → learning → dashboard,
    with every socket and subprocess forbidden."""
    original_socket, originals = _ban_sockets_and_processes()
    try:
        orch = AdaptiveOrchestrator(
            builder=builder, runner_factory=ParallelRunner
        )
        decision = BrainDecision(
            decision_id="int-001",
            hypothesis_type="xss",
            target="target.test",
            rationale="integration cycle",
        )
        result = orch.orchestrate(
            decision,
            Target(host="target.test", allowed_scopes=["target.test"]),
            runner=_fake_runner,
        )
        assert result.chain.hypothesis_type == "xss"
        assert result.fused_outputs, "cycle must fuse per-tool outputs"

        # fusion leg: per-tool findings from the run become one picture
        exec_results = [
            ExecResult(
                tool_id=r.tool_id,
                findings=[
                    Evidence(
                        vuln_class=f["vuln_class"],
                        endpoint=f["endpoint"],
                        severity=f["severity"],
                        confidence=float(f["confidence"]),
                        detail=f.get("detail", ""),
                    )
                    for f in r.output.get("findings", [])
                ],
            )
            for r in result.run.step_results
            if r.output.get("findings")
        ]
        fused = ResultFusion().fuse(exec_results)
        assert fused and fused[0].vuln_class == "xss"
        assert fused[0].consensus == pytest.approx(1.0)  # both tools agree

        # learning leg: the outcome lands in the ledger (capped, redacted)
        learn = ApexLearning.load(tmp_path / "learning.jsonl")
        learn.record_chain_outcome(
            result.chain, result.run, target="target.test"
        )
        # RT-18: a recommendation needs MIN_SAMPLES evidence, so the
        # ledger is filled to the bar before querying the best chain.
        for _ in range(ApexLearning.MIN_SAMPLES - 1):
            learn.record_chain_outcome(
                result.chain, result.run, target="target.test"
            )
        assert learn.pattern_count() == 1
        best = learn.get_best_chain_for("xss")
        assert best is not None and best.chain_id == result.chain.chain_id

        # dashboard leg: the recorded state renders all five sections
        snapshot = DashboardSnapshot(
            chains=[
                {
                    "chain_id": result.chain.chain_id,
                    "hypothesis_type": result.chain.hypothesis_type,
                    "target": "redacted",
                    "steps": len(result.chain.steps),
                    "completed": result.run.completed,
                    "failed": result.run.failed,
                    "skipped": result.run.skipped,
                }
            ],
            tool_usage=[
                {"tool_id": s.tool_id, "runs": 1, "last_exit_code": s.exit_code}
                for s in result.run.step_results
            ],
            speed={"chains_run": 1, "measured_speedup_max": 1.0,
                   "total_duration_seconds": result.run.total_duration_seconds},
            findings=[f.to_dict() for f in fused],
            resources={"sandbox_mode": "local", "docker_daemon": "blocked",
                       "audit_lines": 0, "cache_entries": 0},
        )
        text = render(snapshot)
        for section in ("Chains", "Tool usage", "Speed", "Findings",
                        "Resources"):
            assert section in text
    finally:
        _restore(original_socket, originals)


def test_no_apex_module_imports_network_primitives() -> None:
    """APEX-L-9: the apex package declares nothing that dials out."""
    forbidden = {
        "socket", "ssl", "urllib", "urllib.request", "urllib.parse",
        "http", "http.client", "requests", "httpx", "aiohttp", "ftplib",
        "smtplib", "telnetlib", "asyncio", "xmlrpc", "selenium",
    }
    offenders: list[str] = []
    for path in sorted((WORK / "src" / "webpent" / "apex").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if name.split(".")[0] in {f.split(".")[0] for f in forbidden}:
                    offenders.append(f"{path.name}: {name}")
    assert not offenders, f"network primitives imported in apex: {offenders}"


def test_cli_state_isolation_and_dry_run(tmp_path: Path) -> None:
    """Every CLI invocation writes only under its own --apex-dir, and
    chain run stays a dry-run plan (APEX-L-9)."""
    dir_a = tmp_path / "state-a"
    dir_b = tmp_path / "state-b"
    env = {"WEBPENT_APEX_WORKDIR": str(WORK)}

    def _invoke(args: list[str], state: Path):
        return RUNNER.invoke(
            apex_app, args + ["--apex-dir", str(state)], env=env
        )

    build = _invoke(
        ["chain", "build", "--hypothesis", "xss", "--target", "t.test"], dir_a
    )
    assert build.exit_code == 0, build.output
    chain_id = json.loads(build.output.splitlines()[-1])["chain_id"]
    run = _invoke(["chain", "run", chain_id], dir_a)
    assert run.exit_code == 0, run.output
    assert json.loads(run.output.splitlines()[-1])["mode"] == "dry-run"

    # state-a holds the record; state-b knows nothing of it
    assert (dir_a / "chains" / f"{chain_id}.json").is_file()
    assert (dir_a / "runs.jsonl").is_file()
    assert not (dir_b / "runs.jsonl").exists()
    status_b = _invoke(["status"], dir_b)
    payload = json.loads(status_b.output.splitlines()[-1])
    assert payload["chains_run"] == 0, "state must not leak across apex dirs"
    status_a = _invoke(["status"], dir_a)
    assert json.loads(status_a.output.splitlines()[-1])["chains_run"] == 1


def test_cli_full_flow_under_socket_ban(tmp_path: Path) -> None:
    """The whole CLI surface works with sockets forbidden: advisory only."""
    original_socket, originals = _ban_sockets_and_processes()
    try:
        state = tmp_path / "apex-state"
        env = {"WEBPENT_APEX_WORKDIR": str(WORK)}
        for argv in (
            ["status"],
            ["tools", "list"],
            ["tools", "install", "httpx"],
            ["chain", "build", "--hypothesis", "xss", "--target", "t.test"],
            ["findings", "fused"],
            ["dashboard"],
            ["mcp", "serve"],
            ["learn"],
        ):
            result = RUNNER.invoke(
                apex_app, argv + ["--apex-dir", str(state)], env=env
            )
            assert result.exit_code == 0, f"{argv}: {result.output}"
            assert result.output.splitlines()[0].startswith("advisory:")
    finally:
        _restore(original_socket, originals)
