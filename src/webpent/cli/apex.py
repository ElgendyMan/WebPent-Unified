"""The Apex Predator — CLI (v87, U-APEX-11).

House style mirrors cli/dojo.py: a typer sub-app, the PREAMBLE_LINE printed
first on every command, one capped audit line appended per invocation, and
advisory-only behavior throughout (APEX-L-9): `tools install` prints the
vetted install command and executes nothing, `chain run` defaults to a
dry-run plan report, and nothing here opens sockets.

State lives under --apex-dir (default .apex-state): audit.jsonl (capped),
chains/<id>.json (built plans), runs.jsonl, findings.jsonl, learning.jsonl.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import typer
import yaml

from webpent.apex.dashboard import DashboardSnapshot, render
from webpent.apex.result_fusion import ExecResult, ResultFusion
from webpent.apex.tool_chain_builder import ToolChainBuilder
from webpent.apex.tool_registry import ToolRegistry

app = typer.Typer(help="The Apex Predator — advisory surface (v87)")
apex_app = app
tools_app = typer.Typer(help="registry tools")
chain_app = typer.Typer(help="chain build/run")
findings_app = typer.Typer(help="fused findings")
mcp_app = typer.Typer(help="MCP surface")
app.add_typer(tools_app, name="tools")
app.add_typer(chain_app, name="chain")
app.add_typer(findings_app, name="findings")
app.add_typer(mcp_app, name="mcp")

PREAMBLE_LINE = (
    "advisory: every apex command proposes and reports; nothing runs "
    "without the operator's explicit approval and scope."
)

AUDIT_CAP = 1000
DEFAULT_STEP_TIMEOUT_SECONDS = 900



# -- shared helpers -----------------------------------------------------------

def _workdir() -> Path:
    return Path(os.environ.get("WEBPENT_APEX_WORKDIR", os.getcwd()))


def _apex_dir(value: str | None) -> Path:
    return Path(value) if value else Path(".apex-state")


def _config_dir() -> Path:
    return _workdir() / "config" / "apex"


def _emit(
    apex_dir: Path, command: str, payload: dict | None = None,
    human_lines: list[str] | None = None,
) -> None:
    """Print preamble, human lines, then the single-line JSON payload last;
    append one capped audit line."""
    typer.echo(PREAMBLE_LINE)
    for line in human_lines or []:
        typer.echo(line)
    if payload is not None:
        typer.echo(json.dumps(payload, sort_keys=False, separators=(",", ":")))
    _audit(apex_dir, command)


def _audit(apex_dir: Path, command: str) -> None:
    path = apex_dir / "audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = path.read_text().splitlines() if path.is_file() else []
    lines.append(
        json.dumps(
            {"command": command, "ts": round(time.time(), 3)}, sort_keys=True
        )
    )
    if len(lines) > AUDIT_CAP:
        lines = lines[-AUDIT_CAP:]
    path.write_text("\n".join(lines) + "\n")


def _registry() -> ToolRegistry:
    return ToolRegistry.load(_config_dir() / "tools.yaml")


def _builder() -> ToolChainBuilder:
    return ToolChainBuilder.load(_config_dir() / "chains.yaml", _registry())


def _ui_config() -> dict:
    path = _config_dir() / "ui.yaml"
    if path.is_file():
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    return {}


# -- status ---------------------------------------------------------------------

@app.command("status")
def status(
    apex_dir: str = typer.Option(".apex-state", help="state directory"),
) -> None:
    """Current apex status from recorded state (idle/running, counts)."""
    state = _load_status(Path(apex_dir))
    _emit(Path(apex_dir), "status", payload=state)


def _load_status(apex_path: Path) -> dict:
    runs_file = apex_path / "runs.jsonl"
    runs = _read_jsonl(runs_file) if runs_file.is_file() else []
    learning_file = apex_path / "learning.jsonl"
    learning = _read_jsonl(learning_file) if learning_file.is_file() else []
    # RT-20: no fabricated "state" field — a constant "idle" with no
    # evidence source was forged state. The status declares honestly
    # that apex is advisory with no persistent daemon behind it.
    return {
        "daemon": "none",
        "daemon_note": (
            "apex is advisory with no persistent daemon process; these "
            "counters come from the recorded ledgers only"
        ),
        "chains_run": len(runs),
        "learning_events": len(learning),
        "advisory_note": PREAMBLE_LINE,
    }


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


# -- tools -----------------------------------------------------------------------

@tools_app.command("list")
def tools_list(
    category: str = typer.Option(None, help="filter by category"),
    apex_dir: str = typer.Option(".apex-state", help="state directory"),
) -> None:
    """List registered vetted tools (APEX-L-2)."""
    registry = _registry()
    specs = registry.list_tools(category=category)
    rows = [
        f"  {spec.id:14s} {spec.category:12s} speed={spec.speed:6s} "
        f"stealth={spec.stealth:6s} installed={registry.verify_installed(spec.id)}"
        for spec in specs
    ]
    _emit(
        Path(apex_dir), "tools list",
        payload={"count": len(rows), "tools": [s.id for s in specs]},
        human_lines=rows,
    )


@tools_app.command("install")
def tools_install(
    tool_id: str = typer.Argument(..., help="registered tool id"),
    apex_dir: str = typer.Option(".apex-state", help="state directory"),
) -> None:
    """Show the vetted install command. ADVICE ONLY — nothing executes."""
    registry = _registry()
    if not registry.has(tool_id):  # RT-11: no raw traceback, a clean error
        raise typer.BadParameter(
            f"{tool_id!r} is not a vetted tool id; see `tools list`"
        )
    spec = registry.get(tool_id)
    _emit(
        Path(apex_dir), f"tools install {tool_id}",
        payload={
            "tool_id": spec.id,
            "install_command": spec.install_command,
            "executed": False,
            "advisory": True,
        },
        human_lines=["  run this yourself, in the sandbox you trust:"],
    )


# -- chains -------------------------------------------------------------------------

@chain_app.command("build")
def chain_build(
    hypothesis: str = typer.Option(..., help="hypothesis type"),
    target: str = typer.Option(..., help="in-scope target"),
    apex_dir: str = typer.Option(".apex-state", help="state directory"),
) -> None:
    """Build a deterministic chain plan and save it under chains/."""
    chain = _builder().build(hypothesis, target)
    chains_dir = Path(apex_dir) / "chains"
    chains_dir.mkdir(parents=True, exist_ok=True)
    (chains_dir / f"{chain.chain_id}.json").write_text(
        json.dumps(chain.to_dict(), indent=2), encoding="utf-8"
    )
    _emit(Path(apex_dir), "chain build", payload=chain.to_dict())


@chain_app.command("run")
def chain_run(
    chain_id: str = typer.Argument(..., help="chain id from `chain build`"),
    execute: bool = typer.Option(
        False, "--execute", help="actually run tools (needs installed binaries)"
    ),
    apex_dir: str = typer.Option(".apex-state", help="state directory"),
) -> None:
    """Run a built chain plan. Default is a dry-run plan report."""
    plan_path = Path(apex_dir) / "chains" / f"{chain_id}.json"
    if not plan_path.is_file():
        raise typer.BadParameter(f"no saved chain plan for {chain_id}")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    steps = [
        {
            "step_id": s["step_id"],
            "tool_id": s["tool_id"],
            "after": s.get("after", []),
            "executed": False,
        }
        for s in plan["steps"]
    ]
    payload = {
        "chain_id": chain_id,
        "mode": "dry-run" if not execute else "execute",
        "steps": steps,
        "advisory": True,
    }
    # RT-03: the runs ledger never lies. A dry-run records a plan report
    # (no step results, no "measured" speedup); --execute records the
    # real exit codes the sandbox returned.
    if execute:
        from webpent.apex.executor import ToolExecutor
        from webpent.apex.learning import ApexLearning
        from webpent.apex.parallel_runner import ParallelRunner
        from webpent.apex.sandbox import LocalSandbox, SandboxConfig, ScopeGuard
        from webpent.apex.tool_chain_builder import ChainStep, ToolChain

        registry = _registry()
        executor = ToolExecutor(registry)
        sandbox = LocalSandbox(
            config=SandboxConfig(timeout_seconds=DEFAULT_STEP_TIMEOUT_SECONDS)
        )
        target = plan.get("target", "")
        guard = ScopeGuard(allowed_hosts={target} if target else set())
        chain = ToolChain(
            chain_id=chain_id,
            hypothesis_type=plan.get("hypothesis_type", "-"),
            target=target or "-",
            steps=[
                ChainStep(
                    tool_id=s["tool_id"],
                    capability=s.get("capability", ""),
                    after=list(s.get("after", [])),
                    step_id=s["step_id"],
                )
                for s in plan["steps"]
            ],
        )

        def runner(step: ChainStep) -> dict:
            # RT-15: the step's command carries the in-scope target —
            # never a bare binary invocation.
            try:
                executed = executor.execute(
                    step.tool_id, [target], sandbox, scope=guard
                )
            except Exception as exc:  # noqa: BLE001 — honest failure only
                return {"exit_code": 127, "stderr": type(exc).__name__}
            stderr = (
                executed.stderr.decode("utf-8", errors="replace")
                if isinstance(executed.stderr, bytes)
                else str(executed.stderr)
            )
            return {
                "exit_code": executed.exit_code,
                "stderr": stderr,
                "command": executed.command,
            }

        # RT-15: dependency-aware execution (ParallelRunner carries the
        # RT-05 transitive skip), real measured wall clock, skips counted
        # from results — the ledger never reports fixed constants.
        run = ParallelRunner().run(chain, runner)
        step_results = []
        for r in run.step_results:
            row = {
                "step_id": r.step_id,
                "tool_id": r.tool_id,
                "exit_code": r.exit_code,
                "skipped": r.skipped,
            }
            command = (
                r.output.get("command")
                if isinstance(r.output, dict) and not r.skipped
                else None
            )
            if command:
                row["command"] = list(command)
            if r.error:
                row["error"] = r.error[:200]
            step_results.append(row)
        ledger = {
            "chain_id": chain_id,
            "hypothesis_type": plan.get("hypothesis_type", "-"),
            "target": plan.get("target", "-"),
            "mode": "execute",
            "dry_run": False,
            "step_results": step_results,
            "completed": run.completed,
            "failed": run.failed,
            "skipped": run.skipped,
            "measured_speedup": round(run.measured_speedup, 3),
            "total_duration_seconds": round(run.total_duration_seconds, 4),
        }
        # RT-15: the learning loop is fed from the CLI too — one chain
        # outcome, and per-tool results for steps that actually ran
        # (a skipped tool never ran, so it records neither success nor
        # failure).
        learner = ApexLearning(Path(apex_dir) / "learning.jsonl")
        learner.record_chain_outcome(chain, run, target)
        for r in run.step_results:
            if not r.skipped:
                learner.record_tool_result(r.tool_id, r.exit_code == 0)
        for s, r in zip(steps, run.step_results, strict=True):
            s["executed"] = not r.skipped
    else:
        ledger = {
            "chain_id": chain_id,
            "hypothesis_type": plan.get("hypothesis_type", "-"),
            "target": plan.get("target", "-"),
            "mode": "dry-run",
            "dry_run": True,
            "step_results": [],
            "completed": 0,
            "failed": 0,
            "skipped": 0,
            "measured_speedup": None,
            "total_duration_seconds": 0.0,
        }
    runs_file = Path(apex_dir) / "runs.jsonl"
    runs_file.parent.mkdir(parents=True, exist_ok=True)
    with runs_file.open("a") as fh:
        fh.write(json.dumps(ledger) + "\n")
    _emit(Path(apex_dir), f"chain run {chain_id}", payload=payload)


# -- findings ---------------------------------------------------------------------------

@findings_app.command("fused")
def findings_fused(
    apex_dir: str = typer.Option(".apex-state", help="state directory"),
) -> None:
    """Fuse recorded per-tool findings into one picture (APEX-L-6)."""
    findings_file = Path(apex_dir) / "findings.jsonl"
    results: list[ExecResult] = []
    if findings_file.is_file():

        for row in _read_jsonl(findings_file):
            evidence_rows = row.get("findings", [])
            from webpent.apex.result_fusion import Evidence

            evidence = [
                Evidence(
                    vuln_class=e["vuln_class"],
                    endpoint=e["endpoint"],
                    severity=e["severity"],
                    confidence=float(e["confidence"]),
                    detail=e.get("detail", ""),
                )
                for e in evidence_rows
            ]
            results.append(ExecResult(tool_id=row["tool_id"], findings=evidence))
    fused = ResultFusion().fuse(results)
    _emit(
        Path(apex_dir), "findings fused",
        payload={
            "count": len(fused),
            "findings": [f.to_dict() for f in fused],
        },
    )


# -- dashboard ------------------------------------------------------------------------------

@app.command("dashboard")
def dashboard(
    apex_dir: str = typer.Option(".apex-state", help="state directory"),
) -> None:
    """Render the operator dashboard (all five sections)."""
    cfg = _ui_config()
    snapshot = _build_dashboard_snapshot(Path(apex_dir), cfg)
    _emit(Path(apex_dir), "dashboard", human_lines=[render(snapshot)])


def _build_dashboard_snapshot(apex_path: Path, cfg: dict) -> DashboardSnapshot:
    resources_cfg = cfg.get("resources", {})
    runs_file = apex_path / "runs.jsonl"
    runs = _read_jsonl(runs_file) if runs_file.is_file() else []
    max_recent = int(
        cfg.get("dashboard", {}).get("max_recent_chains", len(runs) or 0)
        or len(runs)
    )
    chains = [
        {
            "chain_id": run["chain_id"],
            "hypothesis_type": run.get("hypothesis_type", "-"),
            "target": run.get("target", "-"),
            "steps": run.get("steps", len(run.get("step_results", []))),
            "completed": run.get("completed", 0),
            "failed": run.get("failed", 0),
            "skipped": run.get("skipped", 0),
        }
        for run in runs
    ]
    chains = chains[-max_recent:] if max_recent > 0 else []  # RT-09
    usage: dict[str, dict] = {}
    for run in runs:
        for step in run.get("step_results", []):
            tool_id = step.get("tool_id", "?")
            row = usage.setdefault(
                tool_id, {"tool_id": tool_id, "runs": 0, "last_exit_code": 0}
            )
            row["runs"] += 1
            row["last_exit_code"] = step.get("exit_code", 0)
    speedups = [
        float(run["measured_speedup"])
        for run in runs
        if run.get("measured_speedup") is not None
    ]
    findings_file = apex_path / "findings.jsonl"
    findings: list[dict] = []
    if findings_file.is_file():
        rows = _read_jsonl(findings_file)
        exec_results = []
        from webpent.apex.result_fusion import Evidence

        for row in rows:
            evidence = [
                Evidence(
                    vuln_class=e["vuln_class"],
                    endpoint=e["endpoint"],
                    severity=e["severity"],
                    confidence=float(e["confidence"]),
                    detail=e.get("detail", ""),
                )
                for e in row.get("findings", [])
            ]
            exec_results.append(
                ExecResult(tool_id=row["tool_id"], findings=evidence)
            )
        findings = [f.to_dict() for f in ResultFusion().fuse(exec_results)]
    audit_file = apex_path / "audit.jsonl"
    audit_lines = (
        len(audit_file.read_text().splitlines()) if audit_file.is_file() else 0
    )
    return DashboardSnapshot(
        chains=chains,
        tool_usage=list(usage.values()),
        speed={
            "chains_run": len(runs),
            "measured_speedup_max": max(speedups) if speedups else None,
            "total_duration_seconds": sum(
                run.get("total_duration_seconds", 0.0) for run in runs
            ),
        },
        findings=findings,
        resources={
            "sandbox_mode": resources_cfg.get("sandbox_mode", "local"),
            "docker_daemon": resources_cfg.get(
                "docker_daemon", "blocked in this environment"
            ),
            "audit_lines": audit_lines,
            "cache_entries": 0,
        },
    )


# -- mcp -----------------------------------------------------------------------------------

@mcp_app.command("serve")
def mcp_serve(
    bind: str = typer.Option("127.0.0.1:0", help="declared bind address"),
    apex_dir: str = typer.Option(".apex-state", help="state directory"),
) -> None:
    """Print the MCP manifest and binding declaration. No socket is opened."""
    from webpent.apex.mcp_server import ApexMcpServer

    server = ApexMcpServer(
        builder=_builder(), token="display-only", bind=bind
    )
    manifest = server.manifest()
    names = [tool["name"] for tool in manifest["tools"]]
    _emit(
        Path(apex_dir), "mcp serve",
        payload={
            "bind": manifest["server"]["bind"],
            "local_only": manifest["server"]["local_only"],
            "transport_note": manifest["server"]["transport_note"],
            "tools": names,
        },
    )


# -- learn --------------------------------------------------------------------------------

@app.command("learn")
def learn(
    apex_dir: str = typer.Option(".apex-state", help="state directory"),
) -> None:
    """Summarize what the learning loop has recorded so far (APEX-L-7)."""
    learning_file = Path(apex_dir) / "learning.jsonl"
    events = _read_jsonl(learning_file) if learning_file.is_file() else []
    lessons = [e.get("lesson") for e in events if e.get("lesson")]
    _emit(
        Path(apex_dir), "learn",
        payload={
            "events": len(events),
            "last_lesson": lessons[-1] if lessons else None,
            "advisory": True,
        },
    )


def main() -> None:
    """RT-01: `python -m webpent.cli.apex` used to exit 0 silently."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
