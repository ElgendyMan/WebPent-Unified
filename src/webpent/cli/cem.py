"""CEM operator commands (v83, U-CEM-12).

``webpent cem`` is a file-state console, not a daemon launcher: every
command reads or writes local JSON state and returns. The external
scheduler (cron) is what calls ``run_cem_cycle``; these commands only
register targets, pause and resume them, engage the kill switch, and
render status, digest and findings. Every command is appended to a
capped, redacted JSON-lines audit log.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from webpent.autonomous.cem.cycle import load_cem_state, save_cem_state
from webpent.autonomous.cem.digest import build_digest, write_digest
from webpent.autonomous.cem.regression_watch import RegressionWatch
from webpent.autonomous.cem.scheduler import KillSwitch, PoliteScheduler
from webpent.autonomous.hunt_contracts import redact

StateDir = Annotated[Path | None, typer.Option("--state-dir", help="CEM state directory.")]

cem_app = typer.Typer(
    name="cem",
    help="Continuous Engagement Mode: operator controls (file state only, no daemon).",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)

AUDIT_LIMIT = 1000
MAX_TEXT = 200


def _state_dir(explicit: Path | None) -> Path:
    if explicit is not None:
        return Path(explicit)
    env = os.environ.get("WEBPENT_CEM_DIR")
    if env:
        return Path(env)
    return Path.home() / ".webpent" / "cem"


def _paths(state_dir: Path) -> dict[str, Path]:
    return {
        "state": state_dir / "cem_state.json",
        "scheduler": state_dir / "scheduler.json",
        "kill": state_dir / "scheduler_kill.json",
        "regression": state_dir / "regression.json",
        "audit": state_dir / "audit_log.jsonl",
        "digest_dir": state_dir / "digest",
    }


def _audit(paths: dict[str, Path], *, command: str, **fields: object) -> None:
    """Append one redacted JSON line, then cap the log to the last AUDIT_LIMIT lines."""
    entry = {
        "ts": round(time.time(), 3),
        "command": redact(command)[:40],
        **{key: redact(str(value or ""))[:MAX_TEXT] for key, value in fields.items()},
    }
    try:
        path = paths["audit"]
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        lines = [line for line in lines if line.strip()]
        lines.append(json.dumps(entry, ensure_ascii=False))
        keep = lines[-AUDIT_LIMIT:]
        fd, tmp_name = tempfile.mkstemp(dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("\n".join(keep) + "\n")
            os.replace(tmp_name, path)
        except BaseException:
            with suppress(OSError):
                os.unlink(tmp_name)
            raise
    except OSError as exc:
        err_console.print(f"[yellow]audit log write failed: {exc}[/yellow]")


def _save_state(state: dict, paths: dict[str, Path]) -> None:
    save_cem_state(state, paths["state"])


@cem_app.command("start")
def start(
    target: str = typer.Argument(..., help="Target id to register for observation."),
    state_dir: StateDir = None,
) -> None:
    """Register a target with the engagement (no cycle runs; cron does that)."""
    paths = _paths(_state_dir(state_dir))
    state = load_cem_state(paths["state"])
    target_id = redact(target.strip())[:120]
    if not target_id:
        err_console.print("[red]empty target id.[/red]")
        raise typer.Exit(1)
    state["targets"][target_id] = {"enabled": True, "paused": False}
    _save_state(state, paths)
    _audit(paths, command="start", target=target_id)
    console.print(f"[green]registered {target_id}[/green] — total targets: {len(state['targets'])}")


@cem_app.command("pause")
def pause(
    target: str | None = typer.Argument(None, help="Target to pause (default: all)."),
    state_dir: StateDir = None,
) -> None:
    """Pause one target or the whole engagement for the external scheduler."""
    paths = _paths(_state_dir(state_dir))
    state = load_cem_state(paths["state"])
    changed = _set_paused(state, target, True)
    _save_state(state, paths)
    _audit(paths, command="pause", target=redact(target or "*")[:120], changed=str(changed))
    console.print(f"paused {changed} target(s)")


@cem_app.command("resume")
def resume(
    target: str | None = typer.Argument(None, help="Target to resume (default: all)."),
    clear_kill_switch: bool = typer.Option(
        False, "--clear-kill-switch",
        help="Explicitly disengage an engaged kill switch. Never happens silently.",
    ),
    state_dir: StateDir = None,
) -> None:
    """Resume targets. Disengages the kill switch ONLY with --clear-kill-switch."""
    paths = _paths(_state_dir(state_dir))
    state = load_cem_state(paths["state"])
    changed = _set_paused(state, target, False)
    _save_state(state, paths)
    kill = KillSwitch(paths["kill"])
    disengaged = False
    if clear_kill_switch and kill.engaged():
        kill.disengage(now=time.time())
        disengaged = True
    _audit(paths, command="resume", target=redact(target or "*")[:120],
           changed=str(changed), kill_disengaged=str(disengaged))
    suffix = ", kill switch disengaged" if disengaged else ""
    if clear_kill_switch and not kill.engaged() and not disengaged:
        suffix = ", kill switch already clear"
    console.print(f"resumed {changed} target(s){suffix}")


def _set_paused(state: dict, target: str | None, paused: bool) -> int:
    target_id = redact(str(target or "").strip())[:120]
    if target_id:
        if target_id in state["targets"]:
            state["targets"][target_id]["paused"] = paused
            return 1
        return 0
    for meta in state["targets"].values():
        if isinstance(meta, dict):
            meta["paused"] = paused
    return len(state["targets"])


@cem_app.command("kill")
def kill(
    reason: str = typer.Argument(..., help="Why the engagement is being stopped."),
    state_dir: StateDir = None,
) -> None:
    """Engage the kill switch: the very next cycle refuses everything."""
    paths = _paths(_state_dir(state_dir))
    switch = KillSwitch(paths["kill"])
    switch.engage(reason=redact(reason)[:MAX_TEXT], now=time.time())
    _audit(paths, command="kill", reason=redact(reason)[:MAX_TEXT])
    console.print("[red]kill switch ENGAGED[/red] — every cycle will refuse until resumed.")


@cem_app.command("status")
def status(
    state_dir: StateDir = None,
) -> None:
    """Show bounded engagement state: targets, cycles, budget, kill switch."""
    paths = _paths(_state_dir(state_dir))
    state = load_cem_state(paths["state"])
    now = time.time()
    scheduler = PoliteScheduler(paths["scheduler"])
    kill = KillSwitch(paths["kill"])
    sched_status = scheduler.status(now)
    paused = sum(1 for meta in state["targets"].values()
                 if isinstance(meta, dict) and meta.get("paused"))
    console.print(f"cycle_count: {state.get('cycle_count', 0)}")
    console.print(f"targets: {len(state['targets'])} ({paused} paused)")
    console.print(f"kill_switch: {'ENGAGED' if kill.engaged() else 'disengaged'}")
    console.print(f"active_hours: {sched_status.get('active_hours', '?')}")
    console.print(
        f"spend_today: {sched_status.get('spent_today', 0)}/{sched_status.get('daily_cap', '?')}"
    )
    console.print(f"last_cycle: {state.get('last_cycle_ts') or 'never'}")
    _audit(paths, command="status")


@cem_app.command("digest")
def digest(
    state_dir: StateDir = None,
) -> None:
    """Write today's digest (Markdown + JSON) into the state directory."""
    paths = _paths(_state_dir(state_dir))
    now = time.time()
    scheduler = PoliteScheduler(paths["scheduler"])
    watch = RegressionWatch(paths["regression"])
    built = build_digest(
        now=now,
        cem_state=load_cem_state(paths["state"]),
        scheduler_status=scheduler.status(now),
        regression_status=watch.status(),
        regressed=watch.regressed(),
        drift_alerts=[],
    )
    written = write_digest(built, directory=paths["digest_dir"])
    _audit(paths, command="digest", files=str(len(written)))
    for name in sorted(written):
        console.print(f"written: {written[name]}")


@cem_app.command("findings")
def findings(
    state_dir: StateDir = None,
) -> None:
    """Show regression-watch status and regressed findings (advisory)."""
    paths = _paths(_state_dir(state_dir))
    watch = RegressionWatch(paths["regression"])
    counts = watch.status()
    console.print(f"active: {counts.get('active', 0)} · fixed: {counts.get('fixed', 0)} · "
                  f"regressed: {counts.get('regressed', 0)} ·"
                  f"deferred: {counts.get('deferred', 0)}")
    for finding in watch.regressed()[:10]:
        console.print(f"- {redact(str(finding.get('finding_id') or ''))[:60]} "
                      f"({redact(str(finding.get('target_id') or ''))[:60]})")
    _audit(paths, command="findings")


__all__ = ["cem_app"]
