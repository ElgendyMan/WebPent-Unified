"""Emulator CLI — a thin wrapper around the Docker range (U-EMU-5).

The CLI never talks to real targets: it only drives the local Docker
compose stack and reads the shared logs. Every command fails cleanly
when Docker is unavailable.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import click

EMU_DIR = Path(__file__).resolve().parent
LOG_DIR = EMU_DIR / "monitoring" / "nginx-logs"

TARGETS = [
    ("juice-shop", "http://localhost:3000", "vulnerable app (open)"),
    ("dvwa", "http://localhost:8080", "vulnerable app (admin/password)"),
    ("custom-api", "http://localhost:9000", "custom training API"),
    ("waf", "http://localhost:80", "juice-shop behind ModSecurity CRS PL2"),
    ("rate-limiter", "http://localhost:8000", "juice-shop behind 5 r/s limit"),
    ("monitoring", "http://localhost:9090", "logs dashboard"),
]


def run_compose(args: list[str]) -> subprocess.CompletedProcess:
    """Run a docker compose command inside the emulator directory."""
    return subprocess.run(
        ["docker", "compose", *args], cwd=EMU_DIR, check=False,
        capture_output=True, text=True)


def docker_available() -> bool:
    return shutil.which("docker") is not None


@click.group()
def cli() -> None:
    """The Pre-Verdict emulator: a hostile-feeling local range."""


@cli.command()
def start() -> None:
    """Bring the whole emulator up."""
    if not docker_available():
        raise click.ClickException("docker is not available on this machine")
    result = run_compose(["up", "-d", "--build"])
    if result.returncode != 0:
        raise click.ClickException(f"compose failed: {result.stderr.strip()}")
    click.echo("Emulator running. Endpoints:")
    for name, url, note in TARGETS:
        click.echo(f"  {name:13} {url}  ({note})")


@cli.command()
def stop() -> None:
    """Bring the emulator down."""
    if not docker_available():
        raise click.ClickException("docker is not available on this machine")
    result = run_compose(["down"])
    if result.returncode != 0:
        raise click.ClickException(f"compose failed: {result.stderr.strip()}")
    click.echo("Emulator stopped.")


@cli.command()
def reset() -> None:
    """Full teardown (including volumes) and a fresh start."""
    if not docker_available():
        raise click.ClickException("docker is not available on this machine")
    for args in (["down", "-v"], ["up", "-d", "--build"]):
        result = run_compose(args)
        if result.returncode != 0:
            raise click.ClickException(
                f"compose {' '.join(args)} failed: {result.stderr.strip()}")
    click.echo("Emulator reset and running.")


@cli.command()
def status() -> None:
    """Which services are up, as recorded by docker compose."""
    if not docker_available():
        click.echo("docker: not available — emulator is down")
        return
    result = run_compose(["ps", "--format", "json"])
    services = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        services.append((entry.get("Service", "?"),
                         entry.get("State", "?")))
    if not services:
        click.echo("emulator: down (no running services)")
        return
    for name, state in sorted(services):
        click.echo(f"{name:13} {state}")


@cli.command()
@click.option("--tail", default=50, show_default=True)
def logs(tail: int) -> None:
    """Recent compose logs."""
    if not docker_available():
        raise click.ClickException("docker is not available on this machine")
    result = run_compose(["logs", "--tail", str(tail)])
    click.echo(result.stdout or result.stderr)


@cli.command()
def analyze() -> None:
    """Produce the attack report from the shared logs."""
    report_path = LOG_DIR.parent / "attack_report.md"
    try:
        from logparse import analyze
    except ImportError:
        raise click.ClickException("logparse module not found") from None
    report = analyze(LOG_DIR)
    report.generated_at = datetime.now(timezone.utc).isoformat()
    report_path.write_text(report.to_markdown(), encoding="utf-8")
    click.echo(report.to_markdown(), nl=False)
    click.echo(f"\nwritten to {report_path}")


@cli.command(name="targets")
def targets() -> None:
    """Every endpoint the emulator exposes."""
    for name, url, note in TARGETS:
        click.echo(f"{name:13} {url}  {note}")


if __name__ == "__main__":
    cli()
