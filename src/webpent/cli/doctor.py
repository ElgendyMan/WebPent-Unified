# src/webpent/cli/doctor.py
"""webpent.cli.doctor — the ONE ``webpent doctor`` command (Track 8.4/3.6).

Roadmap contract (المسار 8، تثبيت وإعداد أسهل — البند 3، والمسار 3
البند 6):

    جعل ``webpent doctor`` أمرًا واحدًا يفحص قاعدة البيانات ومزود
    النموذج والأدوات الخارجية ويعرض النواقص بوضوح.

    ("Make ``webpent doctor`` a single command that checks the local
    database, the LLM provider, and the external tools, and shows
    missing items clearly.")

Why this exists
---------------
Until 0.25.0 the doctor story was split: ``scripts/doctor.py`` (LLM
providers only, wired to ``make doctor``) and ``webpent preflight``
(tools + Playwright + LLM status). The DB was checked NOWHERE, and four
operator-facing surfaces (README quickstart ×2, ``install.sh``,
``docker-compose.yml`` quickstart banner) referenced a ``webpent
doctor`` command that did not exist — every fresh install silently
failed that step and fell back or skipped.

This module closes the gap as a NEW Typer sub-app (the frozen-window
protocol pattern used for ``ops``/``retest``): one command, read-only,
no network requests to any target, no campaign behavior change.

What it checks (each area, fail-closed where it matters)
--------------------------------------------------------
1. **version**    — the ``webpent`` package imports and reports its version.
2. **database**   — the local findings DB opens through the standard
   manager, a trivial COUNT works, and the resolved path is shown.
3. **llm**        — provider posture via the EXACT shared check
   (``webpent.shared.preflight._check_llm_providers``): enabled?
   configured providers? circuit-breaker dead list? Optional live probe
   (``--probe``) exercises the same builder path the runtime uses.
4. **tools**      — the external recon/exploitation tools the engine
   integrates with (nuclei/subfinder/httpx-pd/katana/dalfox/sqlmap).
   Missing tools are listed clearly; they are OPTIONAL by design (the
   deterministic path works without them) so they degrade to WARN.
5. **knowledge**  — offline knowledge-pack readiness (advisory, never
   changes the exit code — same policy as scripts/doctor.py).
6. **playwright** — browser sandbox availability (WARN when absent;
   the sandbox skips gracefully).

Exit codes (mirrors scripts/doctor.py policy)
---------------------------------------------
0 — no FAIL results (WARNs are allowed; deterministic-only operation is
    explicitly usable),
1 — at least one FAIL (e.g. DB unusable, or LLM enabled but no usable
    provider),
2 — harness error (imports/settings could not load).

No drift-by-second-implementation: every check reuses the shared
module the runtime itself uses. The optional live probe reuses the
``webpent.shared.llm`` builders directly (same policy as
``scripts/doctor.py`` — the doctor and the router must exercise the
SAME code path).
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from typing import Any

import typer
from rich.console import Console

console = Console()
err_console = Console(stderr=True)

#: External tools the engine integrates with. V8 FIX inherited from the
#: ``preflight`` command: check ``httpx-pd`` (the Go ProjectDiscovery
#: binary), not the Python ``httpx`` CLI that pip would shadow.
EXTERNAL_TOOLS = ("nuclei", "subfinder", "httpx-pd", "katana", "dalfox", "sqlmap")

_OK = "ok"
_WARN = "warn"
_FAIL = "fail"


@dataclass
class CheckResult:
    """One doctor check — status is one of ok/warn/fail."""

    area: str
    status: str
    detail: str
    missing: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "area": self.area,
            "status": self.status,
            "detail": self.detail,
            "missing": list(self.missing),
        }


def _check_version() -> CheckResult:
    try:
        from importlib.metadata import version

        return CheckResult("version", _OK, f"webpent {version('webpent')}")
    except Exception as exc:  # pragma: no cover - packaging anomaly
        return CheckResult("version", _FAIL, f"package import failed: {type(exc).__name__}")


def _check_database() -> CheckResult:
    """Open the local DB through the standard manager (the exact path
    the engine uses) and run a trivial aggregate."""
    try:
        from webpent.memory.db import get_db_manager

        manager = get_db_manager()
        findings = manager.get_all_findings()
        path = manager._db_path()
        size = path.stat().st_size if (str(path) != ":memory:" and path.exists()) else 0
        size_text = f"{size / 1024:.1f} KiB" if size else "empty/new"
        return CheckResult(
            "database",
            _OK,
            f"opens at {path} ({size_text}); findings rows readable: {len(findings)}",
        )
    except Exception as exc:
        return CheckResult("database", _FAIL, f"DB check failed: {type(exc).__name__}: {exc}")


def _check_llm(probe: bool) -> CheckResult:
    """Provider posture via the shared runtime check; optional live probe."""
    from webpent.shared.preflight import _check_llm_providers

    status = _check_llm_providers()
    enabled = bool(status.get("enabled", False))
    providers = list(status.get("configured_providers") or [])
    dead = list(status.get("dead_providers") or [])
    detail = (
        f"enabled={enabled}; configured={', '.join(map(str, providers)) or 'none'}; "
        f"circuit-breaker dead={', '.join(map(str, dead)) or 'none'}"
    )
    if not enabled:
        return CheckResult("llm", _OK, detail + " — deterministic path is the plan")
    if not providers:
        return CheckResult(
            "llm", _FAIL, detail + " — LLM enabled but no provider key configured"
        )
    result = CheckResult("llm", _OK, detail)
    if probe:
        probe_detail = _live_probe(providers)
        result.detail = f"{detail}; probe: {probe_detail}"
        if probe_detail.startswith("unreachable"):
            result.status = _FAIL
    return result


def _live_probe(providers: list[Any]) -> str:
    """Send a minimal non-target prompt through the runtime builders.

    Same policy as scripts/doctor.py: the probe must exercise the EXACT
    builder path the router uses (``webpent.shared.llm``) so the doctor
    cannot report a provider ACTIVE while the real router fails.
    """
    from webpent.shared.llm import TaskType, get_llm

    for provider in providers:
        name = str(provider)
        try:
            runnable = get_llm(TaskType.GENERAL, prompt="Reply with OK", provider=name)
            if runnable is None:
                return f"{name}: no builder (skipped)"
            runnable.invoke("Reply with OK")
            return f"{name}: reachable"
        except Exception as exc:
            return f"{name}: unreachable ({type(exc).__name__})"  # first provider only
    return "no provider to probe"


def _check_tools() -> CheckResult:
    missing = [tool for tool in EXTERNAL_TOOLS if not shutil.which(tool)]
    present = len(EXTERNAL_TOOLS) - len(missing)
    detail = f"{present}/{len(EXTERNAL_TOOLS)} available"
    if missing:
        return CheckResult(
            "tools",
            _WARN,
            detail + " — optional: integrations degrade gracefully without them",
            missing=missing,
        )
    return CheckResult("tools", _OK, detail)


def _check_knowledge() -> CheckResult:
    """Advisory knowledge-pack readiness — never changes the exit code."""
    try:
        from webpent.shared.preflight import _check_knowledge_ready

        report = _check_knowledge_ready()
        ready = bool(report.get("knowledge_ready", False))
        detail = "offline knowledge pack ready" if ready else "knowledge pack empty/missing"
        return CheckResult("knowledge", _OK if ready else _WARN, detail)
    except Exception as exc:
        return CheckResult("knowledge", _WARN, f"knowledge check skipped: {type(exc).__name__}")


def _check_playwright() -> CheckResult:
    try:
        import importlib.util

        installed = importlib.util.find_spec("playwright") is not None
        if installed:
            return CheckResult("playwright", _OK, "python package present")
        return CheckResult(
            "playwright", _WARN, "not installed — browser sandbox will skip gracefully"
        )
    except Exception as exc:  # pragma: no cover
        return CheckResult("playwright", _WARN, f"check skipped: {type(exc).__name__}")


#: Areas whose WARN is expected on a minimal deterministic install and
#: must never fail the command.
_ADVISORY_AREAS = frozenset({"tools", "knowledge", "playwright"})


def run_checks(probe: bool) -> list[CheckResult]:
    checks: list[CheckResult] = [
        _check_version(),
        _check_database(),
        _check_llm(probe),
        _check_tools(),
        _check_knowledge(),
        _check_playwright(),
    ]
    return checks


def register_doctor(target_app: Any) -> None:
    """Register the ``webpent doctor`` command on the main CLI app.

    Kept as a two-line wiring helper so ``commands.py`` (a frozen-window
    file) only gains an import + a call — the same minimal-delta pattern
    the ``ops``/``retest`` sub-apps used.
    """

    @target_app.command("doctor")
    def doctor(
        probe: bool = typer.Option(
            False,
            "--probe",
            help="Live-probe the first configured LLM provider (network).",
        ),
        timeout: int = typer.Option(10, "--timeout", min=1, max=120),
        as_json: bool = typer.Option(False, "--json", help="Machine-readable report."),
    ) -> None:
        """Check DB + LLM providers + external tools; show missing items clearly.

        Read-only, no target requests, no campaign behavior change. Exit 0
        when usable, 1 on a blocking gap, 2 on a harness error.
        """
        # ``timeout`` is accepted for CLI compatibility with
        # scripts/doctor.py callers; configuration-level checks do not
        # need a per-provider network budget (the optional --probe uses
        # the runtime's own transport defaults).
        del timeout
        try:
            checks = run_checks(probe=probe)
        except Exception as exc:
            err_console.print(f"[red]doctor harness error:[/red] {type(exc).__name__}: {exc}")
            raise typer.Exit(2) from exc

        if as_json:
            blocking = [c.as_dict() for c in checks if c.status == _FAIL]
            payload = {
                "status": "fail" if blocking else "ok",
                "checks": [c.as_dict() for c in checks],
                "missing": sorted(m for c in checks for m in c.missing),
            }
            console.print_json(json.dumps(payload, default=str))
        else:
            for check in checks:
                icon = {_OK: "[green]OK   [/green]", _WARN: "[yellow]WARN [/yellow]",
                        _FAIL: "[red]FAIL [/red]"}[check.status]
                console.print(f"{icon}{check.area:<11} {check.detail}")
                for item in check.missing:
                    console.print(f"      - missing: {item}")
            blocking = [c for c in checks if c.status == _FAIL]
            if blocking:
                names = ", ".join(c.area for c in blocking)
                err_console.print(f"\n[red]blocking gaps:[/red] {names}")
            else:
                console.print(
                    "\n[green]doctor: usable.[/green] Next: [bold]webpent init[/bold] "
                    "then a lab hunt (see README — تجربة على lab آمن)."
                )

        if any(c.status == _FAIL for c in checks):
            raise typer.Exit(1)
        raise typer.Exit(0)
