# src/webpent/cli/retest.py
"""webpent.cli.retest — Track 11, item 7: controlled re-test commands.

``webpent retest list``    — list findings eligible for retest (DB-backed).
``webpent retest finding`` — gated single-finding retest: mandatory
authorization, mandatory typed scope file, one bounded replay of the
STORED evidence request through the hardened HTTP factory, deterministic
verdict, status update through the standard DB manager (so the platform's
status-history audit trail records the transition), and one append-only
JSONL comparison row (``retest_ledger_path``).

The command never regenerates payloads, never explores, never retries
storms, and never promotes a finding. Anything ambiguous becomes
"Needs Human Review" — the plan's fail-safe posture.
"""

from __future__ import annotations

from uuid import UUID

import typer
from rich.console import Console
from rich.table import Table

retest_app = typer.Typer(
    name="retest",
    help=(
        "Controlled re-test of a previous finding (Track 11 item 7): "
        "authorized scope only, one bounded replay, comparison record saved."
    ),
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)

__all__ = ["retest_app"]


@retest_app.command("list")
def retest_list(
    limit: int = typer.Option(20, "--limit", "-n", min=1, max=200),
    thread: str | None = typer.Option(None, "--thread", help="Filter by thread id."),
) -> None:
    """List findings from the local DB that can be retested (no requests sent)."""
    from webpent.memory.db import get_db_manager
    from webpent.vip.retest import RetestLedger

    manager = get_db_manager()
    findings = (
        manager.get_findings_by_thread(thread) if thread else manager.get_all_findings()
    )
    findings = findings[-limit:] if len(findings) > limit else findings
    if not findings:
        console.print("[dim]No findings stored in the local DB.[/dim]")
        return

    ledger = RetestLedger(_ledger_path())
    table = Table(title="Findings available for controlled retest", border_style="grey50")
    table.add_column("ID", width=12)
    table.add_column("Class", width=18)
    table.add_column("Severity", width=9)
    table.add_column("Level", width=17)
    table.add_column("URL", overflow="fold", max_width=48)
    table.add_column("Last retest", width=16)
    for finding in findings:
        history = ledger.history_for(finding.id)
        last = history[-1]["outcome"] if history else "-"
        table.add_row(
            str(finding.id)[:12],
            str(finding.vuln_class),
            str(finding.severity),
            str(finding.confidence_level),
            str(finding.url),
            last,
        )
    console.print(table)
    console.print(
        "[dim]Retest one finding with: webpent retest finding <ID> "
        "--scope-file <scope.yaml> --authorization <ref>[/dim]"
    )


@retest_app.command("finding")
def retest_finding(
    finding_id: str = typer.Argument(..., help="UUID of the stored finding to retest."),
    authorization: str | None = typer.Option(
        None, "--authorization", help="Written authorization reference (REQUIRED)."
    ),
    scope_file: str | None = typer.Option(
        None, "--scope-file", help="Typed YAML/JSON scope policy (REQUIRED)."
    ),
    timeout: float | None = typer.Option(
        None, "--timeout", help="Per-request timeout override (seconds)."
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show gates and the request that WOULD be replayed; send nothing.",
    ),
    reason: str = typer.Option(
        "", "--reason", help="Optional operator reason stored in the ledger."
    ),
) -> None:
    """Retest ONE stored finding inside the authorized scope (fail-closed gates)."""
    from webpent.memory.db import get_db_manager
    from webpent.vip.retest import (
        RetestLedger,
        apply_retest,
        load_scope_policy,
        run_retest,
        validate_authorization,
    )

    # Gate 1: authorization (before anything else).
    try:
        auth_ref = validate_authorization(authorization)
    except ValueError as exc:
        err_console.print(f"[red]Refused:[/red] {exc}")
        raise typer.Exit(2) from exc

    # Gate 2: scope policy file is mandatory.
    try:
        policy = load_scope_policy(scope_file or "")
    except ValueError as exc:
        err_console.print(f"[red]Refused:[/red] {exc}")
        raise typer.Exit(2) from exc
    except OSError as exc:
        err_console.print(f"[red]Error:[/red] scope file unreadable: {exc}")
        raise typer.Exit(1) from exc

    # Load the finding from the local DB.
    try:
        finding_uuid = UUID(finding_id.strip())
    except ValueError as exc:
        err_console.print(f"[red]Error:[/red] invalid finding id: {finding_id}")
        raise typer.Exit(1) from exc
    finding = get_db_manager().get_finding(finding_uuid)
    if finding is None:
        err_console.print(f"[red]Error:[/red] finding {finding_id} not found in the local DB.")
        raise typer.Exit(1)

    console.print(f"[bold]Retesting finding[/bold] {finding.id}")
    console.print(f"  class={finding.vuln_class} level={finding.confidence_level}")
    console.print(f"  url={finding.url}")
    if dry_run:
        console.print("  [yellow]dry-run:[/yellow] no request will be sent.")

    settings = _settings()
    ledger = RetestLedger(str(settings.retest_ledger_path))
    effective_timeout = float(
        timeout if timeout is not None else settings.retest_request_timeout
    )

    result = run_retest(
        finding,
        scope_policy=policy,
        authorization=auth_ref,
        timeout=effective_timeout,
        ledger=ledger,
        skip_network=bool(dry_run),
    )

    if reason:
        result.notes.append(f"operator reason: {reason}")

    console.print(f"[bold]Outcome:[/bold] {_outcome_style(result.outcome.value)}")
    for note in result.notes:
        console.print(f"  - {note}")
    console.print(
        f"  prior level={result.prior_confidence_level} -> new level={result.new_confidence_level}"
    )
    console.print(f"  comparison record appended to {ledger.path}")

    if dry_run:
        return

    # Persist the status update through the standard DB manager so the
    # platform status-history audit trail records the transition.
    updated = apply_retest(finding, result)
    get_db_manager().save_finding(updated)
    console.print("[green]Finding updated in DB (status history recorded).[/green]")


def _ledger_path() -> str:
    from webpent.config.settings import get_settings

    return str(get_settings().retest_ledger_path)


def _settings():
    from webpent.config.settings import get_settings

    return get_settings()


def _outcome_style(outcome: str) -> str:
    mapping = {
        "still_present": "[red]still_present[/red]",
        "fixed": "[green]fixed (human closure required)[/green]",
        "inconclusive": "[yellow]inconclusive — needs human review[/yellow]",
        "blocked_by_scope": "[red]blocked_by_scope (no request sent)[/red]",
    }
    return mapping.get(outcome, outcome)
