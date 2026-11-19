# src/webpent/cli/portfolio.py
"""webpent.cli.portfolio — M1-C (UM-DR-12) fleet-portfolio operator surface.

M1_READINESS_REVIEW §5.5 disposition for the ق11 portfolio manager
(``webpent.portfolio.manager`` — zero production importers at M0):

    M1-C: CLI surface ``webpent portfolio wave`` (safe, no graph edits).

This module is that surface: a Typer sub-app (the established
new-file-plus-minimal-wiring pattern used for ``ops``/``retest``) that
exposes the fleet manager's ``plan_wave`` — an operator-inspectable
launch ORDER for one fleet wake. What it deliberately does NOT do:

* it never launches, mutates, or schedules a campaign — planning is a
  pure ordering computation over the operator-supplied entries file;
* it never invents budgets — every cap comes from the entries file the
  operator owns;
* it never silently drops a target — ``plan_wave`` records every skip
  WITH its reason (paused / exhausted / capped) and this surface prints
  the skips as first-class output.

Entries file (JSON list):
    [
      {"target_ref": "https://lab.example", "campaign_id": "camp-1",
       "priority": 1, "budget_usd_cap": 40.0,
       "wallclock_minutes_cap": 90, "max_findings_cap": 12},
      ...
    ]
Unknown fields are rejected (fail-closed): the file is the operator's
authority, not a free-form bag.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

console = Console()
err_console = Console(stderr=True)

portfolio_app = typer.Typer(
    help="Fleet portfolio (ق11): plan operator-inspectable launch waves.",
    no_args_is_help=True,
)


@portfolio_app.callback()
def _portfolio_root() -> None:
    """Fleet portfolio (ق11): ordering + budgets — never launches anything."""

_ALLOWED_ENTRY_FIELDS = frozenset(
    {
        "target_ref",
        "campaign_id",
        "priority",
        "budget_usd_cap",
        "wallclock_minutes_cap",
        "max_findings_cap",
        "state",
        "pause_reason",
        "spent_usd",
        "spent_wallclock_minutes",
        "findings",
        "created_at",
    }
)


def _load_entries(path: Path) -> list[dict[str, Any]]:
    """Load + validate the operator's entries file (fail-closed)."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        err_console.print(f"[red]Error:[/red] entries file not found: {path}")
        raise typer.Exit(2) from exc
    except json.JSONDecodeError as exc:
        err_console.print(f"[red]Error:[/red] entries file is not valid JSON: {exc}")
        raise typer.Exit(2) from exc
    if not isinstance(raw, list) or not raw:
        err_console.print("[red]Error:[/red] entries file must be a non-empty JSON list")
        raise typer.Exit(2)
    entries: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            err_console.print(f"[red]Error:[/red] entry #{index} must be an object")
            raise typer.Exit(2)
        unknown = set(item) - _ALLOWED_ENTRY_FIELDS
        if unknown:
            err_console.print(
                f"[red]Error:[/red] entry #{index} has unknown field(s): "
                f"{sorted(unknown)} (allowed: {sorted(_ALLOWED_ENTRY_FIELDS)})"
            )
            raise typer.Exit(2)
        if not str(item.get("target_ref", "")).strip():
            err_console.print(f"[red]Error:[/red] entry #{index} needs a target_ref")
            raise typer.Exit(2)
        if not str(item.get("campaign_id", "")).strip():
            err_console.print(f"[red]Error:[/red] entry #{index} needs a campaign_id")
            raise typer.Exit(2)
        entries.append(item)
    return entries


@portfolio_app.command("wave")
def wave(
    entries: Path = typer.Option(
        ...,
        "--entries",
        "-e",
        help="JSON file with the portfolio entries (operator-owned authority).",
    ),
    capacity: int = typer.Option(
        1,
        "--capacity",
        "-c",
        min=0,
        help="Fleet capacity for this wake (how many targets may launch).",
    ),
) -> None:
    """Plan one launch wave: priority order + explicit skips (read-only)."""
    from webpent.portfolio.manager import PortfolioEntry, PortfolioError, PortfolioManager

    raw_entries = _load_entries(entries)
    manager = PortfolioManager()
    for index, item in enumerate(raw_entries):
        try:
            manager.add(PortfolioEntry(**item))
        except (PortfolioError, TypeError) as exc:
            err_console.print(f"[red]Error:[/red] entry #{index} rejected: {exc}")
            raise typer.Exit(2) from exc
    try:
        result = manager.plan_wave(capacity=capacity)
    except PortfolioError as exc:
        err_console.print(f"[red]Error:[/red] wave planning refused: {exc}")
        raise typer.Exit(2) from exc

    table = Table(title=f"Wave {result.wave_id} — launch order (capacity {result.capacity})")
    table.add_column("#")
    table.add_column("target")
    table.add_column("campaign")
    table.add_column("priority")
    table.add_column("work_unit_id")
    for order, planned in enumerate(result.planned, start=1):
        table.add_row(
            str(order),
            str(planned.get("target_ref", "")),
            str(planned.get("campaign_id", "")),
            str(planned.get("priority", "")),
            str(planned.get("work_unit_id", "")),
        )
    console.print(table)
    if result.skipped:
        skip_table = Table(title="Skipped (nothing silently dropped)")
        skip_table.add_column("target")
        skip_table.add_column("reason")
        skip_table.add_column("detail")
        for skipped in result.skipped:
            skip_table.add_row(
                str(skipped.get("target_ref", "")),
                str(skipped.get("reason", "")),
                str(skipped.get("detail", "")),
            )
        console.print(skip_table)
    console.print(
        f"[dim]Utilization: {result.utilization:.0%} — planning only; "
        "launching stays the operator's worker/scheduler decision.[/dim]"
    )


__all__ = ["portfolio_app"]
