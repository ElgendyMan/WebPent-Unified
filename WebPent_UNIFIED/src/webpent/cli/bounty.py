# src/webpent/cli/bounty.py
"""webpent.cli.bounty — M1-C (UM-DR-12) bounty-pipeline operator surface.

M1_READINESS_REVIEW §5.5 disposition for the ق10 bounty pipeline
(``webpent.reporter.bounty_pipeline`` — zero production importers at M0):

    M1-C: expose as ``webpent bounty`` subcommand
    (safe: sends nothing without approval cage).

This module is that surface — PREVIEW ONLY by design:

* ``webpent bounty preview`` runs the pipeline's draft → render →
  preview stages over findings loaded from the local DB and prints the
  platform-native, submission-ready Markdown for operator review.
* There is NO submit command here. The pipeline's ``submit`` stage is
  fail-closed on approval AND (under the ق2 cage) on a tier-3 authority
  grant — putting an approval-free submit behind a CLI flag would
  defeat both. Submission stays an operator decision made through an
  explicitly provided approval callback (see the pipeline module); the
  CLI surface hands over rendered drafts and nothing else. The module
  performs no network I/O of any kind.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

console = Console()
err_console = Console(stderr=True)

bounty_app = typer.Typer(
    help="Bounty pipeline (ق10): render operator-reviewable submission drafts.",
    no_args_is_help=True,
)


@bounty_app.callback()
def _bounty_root() -> None:
    """Bounty pipeline (ق10): previews only — nothing is ever sent."""

_VALID_PLATFORMS = ("hackerone", "bugcrowd", "intigriti", "neutral")


def _load_findings(engagement: str) -> list[Any]:
    """Load a campaign's findings from the local DB (read-only)."""
    from webpent.api.scan_registry import get_thread_ids_by_engagement_id
    from webpent.memory.db import get_db_manager
    from webpent.shared.finding_aggregation import aggregate_findings

    try:
        thread_ids = None
        try:
            thread_ids = get_thread_ids_by_engagement_id(engagement)
        except Exception:  # engagement-index unavailable in some installs
            thread_ids = None
        thread_list = list(thread_ids or []) or [engagement]
        return aggregate_findings(get_db_manager().get_findings_by_threads(thread_list))
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] unable to load campaign findings: {exc}")
        raise typer.Exit(2) from exc


@bounty_app.command("preview")
def preview(
    engagement: str = typer.Argument(..., help="Campaign/engagement identifier."),
    finding_id: str | None = typer.Option(
        None, "--finding-id", help="Preview one finding instead of all eligible ones."
    ),
    platform: str = typer.Option(
        "hackerone", "--platform", help="hackerone, bugcrowd, intigriti, or neutral."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the preview(s) to a file instead of stdout."
    ),
) -> None:
    """Render submission-ready previews from promoted ProofBundles (no send)."""
    if platform.strip().lower() not in _VALID_PLATFORMS:
        err_console.print(
            f"[red]Error:[/red] platform must be one of {', '.join(_VALID_PLATFORMS)}"
        )
        raise typer.Exit(1)
    from webpent.reporter.bounty_pipeline import BountyPipeline

    findings = _load_findings(engagement)
    if finding_id:
        findings = [f for f in findings if str(f.id) == str(finding_id)]
        if not findings:
            err_console.print(f"[red]Error:[/red] finding {finding_id!r} not found in {engagement!r}")
            raise typer.Exit(2)
    pipeline = BountyPipeline(
        # No approval callback and no sink: draft() itself refuses to
        # produce anything for a non-promoted finding, and submit is not
        # reachable from this surface by construction.
    )
    rendered: list[str] = []
    refused = 0
    for finding in findings:
        draft = pipeline.draft(finding, platform=platform.strip().lower())
        if draft is None:
            refused += 1
            continue
        body = getattr(draft, "preview", None) or getattr(draft, "markdown", "")
        rendered.append(str(body))
    if not rendered:
        console.print(
            "[dim]No submission-ready promoted ProofBundle drafts for this "
            f"campaign ({refused} finding(s) refused by the pipeline — "
            "only promoted, sealed evidence enters the pipeline).[/dim]"
        )
        return
    content = "\n\n---\n\n".join(rendered) + "\n"
    if output:
        output.expanduser().parent.mkdir(parents=True, exist_ok=True)
        output.expanduser().write_text(content, encoding="utf-8")
        console.print(f"[green]Preview written:[/green] {output.expanduser()}")
    else:
        console.print(content, markup=False)
    if refused:
        console.print(
            f"[dim]{refused} finding(s) skipped: not promoted / no sealed ProofBundle "
            "(the pipeline refuses them by contract).[/dim]"
        )


__all__ = ["bounty_app"]
