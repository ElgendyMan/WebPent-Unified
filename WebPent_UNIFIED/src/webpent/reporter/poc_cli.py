"""``webpent-poc`` — CLI for video POC recording and evidence export.

Registered in pyproject.toml as ``webpent-poc = "webpent.reporter.poc_cli:main"``
(also runnable as ``python -m webpent.reporter.poc_cli``).

NOTE on naming: the frozen ``webpent`` typer app (``webpent/cli/commands.py``,
byte-identical under the 695-file trust gate) cannot gain a ``poc``
subcommand without editing sealed code, which the sprint forbids. The
sanctioned surface is therefore the dedicated ``webpent-poc`` console script.

Tokens are read from options or environment (``WEBPENT_POC_OWNER_TOKEN`` /
``WEBPENT_POC_FOREIGN_TOKEN``) and are never echoed or logged.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import typer

app = typer.Typer(
    name="webpent-poc",
    help="Video POC recorder + bug-bounty evidence export (post-promotion enhancement).",
    no_args_is_help=True,
)


def _ledger(path: str | None) -> Any:
    from webpent.shared.persistent_finding_ledger import PersistentFindingLedger

    return PersistentFindingLedger(Path(path)) if path else PersistentFindingLedger()


def _find_finding(ledger: Any, engagement_id: str, finding_id: str) -> dict[str, Any]:
    for model in ledger.get(engagement_id):
        finding = model if isinstance(model, dict) else dict(model)
        if str(finding.get("id")) == finding_id:
            return finding
    raise typer.BadParameter(f"finding {finding_id!r} not found in engagement {engagement_id!r}")


def _audit_chain(engagement_id: str, artifact_root: Path | None):
    """Best-effort engagement audit chain (v4, R-09).

    v3 never passed an audit chain from any shipped caller, so the documented
    ``poc.recorded`` / ``poc.failed`` events were dead code. The chain used is
    the engagement's EXISTING product-owned ``EngagementAuditChain`` (same
    hash-chained file as the campaign) — construction failures degrade to
    ``None`` (no audit), never to a recording failure.
    """
    if artifact_root is None:
        return None
    try:
        from webpent.shared.engagement_audit import EngagementAuditChain

        return EngagementAuditChain(
            engagement_id=engagement_id,
            audit_dir=artifact_root / "audit",
            workspace_dir=artifact_root / "audit_workspace",
        )
    except (OSError, TypeError, ValueError, ImportError):
        return None


@app.command("record")
def record(
    finding_id: str = typer.Option(..., "--finding", help="Finding UUID from the ledger."),
    engagement: str = typer.Option(..., "--engagement", help="Engagement id used in the ledger."),
    output: Path = typer.Option(Path("hunt_artifacts/poc"), "--output", help="Artifact directory."),
    ledger_path: Path | None = typer.Option(None, "--ledger", help="Optional ledger DB path."),
    owner_token: str | None = typer.Option(None, "--owner-token", envvar="WEBPENT_POC_OWNER_TOKEN", help="Owner token (or env)."),
    foreign_token: str | None = typer.Option(None, "--foreign-token", envvar="WEBPENT_POC_FOREIGN_TOKEN", help="Foreign token (or env)."),
    token_header: str = typer.Option("Authorization", "--token-header", help="Header carrying the token."),
    artifact_root: Path | None = typer.Option(None, "--artifact-root", help="Engagement artifact root holding the product audit chain (default: hunt_artifacts/<engagement>)."),
) -> None:
    """Record the step-by-step vulnerability video for one finding.

    Fail-soft by contract: a recording failure prints the reason and exits 0
    with status=failed — a POC problem must never be mistaken for a campaign
    failure.
    """
    from webpent.reporter.poc_recorder import maybe_record_poc

    finding = _find_finding(_ledger(str(ledger_path) if ledger_path else None), engagement, finding_id)
    chain = _audit_chain(engagement, artifact_root or Path("hunt_artifacts") / engagement)
    result = maybe_record_poc(
        finding,
        engagement_id=engagement,
        output_dir=output,
        owner_token=owner_token,
        foreign_token=foreign_token,
        token_header=token_header,
        audit_chain=chain,
    )
    typer.echo(f"status={result.get('status')}")
    if result.get("status") == "failed":
        typer.echo(f"reason={result.get('reason')}")
    else:
        typer.echo(f"video={result.get('video_path')}")
        typer.echo(f"metadata={result.get('metadata_path')}")


@app.command("export")
def export(
    engagement: str = typer.Option(..., "--engagement", help="Engagement id used in the ledger."),
    finding_id: str | None = typer.Option(None, "--finding", help="Single finding (default: all promoted)."),
    output: Path = typer.Option(Path("hunt_artifacts/submissions"), "--output", help="Export directory."),
    poc_dir: Path = typer.Option(Path("hunt_artifacts/poc"), "--poc-dir", help="POC artifacts directory."),
    ledger_path: Path | None = typer.Option(None, "--ledger", help="Optional ledger DB path."),
    token_header: str = typer.Option("Authorization", "--token-header", help="Header carrying the token."),
) -> None:
    """Export promoted finding(s) as bug-bounty submissions (md + json)."""
    from webpent.reporter.poc_export import export_all_promoted, export_finding_evidence

    ledger = _ledger(str(ledger_path) if ledger_path else None)
    if finding_id:
        finding = _find_finding(ledger, engagement, finding_id)
        result = export_finding_evidence(finding, output_dir=output, poc_dir=poc_dir, token_header=token_header)
        typer.echo(f"markdown={result['markdown']}")
        typer.echo(f"json={result['json']}")
        return
    summary = export_all_promoted(
        [dict(f) for f in ledger.get(engagement)],
        output_dir=output,
        poc_dir=poc_dir,
        token_header=token_header,
    )
    typer.echo(f"exported={summary['count']}")
    for item in summary["exported"]:
        typer.echo(f"  {item['finding_id']} -> {item['markdown']}")
    for item in summary["skipped"]:
        typer.echo(f"  skipped {item['finding_id']}: {item['reason']}")


@app.command("embed")
def embed(
    report: Path = typer.Option(..., "--report", help="Rendered HTML report path."),
    poc_dir: Path = typer.Option(Path("hunt_artifacts/poc"), "--poc-dir", help="POC artifacts directory."),
) -> None:
    """Embed recorded POC videos into a rendered HTML report (idempotent)."""
    from webpent.reporter.poc_recorder import enrich_report_with_poc

    if enrich_report_with_poc(report, poc_dir):
        typer.echo(f"embedded -> {report}")
    else:
        typer.echo("nothing embedded (no videos, non-HTML report, or already embedded)")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
