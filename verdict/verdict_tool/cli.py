"""U-VERDICT-1 — the Verdict Protocol CLI.

A structured notebook with commands, not an agent: nothing here runs
the operator's tools, touches a real target or opens a network
connection (the single HEAD in the targets check is explicit and
operator-invoked). The operator runs webpent; the CLI records.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import click

from verdict_tool.classifier import ClassificationError, FindingClassifier
from verdict_tool.metrics import VerdictCalculator
from verdict_tool.protocol import TOTAL_DAYS, get_day, load_state
from verdict_tool.submission import SubmissionError, SubmissionPipeline
from verdict_tool.targets import TargetConfigError, TargetManager
from verdict_tool.tracking import WATCH_STATUSES, Workspace, new_state, utc_now

TEMPLATES = Path(__file__).resolve().parent / "templates"


@click.group()
@click.option("--path", "-p", default=".", show_default=True,
              type=click.Path(file_okay=False),
              help="Verdict workspace directory")
@click.pass_context
def cli(ctx: click.Context, path: str) -> None:
    """The Verdict Protocol — a 47-day truth-finding notebook."""
    ctx.obj = Workspace(path)


# -- init / status ------------------------------------------------------------

@cli.command()
@click.pass_obj
def init(ws: Workspace) -> None:
    """Create a Verdict workspace with the standard structure."""
    if ws.exists():
        raise click.ClickException(
            f"workspace already initialized at {ws.root}"
        )
    ws.ensure_dirs()
    state = new_state()
    ws.save(state)
    template = TEMPLATES / "pre_registration.md"
    pre_reg = ws.root / "pre_registration.md"
    if template.is_file() and not pre_reg.exists():
        pre_reg.write_text(template.read_text(encoding="utf-8"),
                           encoding="utf-8")
    state.open_day(0)
    ws.save(state)
    click.echo(f"Verdict workspace initialized at {ws.root}")
    click.echo("Day 0 is open. Start with: verdict pre-registration edit")


@cli.command()
@click.pass_obj
def status(ws: Workspace) -> None:
    """One-screen summary of the whole protocol."""
    state = load_state(ws)
    click.echo(state.summary())


# -- days ---------------------------------------------------------------------

@cli.command()
@click.argument("day", type=int)
@click.option("--complete", is_flag=True,
              help="Close the day (only when every checklist item passes)")
@click.option("--list", "list_days", is_flag=True,
              help="List all protocol days")
@click.pass_obj
def day(ws: Workspace, day: int, complete: bool, list_days: bool) -> None:
    """Show the checklist for DAY (0..46)."""
    if list_days:
        from verdict_tool.protocol import protocol_days
        for number, spec in sorted(protocol_days().items()):
            click.echo(f"  day {number:2d}: {spec.title}")
        return
    if not 0 <= day < TOTAL_DAYS:
        raise click.ClickException(f"day must be in 0..{TOTAL_DAYS - 1}")
    spec = get_day(day)
    if complete:
        state = load_state(ws)
        state.open_day(day)
        missing = spec.missing(ws)
        if missing:
            raise click.ClickException(
                f"day {day} cannot be completed yet:\n  - "
                + "\n  - ".join(missing)
            )
        state.complete_day(day)
        ws.save(state)
        click.echo(f"day {day} complete")
        return
    click.echo(spec.render(ws))


# -- pre-registration -----------------------------------------------------------

@cli.group()
@click.pass_obj
def pre_registration(ws: Workspace) -> None:
    """Day-0 pre-registration (predictions frozen before testing)."""
    if not ws.exists():
        raise click.ClickException("run 'verdict init' first")


@pre_registration.command("edit")
@click.pass_obj
def pre_registration_edit(ws: Workspace) -> None:
    """Open pre_registration.md in your editor."""
    state = load_state(ws)
    if state.pre_registered:
        raise click.ClickException(
            "pre-registration is frozen; pre_registration.md is evidence "
            "and can no longer be edited (Round-3 findings F-2/F-3)"
        )
    path = ws.root / "pre_registration.md"
    if not path.exists():
        template = TEMPLATES / "pre_registration.md"
        if template.is_file():
            path.write_text(template.read_text(encoding="utf-8"),
                            encoding="utf-8")
    click.edit(filename=str(path))
    click.echo(f"edited {path}")


@pre_registration.command("done")
@click.pass_obj
def pre_registration_done(ws: Workspace) -> None:
    """Mark the pre-registration as frozen (day 0)."""
    state = load_state(ws)
    path = ws.root / "pre_registration.md"
    if not path.is_file():
        raise click.ClickException("pre_registration.md does not exist")
    state.pre_registered = True
    state.pre_registration_sha256 = hashlib.sha256(
        path.read_bytes()).hexdigest()
    ws.save(state)
    click.echo("pre-registration frozen (hash recorded: "
               f"{state.pre_registration_sha256[:16]}…)")


@pre_registration.command("predict")
@click.option("--findings", "findings_range", required=True, nargs=2,
              type=int, help="Predicted findings range, e.g. 5 15")
@click.option("--acceptance", "acceptance_range", required=True, nargs=2,
              type=float, help="Predicted acceptance rate range, e.g. 0.2 0.5")
@click.pass_obj
def pre_registration_predict(ws: Workspace, findings_range: tuple[int, int],
                             acceptance_range: tuple[float, float]) -> None:
    """Record the predicted ranges for the day-46 comparison."""
    state = load_state(ws)
    if state.pre_registered:
        raise click.ClickException(
            "pre-registration is frozen; predictions cannot change "
            "after day 0 (Round-3 finding F-2)"
        )
    state.predicted_findings_range = list(findings_range)
    state.predicted_acceptance_range = list(acceptance_range)
    ws.save(state)
    click.echo("predictions recorded")


# -- targets ----------------------------------------------------------------------

@cli.group()
@click.pass_obj
def targets(ws: Workspace) -> None:
    """Target configuration management (U-VERDICT-3)."""
    if not ws.exists():
        raise click.ClickException("run 'verdict init' first")


@targets.command("add")
@click.argument("yaml_path", type=click.Path(exists=True, dir_okay=False))
@click.pass_obj
def targets_add(ws: Workspace, yaml_path: str) -> None:
    """Validate a target YAML and register it."""
    manager = TargetManager(ws.root / "targets")
    try:
        target = manager.add(Path(yaml_path))
    except TargetConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    state = load_state(ws)
    state.targets.append({
        "name": target.name,
        "platform": target.platform,
        "config_path": target.config_path,
        "added_at": utc_now(),
        "legal_review": target.legal_review_completed,
    })
    ws.save(state)
    click.echo(f"target registered: {target.name} ({target.platform})")


@targets.command("list")
@click.pass_obj
def targets_list(ws: Workspace) -> None:
    """List registered targets and their validation status."""
    manager = TargetManager(ws.root / "targets")
    found = False
    for target in manager.list():
        found = True
        errors = manager.validate(target)
        flag = "ok" if not errors else "; ".join(errors)
        click.echo(f"  {target.name} [{target.platform}] {flag}")
    if not found:
        click.echo("  (no targets registered)")


@targets.command("check")
@click.argument("name")
@click.pass_obj
def targets_check(ws: Workspace, name: str) -> None:
    """One HEAD request to the program URL (explicit operator action)."""
    manager = TargetManager(ws.root / "targets")
    try:
        target = manager.get(name)
    except TargetConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    reachable = manager.check_accessibility(target)
    click.echo(f"{target.name}: {'reachable' if reachable else 'NOT reachable'}")


# -- runs -------------------------------------------------------------------------

@cli.group()
@click.pass_obj
def run(ws: Workspace) -> None:
    """Run bookkeeping (start/stop). The operator runs webpent."""
    if not ws.exists():
        raise click.ClickException("run 'verdict init' first")


@run.command("start")
@click.argument("target")
@click.pass_obj
def run_start(ws: Workspace, target: str) -> None:
    """Record the start of a run against TARGET."""
    manager = TargetManager(ws.root / "targets")
    try:
        config = manager.get(target)
        errors = manager.validate(config)
    except TargetConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    if errors:
        raise click.ClickException(
            f"{target} fails validation: {'; '.join(errors)}"
        )
    state = load_state(ws)
    run_dir = ws.subdir("runs") / target
    run_dir.mkdir(parents=True, exist_ok=True)
    launch = run_dir / "launch.txt"
    if not launch.exists():
        launch.write_text(
            f"# launch {target} at {utc_now()}\n"
            f"# max_rate_rps: {config.max_rate_rps}\n"
            f"# scope: {', '.join(config.in_scope)}\n",
            encoding="utf-8",
        )
    state.runs.append({
        "target": target,
        "started_at": utc_now(),
        "stopped_at": None,
        "launch_path": str(launch),
        "stop_path": "",
    })
    ws.save(state)
    click.echo(f"run started for {target}")


@run.command("stop")
@click.argument("target")
@click.pass_obj
def run_stop(ws: Workspace, target: str) -> None:
    """Record the clean stop of a run and the evidence backup step."""
    state = load_state(ws)
    runs = [r for r in state.runs if r.get("target") == target
            and not r.get("stopped_at")]
    if not runs:
        raise click.ClickException(f"no open run for {target}")
    entry = runs[-1]
    entry["stopped_at"] = utc_now()
    run_dir = ws.subdir("runs") / target
    (run_dir / "stop.txt").write_text(
        f"stopped {target} at {entry['stopped_at']}\n", encoding="utf-8")
    (run_dir / "backup").mkdir(exist_ok=True)
    (run_dir / "checkins.txt").touch()
    entry["stop_path"] = str(run_dir / "stop.txt")
    ws.save(state)
    click.echo(f"run stopped for {target}; backup dir and checkins created")


# -- findings -----------------------------------------------------------------------

@cli.group()
@click.pass_obj
def findings(ws: Workspace) -> None:
    """Finding registration and classification (U-VERDICT-4)."""
    if not ws.exists():
        raise click.ClickException("run 'verdict init' first")


@findings.command("list")
@click.pass_obj
def findings_list(ws: Workspace) -> None:
    state = load_state(ws)
    if not state.findings:
        click.echo("  (no findings recorded)")
    for f in state.findings:
        classification = f.get("classification") or "unclassified"
        click.echo(
            f"  {f['finding_id']}: {f.get('target')} / {f.get('family')} "
            f"[{f.get('original_severity')}] -> {classification}"
        )


@findings.command("classify")
@click.argument("finding_id")
@click.option("--classification", "-c", required=True,
              type=click.Choice(("confirmed", "false_positive",
                                 "inconclusive")))
@click.option("--evidence", "-e", multiple=True,
              help="Re-test evidence path (repeatable)")
@click.option("--reason", "-r", default="",
              help="Required for false_positive and inconclusive")
@click.option("--severity", "severity_confirmed", default=None,
              type=click.Choice(("critical", "high", "medium", "low", "info")))
@click.option("--impact", "impact_confirmed", default=None,
              help="Required for confirmed")
@click.pass_obj
def findings_classify(ws: Workspace, finding_id: str,
                      classification: str, evidence: tuple[str, ...],
                      reason: str, severity_confirmed: str | None,
                      impact_confirmed: str | None) -> None:
    """Classify a finding after the manual re-test."""
    state = load_state(ws)
    classifier = FindingClassifier(state, ws)
    try:
        classifier.classify(
            finding_id, classification, list(evidence), reason,
            severity_confirmed, impact_confirmed,
        )
    except ClassificationError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"{finding_id} classified: {classification}")


@findings.command("register")
@click.argument("finding_id")
@click.argument("target")
@click.argument("family")
@click.option("--severity", required=True,
              type=click.Choice(("critical", "high", "medium", "low", "info")))
@click.option("--score", required=True, type=float,
              help="Original evidence score in [0, 1]")
@click.pass_obj
def findings_register(ws: Workspace, finding_id: str, target: str,
                      family: str, severity: str, score: float) -> None:
    """Register a finding produced by a run."""
    state = load_state(ws)
    classifier = FindingClassifier(state, ws)
    try:
        classifier.register(finding_id, target, family, severity, score)
    except ClassificationError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"finding registered: {finding_id}")


# -- analysis ---------------------------------------------------------------------

@cli.command()
@click.pass_obj
def analysis(ws: Workspace) -> None:
    """Show the classification batch summary and FP rate."""
    state = load_state(ws)
    classifier = FindingClassifier(state, ws)
    summary = classifier.batch_summary()
    for key, value in summary.items():
        click.echo(f"  {key}: {value}")


# -- selection ---------------------------------------------------------------------

@cli.command()
@click.argument("finding_ids", nargs=5, required=True)
@click.pass_obj
def select(ws: Workspace, finding_ids: tuple[str, ...]) -> None:
    """Freeze exactly 5 confirmed finding ids for submission."""
    state = load_state(ws)
    if state.selection:
        raise click.ClickException(
            "selection already frozen: "
            + ", ".join(state.selection)
            + "; the day-14 selection is immutable "
            "(Round-3 finding F-5)"
        )
    known = {f.get("finding_id"): f for f in state.findings}
    for fid in finding_ids:
        record = known.get(fid)
        if record is None:
            raise click.ClickException(f"unknown finding {fid!r}")
        if record.get("classification") != "confirmed":
            raise click.ClickException(
                f"{fid} is {record.get('classification') or 'unclassified'}; "
                "only confirmed findings can be selected"
            )
    state.selection = list(finding_ids)
    ws.save(state)
    click.echo("selection frozen: " + ", ".join(finding_ids))


# -- submissions ---------------------------------------------------------------------

@cli.group()
@click.pass_obj
def submit(ws: Workspace) -> None:
    """Submission pipeline (U-VERDICT-5): draft, review, record."""
    if not ws.exists():
        raise click.ClickException("run 'verdict init' first")


@submit.command("report")
@click.argument("finding_id")
@click.option("--title", default="")
@click.option("--summary", default="")
@click.option("--steps", default="")
@click.option("--remediation", default="")
@click.option("--program", default="")
@click.pass_obj
def submit_report(ws: Workspace, finding_id: str, title: str,
                  summary: str, steps: str, remediation: str,
                  program: str) -> None:
    """Generate the report draft for a confirmed finding."""
    state = load_state(ws)
    pipeline = SubmissionPipeline(state, ws)
    try:
        pipeline.write_report(finding_id, title=title, summary=summary,
                              steps=steps, remediation=remediation,
                              program=program)
    except SubmissionError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"draft written: submissions/{finding_id}.md — review it, "
               "then edit before submitting")


@submit.command("record")
@click.argument("finding_id")
@click.option("--platform-id", required=True,
              help="The id the platform assigned to the submission")
@click.option("--screenshot", required=True,
              type=click.Path(dir_okay=False),
              help="Evidence screenshot path (relative to the workspace)")
@click.option("--platform", default="hackerone")
@click.pass_obj
def submit_record(ws: Workspace, finding_id: str, platform_id: str,
                  screenshot: str, platform: str) -> None:
    """Record a MANUAL submission you already performed."""
    state = load_state(ws)
    pipeline = SubmissionPipeline(state, ws)
    try:
        pipeline.record_submission(finding_id, platform_id, screenshot,
                                   platform)
    except SubmissionError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"submission recorded: {finding_id} -> {platform_id}")


# -- watch ------------------------------------------------------------------------

@cli.group()
@click.pass_obj
def watch(ws: Workspace) -> None:
    """The 30-day watch window (days 16-45)."""
    if not ws.exists():
        raise click.ClickException("run 'verdict init' first")


@watch.command("start")
@click.pass_obj
def watch_start(ws: Workspace) -> None:
    """Open the watch period (requires at least one submission)."""
    state = load_state(ws)
    if not state.submissions:
        raise click.ClickException(
            "no submissions recorded; watch opens after submission day"
        )
    if state.watch_opened_at:
        click.echo("watch already open")
        return
    state.watch_opened_at = utc_now()
    tracker = ws.root / "watch" / "tracker.md"
    tracker.parent.mkdir(parents=True, exist_ok=True)
    if not tracker.exists():
        lines = ["# Watch Tracker", ""]
        for s in state.submissions:
            lines.append(
                f"- {s['finding_id']} ({s['platform_id']}): under_review"
            )
        tracker.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ws.save(state)
    click.echo("watch period opened")


@watch.command("update")
@click.argument("finding_id")
@click.argument("status", type=click.Choice(WATCH_STATUSES))
@click.option("--note", default="")
@click.pass_obj
def watch_update(ws: Workspace, finding_id: str, status: str,
                 note: str) -> None:
    """Record a platform response for a submission."""
    state = load_state(ws)
    if not state.watch_opened_at:
        raise click.ClickException("watch not open; run 'verdict watch start'")
    known = {s.get("finding_id") for s in state.submissions}
    if finding_id not in known:
        raise click.ClickException(f"no submission for {finding_id!r}")
    for entry in state.watch:
        if entry.get("finding_id") == finding_id:
            entry["status"] = status
            entry["updated_at"] = utc_now()
            if note:
                entry["note"] = note
            break
    else:
        state.watch.append({
            "finding_id": finding_id,
            "status": status,
            "updated_at": utc_now(),
            "note": note,
        })
    ws.save(state)
    click.echo(f"{finding_id}: {status}")


@watch.command("show")
@click.pass_obj
def watch_show(ws: Workspace) -> None:
    state = load_state(ws)
    if not state.watch:
        click.echo("  (no watch entries)")
    for entry in state.watch:
        click.echo(f"  {entry['finding_id']}: {entry['status']}")


# -- verdict ------------------------------------------------------------------------

@cli.group("verdict")
@click.pass_obj
def verdict(ws: Workspace) -> None:
    """Metrics and the final verdict (U-VERDICT-6)."""
    if not ws.exists():
        raise click.ClickException("run 'verdict init' first")


@verdict.command("final")
@click.pass_obj
def verdict_final(ws: Workspace) -> None:
    """Compute the final verdict and write the reports."""
    state = load_state(ws)
    if state.pre_registration_sha256:
        pre_reg = ws.root / "pre_registration.md"
        actual = (hashlib.sha256(pre_reg.read_bytes()).hexdigest()
                  if pre_reg.is_file() else None)
        if actual != state.pre_registration_sha256:
            raise click.ClickException(
                "pre_registration.md changed after the freeze "
                f"(recorded {state.pre_registration_sha256[:16]}…, "
                f"file now {str(actual)[:16] if actual else 'missing'}…); "
                "the verdict cannot be issued from tampered "
                "pre-registration (Round-3 finding F-3). Restore the "
                "file or restart the workspace"
            )
    calculator = VerdictCalculator()
    metrics = calculator.compute(state)
    outcome, reasoning = calculator.final_verdict(metrics)
    verdict_dir = ws.subdir("verdict")
    (verdict_dir / "metrics_report.md").write_text(
        calculator.generate_report(metrics), encoding="utf-8")
    final = {
        "outcome": outcome,
        "reasoning": reasoning,
        "computed_at": utc_now(),
        "metrics": metrics.to_dict(),
    }
    state.final_verdict = final
    ws.save(state)
    (verdict_dir / "final_verdict.md").write_text(
        f"# Final Verdict\n\n**{outcome}** — {reasoning}\n\n"
        "See metrics_report.md for the full computation.\n",
        encoding="utf-8",
    )
    click.echo(f"final verdict: {outcome} — {reasoning}")


@verdict.command("show")
@click.pass_obj
def verdict_show(ws: Workspace) -> None:
    """Print the metrics report without recording anything."""
    state = load_state(ws)
    metrics = VerdictCalculator().compute(state)
    click.echo(VerdictCalculator().generate_report(metrics, state))


# -- export -----------------------------------------------------------------------

@cli.command()
@click.pass_obj
def export(ws: Workspace) -> None:
    """Write the full export (state + metrics) into export/."""
    state = load_state(ws)
    calculator = VerdictCalculator()
    metrics = calculator.compute(state)
    out_dir = ws.subdir("export")
    json_path = out_dir / "verdict_export.json"
    json_path.write_text(
        json.dumps({
            "state": {
                k: v for k, v in state.__dict__.items() if k != "days"
            },
            "days": state.days,
            "metrics": metrics.to_dict(),
        }, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    (out_dir / "verdict_report.md").write_text(
        calculator.generate_report(metrics), encoding="utf-8")
    click.echo(f"exported: {json_path}")


def main() -> None:  # pragma: no cover — console entry point
    try:
        cli()
    except click.ClickException as exc:
        exc.show()
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main()
