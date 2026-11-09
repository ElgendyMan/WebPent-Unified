# src/webpent/cli/commands.py
"""webpent.cli.commands

Professional CLI for the WebPent Framework V4.5 using Typer + Rich.

Restored during the v10/v61 -> GOED v1.8.4 canonical merge: this module used
to live directly at ``webpent/cli/__init__.py`` (webpent-v61 line). It was
found reduced to a trivial OPTIONAL_LAYER availability stub with no
replacement anywhere in the GOED v1.8.4 tree, silently breaking the
`webpent` console script and every CLI command. Relocated here (unchanged
apart from this note and the header comment) to match the OPTIONAL_LAYER
package-init convention used consistently elsewhere in this codebase
(api/, graph/, agents/, shared/, state/, workers/), while keeping the CLI
itself fully functional. See RECONCILIATION_REPORT.md for details.

Usage (the unified entry point — the retired scan/hunt-auto/hunt-plan
aliases were removed in the v0.32.0 window, declared 2026-11-01):
    webpent hunt --url https://t.com --mode standard \\
        --authorization <ref>
    webpent hunt --url https://t.com --mode quick --authorization <ref>
    webpent hunt --url https://t.com --mode deep --authorization <ref>
    webpent preflight
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from uuid import uuid4

import typer
from rich.console import Console
from rich.table import Table

from webpent.api.scan_registry import (
    get_thread_ids_by_engagement_id,
)
from webpent.cli.apex import apex_app
from webpent.cli.cem import cem_app
from webpent.cli.doctor import register_doctor  # Track 8.4/3.6 (2026-10-29)
from webpent.cli.dojo import dojo_app
from webpent.cli.econ import econ_app
from webpent.cli.jc import jc_app
from webpent.cli.loaders import load_creds_file
from webpent.cli.oracle import oracle_app
from webpent.cli.ops import ops_app  # Track 12 ops (2026-10-28, read-only)
from webpent.cli.prism import prism_app
from webpent.cli.retest import retest_app  # Track 11 item 7 (2026-10-28)
# M1-C (UM-DR-12): ق10 bounty pipeline + ق11 fleet portfolio operator
# surfaces (M1_READINESS_REVIEW §5.5 — preview/order only; nothing sends,
# launches, or mutates campaigns from these commands).
from webpent.cli.bounty import bounty_app  # M1-C ق10 bounty preview surface
from webpent.cli.portfolio import portfolio_app  # M1-C ق11 fleet wave surface
from webpent.config.settings import get_settings
from webpent.llm_researcher.key_pool import KeyPool
from webpent.llm_researcher.task_router import TaskRouter
from webpent.memory.db import get_db_manager
from webpent.memory.knowledge_ingest import knowledge_search, knowledge_status, update_knowledge
from webpent.memory.vectorstore import get_vector_store_manager
from webpent.reporter.bounty_report import generate_bounty_reports
from webpent.service.facade import MultiCampaignService
from webpent.service.models import CampaignSpec
from webpent.shared.action_ledger import SQLiteActionLedger
from webpent.shared.finding_aggregation import aggregate_findings

app = typer.Typer(
    name="webpent",
    help="WebPent Framework V4.5 — Autonomous Pentesting with HITL & RAG",
    no_args_is_help=True,
)
llm_app = typer.Typer(name="llm", help="LLM provider and routing diagnostics.", no_args_is_help=True)

# UNIFIED MERGE (2026-11-02, Phase 2 P2b-3): operator CLI over the
# campaign scheduler's store/state API. The commands are thin glue:
# every safety rule (flag gate, kill switch, scope re-check, caps,
# atomic state) lives in webpent.scheduler.campaign_scheduler and is
# NOT re-implemented here. Exit code 2 + a named reason on the two
# fail-closed configuration refusals.
scheduler_app = typer.Typer(
    name="scheduler",
    help="Operator controls for scheduled campaigns (flag-gated).",
    no_args_is_help=True,
)
app.add_typer(scheduler_app)


def _scheduler_paths() -> tuple[Path, Path]:
    from webpent.config.settings import get_settings

    settings = get_settings()
    if not settings.enable_scheduler:
        typer.secho(
            "scheduler disabled: enable_scheduler is off",
            err=True,
        )
        raise typer.Exit(code=2)
    raw_path = str(settings.scheduler_state_path or "").strip()
    if not raw_path:
        typer.secho(
            "scheduler_state_path is not configured; refusing to run "
            "(fail-closed)",
            err=True,
        )
        raise typer.Exit(code=2)
    base = Path(raw_path).expanduser()
    return base / "schedules.jsonl", base / "state.json"


def _default_scheduler_runner(campaign: Any, state: Any) -> Any:
    """Launch one wake through the production service facade.

    The facade's registry is the same entrypoint `campaign start`
    uses; a scheduled campaign the operator has not registered there
    is a runner error — reported by the wake loop, never silently
    dropped, and retried on the next wake.
    """
    from webpent.scheduler.campaign_scheduler import RunOutcome
    from webpent.service.facade import MultiCampaignService

    result = MultiCampaignService().start(campaign.campaign_id)
    return RunOutcome(
        completed=True,
        detail=json.dumps(result, sort_keys=True, default=str)[:400],
    )


@scheduler_app.command("add")
def scheduler_add(
    campaign_id: str = typer.Option(..., "--campaign-id"),
    target_ref: str = typer.Option(..., "--target-ref"),
    schedule: str = typer.Option("once", "--schedule"),
    start_at: str = typer.Option(..., "--start-at"),
    budget_usd_cap: float = typer.Option(0.0, "--budget-usd-cap"),
    wallclock_minutes_cap: float = typer.Option(
        60.0, "--wallclock-minutes-cap"
    ),
    max_findings_cap: int = typer.Option(50, "--max-findings-cap"),
) -> None:
    """Schedule a campaign ahead of time (one append-only record)."""
    from webpent.scheduler.campaign_scheduler import (
        CampaignScheduleStore,
        ScheduledCampaign,
    )

    store_path, _ = _scheduler_paths()
    campaign = ScheduledCampaign(
        campaign_id=campaign_id,
        target_ref=target_ref,
        schedule=schedule,
        start_at=start_at,
        budget_usd_cap=budget_usd_cap,
        wallclock_minutes_cap=wallclock_minutes_cap,
        max_findings_cap=max_findings_cap,
    )
    CampaignScheduleStore(store_path).add(campaign)
    typer.secho(
        f"scheduled {campaign.campaign_id} ({campaign.schedule}, "
        f"start {campaign.start_at})"
    )


@scheduler_app.command("list")
def scheduler_list() -> None:
    """List scheduled campaigns with their next due time."""
    from webpent.scheduler.campaign_scheduler import (
        CampaignScheduleStore,
        SchedulerStateFile,
    )

    store_path, state_path = _scheduler_paths()
    store = CampaignScheduleStore(store_path)
    state_file = SchedulerStateFile(state_path)
    for campaign in store.list():
        state = state_file.get(campaign.campaign_id)
        next_due = state.next_due if state is not None else (
            campaign.start_at)
        typer.secho(
            f"{campaign.campaign_id} schedule={campaign.schedule} "
            f"target={campaign.target_ref} next_due={next_due} "
            f"status={state.status if state is not None else 'scheduled'}"
        )


@scheduler_app.command("run-due")
def scheduler_run_due(
    now: str = typer.Option("", "--now"),
) -> None:
    """Wake every due campaign within its caps (no daemon)."""
    from webpent.scheduler.campaign_scheduler import (
        CampaignScheduleStore,
        SchedulerStateFile,
        parse_iso_utc,
        run_due_campaigns,
    )

    store_path, state_path = _scheduler_paths()
    report = run_due_campaigns(
        CampaignScheduleStore(store_path),
        SchedulerStateFile(state_path),
        runner=_default_scheduler_runner,
        now=parse_iso_utc(now) if now.strip() else None,
    )
    for entry in report.woken:
        typer.secho(
            f"woke {entry.get('campaign_id')} "
            f"action={entry.get('action', 'run')}"
            + (
                f" stop_reason={entry.get('stop_reason')}"
                if entry.get("stop_reason")
                else ""
            )
            + (
                f" detail={entry.get('detail')}"
                if entry.get("detail")
                else ""
            )
        )
    for entry in report.skipped:
        typer.secho(
            f"skipped {entry.get('campaign_id')} "
            f"reason={entry.get('reason')} "
            f"next_due={entry.get('next_due')}"
        )
llm_keys_app = typer.Typer(name="keys", help="Manage local LLM provider keys safely.", no_args_is_help=True)
def _load_build_info() -> dict[str, Any]:
    """Read the build provenance record (BUILD_INFO.json).

    Resolved relative to the project root (the src/ layout's third
    parent) with a cwd fallback for wheel installs; missing or corrupt
    records degrade to an empty dict — the command still exits 0 and
    prints what it knows. pyproject.toml remains the version SSOT;
    this file is the legacy delivery-provenance label.
    """
    for base in (Path(__file__).resolve().parents[3], Path.cwd()):
        candidate = base / "BUILD_INFO.json"
        if candidate.is_file():
            try:
                data = json.loads(
                    candidate.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
            except (OSError, ValueError):
                continue
    return {}


def _version_callback(value: bool) -> None:
    if value:
        info = _load_build_info()
        build = str(info.get("build_name") or "webpent (dev)")
        Console().print(f"webpent {build}")
        raise typer.Exit()


# UNIFIED MERGE (2026-11-02, Phase 2 P2-1): root self-identification
# contract (tests/test_r4_production_hardening.py,
# TestCliSelfIdentification) — --version and --build-info on the root
# command, both fail-open on missing provenance data (they print what
# they know and exit 0; they are read-only diagnostics).
@app.callback(invoke_without_command=True)
def _root_callback(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the webpent build identity and exit.",
    ),
    build_info: bool = typer.Option(
        False,
        "--build-info",
        help="Print the full build provenance record (BUILD_INFO.json).",
    ),
) -> None:
    """WebPent Framework root command."""
    if build_info:
        Console().print_json(
            json.dumps(_load_build_info(), sort_keys=True))
        raise typer.Exit()


app.add_typer(llm_app)
llm_app.add_typer(llm_keys_app)
knowledge_app = typer.Typer(name="knowledge", help="Manage bounded payload and WSTG advisory knowledge.", no_args_is_help=True)
app.add_typer(knowledge_app)
campaign_app = typer.Typer(name="campaign", help="Operator controls for running campaigns.")
app.add_typer(campaign_app)
app.add_typer(cem_app)
app.add_typer(econ_app)
app.add_typer(jc_app)
app.add_typer(dojo_app)
app.add_typer(apex_app, name="apex")
app.add_typer(oracle_app, name="oracle")
app.add_typer(prism_app, name="prism")
# Track 11 item 7 (2026-10-28): controlled retest of previous findings.
app.add_typer(retest_app, name="retest")
# Track 12 ops (2026-10-28): read-only operations surface (governor,
# workers, graph, calibration, protection posture).
app.add_typer(ops_app, name="ops")
# M1-C (UM-DR-12): ق10/ق11 operator surfaces — bounty previews from
# promoted ProofBundles only (no submit), portfolio wave ORDERING only
# (no launches). Both fail-closed and network-free.
app.add_typer(bounty_app, name="bounty")
app.add_typer(portfolio_app, name="portfolio")
# Track 8.4/3.6 (2026-10-29): the ONE `webpent doctor` command (DB + LLM
# + external tools). Closes the dangling references in README/install.sh
# and the docker-compose quickstart banner.
register_doctor(app)
console = Console()
err_console = Console(stderr=True)


@llm_keys_app.command("status")
def llm_keys_status(
    as_json: bool = typer.Option(False, "--json", help="Render redacted JSON."),
) -> None:
    """Show provider health without exposing key values."""
    pool = KeyPool.load()
    payload = {"providers": pool.status(), "routing": TaskRouter(pool).diagnostics()}
    if as_json:
        console.print_json(json.dumps(payload, sort_keys=True, default=str))
        return
    table = Table(title="LLM provider health")
    for column in ("Provider", "Model", "Status", "Priority", "Key"):
        table.add_column(column)
    for row in payload["providers"]:
        table.add_row(
            str(row["provider"]), str(row["model"]), str(row["status"]),
            str(row["priority"]), str(row["key_fingerprint"]),
        )
    console.print(table)
    console.print(f"Configured providers: {', '.join(pool.providers()) or '(none)'}")


@llm_keys_app.command("add")
def llm_keys_add(
    provider: str = typer.Argument(...),
    model: str = typer.Argument(...),
    env_var: str = typer.Option(..., "--env-var", help="Environment variable holding the secret."),
    config_path: Path = typer.Option(Path(".llm_keys.json"), "--config"),
) -> None:
    """Register an environment-variable reference in the ignored local config."""
    if not env_var.isidentifier() or env_var.upper() != env_var:
        err_console.print("[red]env-var must be an uppercase environment variable name[/red]")
        raise typer.Exit(2)
    path = config_path.expanduser()
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"providers": []}
    providers = data.setdefault("providers", [])
    provider_entry = next((p for p in providers if p.get("name") == provider), None)
    if provider_entry is None:
        provider_entry = {"name": provider, "api_key": env_var, "models": []}
        providers.append(provider_entry)
    else:
        provider_entry["api_key"] = env_var
    models = provider_entry.setdefault("models", [])
    if not any((m.get("id") if isinstance(m, dict) else m) == model for m in models):
        models.append({"id": model, "role": "general"})
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    console.print(f"Registered {provider}/{model} using {env_var}; secret value was not read or printed.")


@llm_keys_app.command("remove")
def llm_keys_remove(
    provider: str = typer.Argument(...),
    config_path: Path = typer.Option(Path(".llm_keys.json"), "--config"),
) -> None:
    """Remove a provider entry from the ignored local config."""
    path = config_path.expanduser()
    if not path.exists():
        console.print("No local key file exists.")
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    before = len(data.get("providers", []))
    data["providers"] = [p for p in data.get("providers", []) if p.get("name") != provider]
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    console.print(f"Removed {before - len(data['providers'])} provider entry/entries for {provider}.")


@llm_keys_app.command("test")
def llm_keys_test() -> None:
    """Probe the first configured route with a fixed, non-target prompt."""
    from webpent.shared.llm import TaskType, get_llm, get_llm_usage_trace, llm_usage_scope

    try:
        with llm_usage_scope():
            runnable = get_llm(TaskType.GENERAL, prompt="Return the number 4")
            response = runnable.invoke("Return the number 4")
            usage = get_llm_usage_trace()
        console.print_json(json.dumps({
            "status": "ok",
            "response_received": response is not None,
            "usage": usage,
        }, default=str))
    except Exception as exc:
        console.print_json(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        raise typer.Exit(1) from exc


@knowledge_app.command("update")
def knowledge_update(
    payload_root: Path = typer.Option(Path("/tmp/payloads"), "--payload-root"),
    wstg_root: Path = typer.Option(Path("/tmp/wstg"), "--wstg-root"),
    docs_dir: Path = typer.Option(Path("docs"), "--docs-dir"),
    provenance_file: Path = typer.Option(Path("docs/payload_wstg_evidence/source_provenance.json"), "--provenance"),
) -> None:
    """Parse pinned sources and idempotently ingest advisory knowledge."""
    if not payload_root.exists() or not wstg_root.exists():
        err_console.print("[red]Source roots are missing; run the pinned source setup first.[/red]")
        raise typer.Exit(2)
    provenance = json.loads(provenance_file.read_text(encoding="utf-8")) if provenance_file.exists() else {}
    result = update_knowledge(payload_root, wstg_root, docs_dir, manager=get_vector_store_manager(), provenance=provenance)
    console.print_json(json.dumps(result, sort_keys=True, default=str))


@knowledge_app.command("status")
def knowledge_status_command(
    docs_dir: Path = typer.Option(Path("docs"), "--docs-dir"),
) -> None:
    """Show parsed source versions and counts."""
    console.print_json(json.dumps(knowledge_status(docs_dir), sort_keys=True, default=str))


@knowledge_app.command("search")
def knowledge_search_command(
    query: str = typer.Argument(...),
    docs_dir: Path = typer.Option(Path("docs"), "--docs-dir"),
    limit: int = typer.Option(10, "--limit", min=1, max=50),
) -> None:
    """Search local bounded payload/WSTG projections."""
    console.print_json(json.dumps(knowledge_search(query, docs_dir, limit), sort_keys=True, default=str))


@campaign_app.command("halt")
def halt_campaign(
    campaign_id: str = typer.Argument(..., help="Engagement/campaign identifier."),
) -> None:
    """Request a cooperative stop after the current action completes.

    U-3 (RA-2 RSTU) truth-source unification: halt routed through service first.
    """
    service = _service()
    try:
        service.halt(campaign_id, "cli")
    except KeyError:
        # Older standalone scans do not have a service campaign row. Keep their
        # documented kill-switch path, but never use it for service campaigns.
        ledger = SQLiteActionLedger(get_settings().action_ledger_path)
        if not ledger.request_halt(campaign_id, "cli"):
            err_console.print("[red]Unable to persist campaign halt request.[/red]")
            raise typer.Exit(1)
    except (RuntimeError, ValueError) as exc:
        err_console.print(f"[red]Unable to halt campaign:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(f"Campaign {campaign_id} halt requested; current action will finish safely.")


def _service() -> MultiCampaignService:
    return MultiCampaignService(root=os.getenv("WEBPENT_SERVICE_ROOT", "/tmp/webpent-service"),
                                project_root=Path.cwd())


@campaign_app.command("plan")
def plan_service_campaign(
    campaign_id: str = typer.Argument(...),
    target_url: str = typer.Option(..., "--target-url"),
    budget: float = typer.Option(10.0, "--budget", min=0.01),
    max_actions: int = typer.Option(100, "--max-actions", min=1),
    retry_limit: int = typer.Option(2, "--retry-limit", min=0, max=10),
) -> None:
    """Create an isolated PLANNED service campaign."""
    try:
        result = _service().plan(CampaignSpec(campaign_id, target_url, budget_limit=budget,
                                               max_actions=max_actions, retry_limit=retry_limit))
    except (ValueError, KeyError) as exc:
        err_console.print(f"[red]Unable to plan campaign:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print_json(json.dumps(result))


@campaign_app.command("start")
def start_service_campaign(campaign_id: str = typer.Argument(...)) -> None:
    """Start one isolated service campaign."""
    try:
        console.print_json(json.dumps(_service().start(campaign_id)))
    except (ValueError, KeyError) as exc:
        err_console.print(f"[red]Unable to start campaign:[/red] {exc}")
        raise typer.Exit(1) from exc


@campaign_app.command("resume")
def resume_service_campaign(campaign_id: str = typer.Argument(...)) -> None:
    """Resume one operator-halted service campaign."""
    try:
        console.print_json(json.dumps(_service().resume(campaign_id)))
    except (ValueError, KeyError) as exc:
        err_console.print(f"[red]Unable to resume campaign:[/red] {exc}")
        raise typer.Exit(1) from exc


@campaign_app.command("status")
def service_campaign_status(campaign_id: str = typer.Argument(...)) -> None:
    """Show redacted state, budget, and pipeline metrics for one campaign."""
    try:
        console.print_json(json.dumps(_service().dashboard(campaign_id)))
    except KeyError as exc:
        err_console.print(f"[red]Campaign not found:[/red] {exc}")
        raise typer.Exit(1) from exc


@campaign_app.command("cost")
def service_campaign_cost(campaign_id: str = typer.Argument(...)) -> None:
    """Show action-ledger spend, LLM usage, and lifecycle cost metrics."""
    try:
        console.print_json(json.dumps(_service().costs.snapshot(campaign_id).as_dict()))
    except KeyError as exc:
        err_console.print(f"[red]Campaign not found:[/red] {exc}")
        raise typer.Exit(1) from exc


@campaign_app.command("health")
def service_health_check() -> None:
    """Run the five security gates and print redacted health results."""
    service = _service()
    results = [item.as_dict() for item in service.health.run()]
    console.print_json(json.dumps(results))


def _parse_credentials(creds: str | None) -> dict[str, str]:
    """Parse a 'user:pass' string into a credentials dict."""
    if not creds:
        return {}
    if ":" not in creds:
        err_console.print("[red]Error:[/red] Credentials must be in 'user:pass' format.")
        raise typer.Exit(1)
    parts = creds.split(":", 1)
    return {"username": parts[0], "password": parts[1]}


def _load_hunter_principals(raw_json: str | None, path: Path | None) -> dict[str, dict[str, Any]] | None:
    """Load runtime-only named principals without echoing secret values."""
    if raw_json and path:
        err_console.print("[red]Use only one of --credentials or --credentials-file.[/red]")
        raise typer.Exit(2)
    if path:
        try:
            loaded = load_creds_file(path)
        except (OSError, TypeError, ValueError) as exc:
            err_console.print(f"[red]Unable to load principal credentials:[/red] {type(exc).__name__}")
            raise typer.Exit(2) from exc
        if isinstance(loaded, dict) and "username" in loaded:
            return {"owner": dict(loaded)}
        return {str(name): dict(profile) for name, profile in loaded.items() if isinstance(profile, dict)}
    if not raw_json:
        return None
    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        err_console.print(f"[red]--credentials must be valid JSON:[/red] {exc.msg}")
        raise typer.Exit(2) from exc
    if not isinstance(payload, dict) or not payload:
        err_console.print("[red]--credentials must be a non-empty JSON object.[/red]")
        raise typer.Exit(2)
    if "username" in payload or "credentials" in payload or "password" in payload:
        return {"owner": payload}
    principals = {str(name): value for name, value in list(payload.items())[:32] if isinstance(value, dict)}
    if not principals or len(principals) != len(payload):
        err_console.print("[red]--credentials must map principal aliases to JSON objects.[/red]")
        raise typer.Exit(2)
    return principals


def _parse_cookies(cookies: str | None) -> dict[str, str]:
    """Parse a 'name1=value1; name2=value2' string into a session-cookie dict.

    Same format as a browser/curl 'Cookie:' header value, so operators
    can paste it directly from DevTools. Mirrors the API's
    ``ScanRequest.session_cookies`` field (``dict[str, str]``) — see
    ``api/app.py``. Threaded into ``initial_state["session_cookies"]``,
    where ``auth_node`` picks it up, validates it, and (if valid) skips
    Playwright login — same precedence as the API path.
    """
    if not cookies:
        return {}
    result: dict[str, str] = {}
    for pair in cookies.split(";"):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            err_console.print(
                f"[red]Error:[/red] Malformed --cookies segment '{pair}' — "
                "expected 'name=value' pairs separated by ';'."
            )
            raise typer.Exit(1)
        name, value = pair.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            err_console.print(f"[red]Error:[/red] Empty cookie name in --cookies segment '{pair}'.")
            raise typer.Exit(1)
        result[name] = value
    return result


def _chain_honesty_verdict(final_state: dict[str, Any] | None) -> str | None:
    """WP-I (Dispatch #009-A): chain-completeness verdict for the graph path.

    Returns ``None`` when the research chain executed end-to-end, otherwise
    a short operator-facing reason string. The research-campaign lane's
    markers are the chain-completeness authority on the graph path (the
    ``_production_trace`` in final state is the RECON-stage resolver
    snapshot by construction — the lane re-derives a fresh orchestrator per
    M2-impl WP-B/WP-C, and its execution evidence lives in the lane
    markers). Fail-closed: a missing/unreadable marker set counts as a
    short-circuit — absence of evidence of completeness is not
    completeness (NF-L0-01 / D-J).
    """
    state = final_state if isinstance(final_state, dict) else {}
    skip_marker = state.get("research_campaign_skipped")
    if skip_marker:
        return f"research chain short-circuited: {skip_marker}"
    if not bool(state.get("research_campaign_executed")):
        return (
            "research chain short-circuited: research campaign did not "
            "execute (no executed-marker on the final state)"
        )
    return None


def _enforce_chain_honesty(
    trace_summary: dict[str, Any] | None, *, surface: str, pointer: str,
    terminal_summary: dict[str, Any] | None = None,
) -> None:
    """WP-I (Dispatch #009-A): exit-code honesty for direct-spine surfaces.

    An incomplete production trace is a FAILED run (NF-L0-01 / D-J): a
    dead or short-circuited chain must never be indistinguishable from a
    clean no-findings scan (Ruling R7 extended to exit-code semantics).
    Fail-closed: a missing trace counts as incomplete.
    U-3 (RA-2 RSTU): terminal_summary carries the D-S matrix projection.
    """
    trace = trace_summary if isinstance(trace_summary, dict) else {}
    if trace.get("complete") is True:
        summary = terminal_summary if isinstance(terminal_summary, dict) else {}
        for field in ("terminal_complete", "terminal", "terminal_state", "terminal_status", "completed", "complete"):
            if field not in summary:
                continue
            value = summary[field]
            if isinstance(value, dict):
                if value.get("complete") is False or value.get("completed") is False:
                    raise typer.Exit(1)
                value = value.get("status", value.get("state", value.get("value")))
            if value is False or str(value).strip().lower() in {"failed", "incomplete", "aborted", "halted"}:
                err_console.print(
                    f"[red]{surface} FAILED — explicit terminal marker is incomplete[/red] "
                    f"(field: {field}). Trace: {pointer}"
                )
                raise typer.Exit(1)
        return
    missing = ", ".join(
        str(item) for item in (trace.get("missing_required_stages") or [])
    )
    err_console.print(
        f"[red]{surface} FAILED — production trace incomplete[/red] "
        f"(missing required stages: {missing or 'trace absent/unproven'}). "
        "The chain did not execute end-to-end; this is NOT a clean "
        f"no-findings scan. Trace: {pointer}"
    )
    raise typer.Exit(1)


def _perform_preflight_check() -> bool:
    """Launch Playwright Chromium once to verify availability.

    Returns True if the browser launches successfully, False otherwise.
    """
    console.print("[dim]Pre-flight: Checking Playwright Chromium...[/dim]")
    try:
        from playwright.sync_api import sync_playwright

        pw = sync_playwright().start()
        browser = pw.chromium.launch(headless=True)
        browser.close()
        pw.stop()
        console.print("[green]✓ Playwright Chromium available.[/green]")
        return True
    except Exception as exc:
        console.print(
            f"[yellow]⚠ Playwright unavailable: {exc}[/yellow]\n"
            "[dim]  Execution sandbox will be skipped gracefully.[/dim]"
        )
        return False


@app.command()
def preflight() -> None:
    """Run pre-flight health checks for all tools and Playwright."""
    console.print("[bold blue]WebPent V4.5 — Pre-flight Health Check[/bold blue]\n")

    # Playwright
    pw_ok = _perform_preflight_check()

    # External tools
    import shutil

    # V8 FIX: check for httpx-pd (the Go ProjectDiscovery tool), not
    # httpx (which resolves to the Python httpx CLI after pip install).
    tools = ["nuclei", "subfinder", "httpx-pd", "katana", "dalfox", "sqlmap"]
    table = Table(title="Tool Availability", border_style="grey50", header_style="bold cyan")
    table.add_column("Tool", width=15)
    table.add_column("Status", width=10)

    for tool in tools:
        if shutil.which(tool):
            table.add_row(tool, "[green]✓ Available[/green]")
        else:
            table.add_row(tool, "[red]✗ Missing[/red]")

    console.print(table)

    try:
        from webpent.shared.preflight import _check_llm_providers

        llm_status = _check_llm_providers()
        llm_table = Table(
            title="LLM Provider Status", border_style="grey50", header_style="bold cyan"
        )
        llm_table.add_column("Setting", width=24)
        llm_table.add_column("Value")
        llm_table.add_row("LLM enabled", str(llm_status.get("enabled", False)))
        llm_table.add_row("Status", str(llm_status.get("status", "unknown")))
        providers = llm_status.get("configured_providers") or []
        llm_table.add_row("Configured providers", ", ".join(map(str, providers)) or "None")
        dead = llm_status.get("dead_providers") or []
        llm_table.add_row("Circuit-breaker dead", ", ".join(map(str, dead)) or "None")
        chains = llm_status.get("fallback_chains") or {}
        chain_text = "; ".join(
            f"{task}: {' -> '.join(models) if models else 'deterministic'}"
            for task, models in chains.items()
        )
        llm_table.add_row("Fallback chains", chain_text or "deterministic")
        console.print(llm_table)
    except Exception as exc:
        console.print(f"[yellow]LLM diagnostics unavailable: {type(exc).__name__}[/yellow]")

    if not pw_ok:
        console.print("\n[yellow]⚠ Playwright is disabled — sandbox will skip gracefully.[/yellow]")


def main() -> None:
    """Entry point for the webpent CLI."""
    # Sprint I-1, item 1.3: fail-closed startup gate — refuses to start
    # when WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY is set
    # in a qualification/staging/production deployment.
    from webpent.shared.preflight import enforce_construction_escape_gate
    enforce_construction_escape_gate()
    app()


if __name__ == "__main__":
    main()


# V55 Phase 8: additive, manifest-backed CLI surface. The original `scan`
# command remains unchanged; these commands are local/read-only by default.
scope_app = typer.Typer(
    name="scope",
    help="Manage validated, versioned engagement scope entries.",
    no_args_is_help=True,
)
app.add_typer(scope_app, name="scope")


def _manifest_or_exit(value: str) -> tuple[Path, dict[str, Any]]:
    from webpent.cli.manifest import load_manifest

    try:
        return load_manifest(value)
    except ValueError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc


@app.command("init")
def init_engagement(
    name: str | None = typer.Argument(
        None, help="Engagement name (omit to start the interactive first-run wizard)."
    ),
    manifest: str = typer.Option(
        "webpent-engagement.json", "--manifest", "-f", help="Manifest output path."
    ),
) -> None:
    """Create a versioned local engagement manifest without secrets.

    Ultimate plan 2026-10-27, proposal 13: with NO arguments this runs
    the interactive first-run wizard — it asks for the target URL (with
    an immediate reachability check), the MANDATORY written-authorization
    confirmation, the hunt mode, and an optional LLM provider — then
    prints the ready-to-copy `webpent hunt` command instead of running
    the campaign itself (you learn the correct syntax for next time).
    With a NAME argument it keeps the pre-plan manifest behavior.
    """
    if name is None:
        _run_interactive_init()
        return
    from webpent.cli.manifest import default_manifest, manifest_path, save_manifest

    path = manifest_path(manifest)
    if path.exists():
        err_console.print(f"[red]Error:[/red] manifest already exists: {path}")
        raise typer.Exit(1)
    try:
        save_manifest(path, default_manifest(name))
    except (OSError, TypeError, ValueError) as exc:
        err_console.print(f"[red]Error:[/red] cannot create manifest: {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Created engagement manifest:[/green] {path}")


def _run_interactive_init() -> None:
    """Interactive first-run wizard (Ultimate plan, proposal 13).

    Asks, in order, with immediate validation of every answer:
      1. target URL (reachability-checked via the hardened HTTP client,
         offline-tolerant — a failed check warns but continues),
      2. MANDATORY written-authorization confirmation (the wizard exits
         without it — same posture as --authorization),
      3. hunt mode (quick/standard/deep),
      4. optional LLM provider setup pointer.
    Prints the ready-to-copy command; NEVER runs the campaign itself.
    """

    console.print("\n[bold]WebPent init — الإعداد الموجه لأول حملة[/bold]\n")
    console.print("جاوب على ٤ أسئلة وهيطلعلك الأمر الجاهز للنسخ.\n")

    # 1) Target URL with immediate validation.
    target_url = ""
    while not target_url:
        try:
            answer = typer.prompt("1) URL الهدف (مصرَّح لك باختباره)").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[yellow]تم الإلغاء.[/yellow]")
            raise typer.Exit(0) from None
        if not answer.startswith(("http://", "https://")):
            console.print("[red]لازم يبدأ بـ http:// أو https://[/red]")
            continue
        target_url = answer
    reachability = _interactive_reachability_check(target_url)
    if reachability is False:
        console.print(
            "[yellow]⚠[/yellow] المش ما بيردش دلوقتي — تقدر تكمّل وتشغل الحملة لما يبقى متاح."
        )

    # 2) MANDATORY authorization confirmation.
    console.print(
        "\n[bold]2) التفويض:[/bold] WebPent بيفحص أهداف مصرَّح لك بها فقط."
    )
    confirmed = typer.confirm(
        "أؤكد إن عندي تصريح كتابي باختبار هذا الهدف", default=False
    )
    if not confirmed:
        console.print(
            "[red]تم الإيقاف:[/red] التأكيد إلزامي. WebPent لا يعمل ضد أهداف دون تفويض."
        )
        raise typer.Exit(1)

    # 3) Mode.
    console.print(
        "\n[bold]3) وضع الفحص:[/bold]  quick (دقائق) | standard (متوازن — موصى به) | deep (شامل)"
    )
    mode = ""
    while mode not in {"quick", "standard", "deep"}:
        try:
            mode = typer.prompt("الوضع", default="standard").strip().lower()
        except (EOFError, KeyboardInterrupt):
            mode = "standard"
            break
        if mode not in {"quick", "standard", "deep"}:
            console.print("[red]اختر quick أو standard أو deep[/red]")

    # 4) Optional LLM pointer (no secret input here — keys live in the
    #    project key store, never in this wizard).
    console.print(
        "\n[bold]4) LLM (اختياري):[/bold] المسار الحتمي يشتغل بدون مفتاح."
        " لو عايز تحليل LLM: webpent llm-keys add anthropic"
    )

    auth_ref = f"confirmed-in-init-{target_url.split('//', 1)[-1][:40]}"
    command = (
        f"webpent hunt --url {target_url} --mode {mode} --authorization \"{auth_ref}\""
    )
    console.print("\n[bold green]الأمر الجاهز للنسخ:[/bold green]")
    console.print(f"  [bold]{command}[/bold]\n")
    console.print(
        "شغّله لما تكون جاهز — الـ init نفسه مش بيبدأ أي حملة "
        "(بتتعلم الصيغة الصحيحة للمرة الجاية)."
    )


def _interactive_reachability_check(target_url: str) -> bool | None:
    """Best-effort reachability probe via the hardened HTTP client.

    Returns True (reachable), False (definitely refused/errored), or
    None (check unavailable — offline/test environment). Never raises;
    never stores the response. Uses the project's SSRF-pinned client so
    even this pre-flight honors the transport boundary — G-02: the only
    httpx in this function is the boundary module's OWN pinned httpx
    (referenced as an attribute for the exception types); no direct
    transport import is added to this file.
    """
    try:
        from webpent.shared import http as http_boundary
        from webpent.shared.http import make_safe_httpx_client
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        return None
    try:
        with make_safe_httpx_client(follow_redirects=False, timeout=5.0) as client:
            response = client.head(target_url)
        if response.status_code < 500:
            console.print(f"[green]✓[/green] الهدف بيرد (HTTP {response.status_code})")
            return True
        console.print(f"[yellow]![/yellow] الهدف رجّع HTTP {response.status_code}")
        return False
    except (http_boundary.httpx.HTTPError, OSError, ValueError, TypeError):
        return None


@scope_app.command("add")
def scope_add(
    value: str = typer.Argument(..., help="In-scope HTTP(S) URL without credentials."),
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
) -> None:
    """Add one normalized, scope-validated URL to an engagement manifest."""
    from webpent.cli.manifest import add_scope_entry, save_manifest

    path, document = _manifest_or_exit(manifest)
    try:
        entry = add_scope_entry(document, value)
        save_manifest(path, document)
    except (OSError, TypeError, ValueError) as exc:
        err_console.print(f"[red]Error:[/red] invalid scope entry: {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Scope recorded:[/green] {entry['url']}")


@scope_app.command("show")
def scope_show(
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
) -> None:
    """Display scope entries without exposing secrets or cookies."""
    _path, document = _manifest_or_exit(manifest)
    entries = document.get("scope", [])
    if not entries:
        console.print("[dim]Scope is empty.[/dim]")
        return
    table = Table(title="Engagement Scope", border_style="grey50", header_style="bold cyan")
    table.add_column("#", justify="right", width=4)
    table.add_column("URL")
    table.add_column("Host")
    for index, item in enumerate(entries, 1):
        if isinstance(item, dict):
            table.add_row(str(index), str(item.get("url", "")), str(item.get("host", "")))
    console.print(table)


@scope_app.command("remove")
def scope_remove(
    value: str = typer.Argument(..., help="Exact normalized URL to remove."),
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
) -> None:
    """Remove one scope URL after the same validation used by `scope add`."""
    from webpent.cli.manifest import remove_scope_entry, save_manifest

    path, document = _manifest_or_exit(manifest)
    try:
        removed = remove_scope_entry(document, value)
        if removed:
            save_manifest(path, document)
    except (OSError, TypeError, ValueError) as exc:
        err_console.print(f"[red]Error:[/red] invalid scope entry: {exc}")
        raise typer.Exit(1) from exc
    console.print(
        "[green]Scope removed.[/green]" if removed else "[yellow]Scope entry not found.[/yellow]"
    )


@scope_app.command("check")
def scope_check(
    url: str = typer.Option(..., "--url", help="URL to evaluate; no network request is made."),
    scope: Path = typer.Option(..., "--scope", "--scope-file", help="Typed YAML/JSON scope policy."),
    method: str = typer.Option("GET", "--method", help="HTTP method to evaluate."),
) -> None:
    """Evaluate a URL against a typed scope policy without contacting the target."""
    from webpent.scope import ScopeEnforcer, parse_scope_file

    try:
        policy = parse_scope_file(scope)
        decision = ScopeEnforcer(policy).check_url(url, method=method)
    except (OSError, ValueError) as exc:
        err_console.print(f"[red]Error:[/red] invalid scope check: {exc}")
        raise typer.Exit(1) from exc
    console.print_json(
        json.dumps(
            {
                "url": url,
                "method": decision.method,
                "status": decision.status.value,
                "allowed": decision.allowed,
                "violation_category": decision.violation_code,
                "reason": decision.reason,
                "rule_source": decision.rule_source,
                "policy_fingerprint": policy.fingerprint,
            },
            sort_keys=True,
        )
    )


@app.command("hunt")
def hunt(
    url: str = typer.Option(
        ..., "--url", "-u", help="Authorized target URL (must include http:// or https://)."
    ),
    mode: str = typer.Option(
        "standard", "--mode", "-m",
        help=(
            "Unified hunt mode: quick (minutes-scale, deterministic-first), "
            "standard (balanced — the recommended default), or deep "
            "(large surfaces; the dynamic step budget takes over)."
        ),
    ),
    authorization: str = typer.Option(
        ..., "--authorization", "-A",
        help=(
            "REQUIRED: reference to your written authorization to test "
            "this target (e.g. a bug-bounty program ID or engagement ref)."
        ),
    ),
    authorization_manifest: str | None = typer.Option(
        None, "--authorization-manifest",
        help=(
            "M2: path to a structured, tamper-evident authorization manifest "
            "JSON (models/authorization.py). When supplied, the free-text "
            "--authorization value must equal the manifest's "
            "authorization_reference, the digest is re-verified, and the "
            "target origin must be covered — every refusal stops the run "
            "before any request is planned."
        ),
    ),
    scope_file: str | None = typer.Option(
        None, "--scope-file", help=(
            "M2: path to a scope file (worker-path grammar: allow entries, "
            "exclude:/include-path:/exclude-path: lines). The target must be "
            "covered or the run refuses; the declaration feeds the in-graph "
            "scope enforcement channels."
        ),
    ),
    client_id: str | None = typer.Option(None, "--client-id", help="Optional client scope for lesson consultation/persistence."),
    engagement_id: str | None = typer.Option(None, "--engagement-id"),
    thread_id: str | None = typer.Option(None, "--thread-id"),
    auto_approve: bool = typer.Option(False, "--auto-approve", help="Bypass HITL pause for automated CI/CD scanning."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Force the deterministic path (no LLM calls)."),
    creds: str | None = typer.Option(None, "--creds", "-c", help="Credentials in 'user:pass' format for authenticated scanning."),
    cookies: str | None = typer.Option(None, "--cookies", help="Operator-supplied session cookies for authenticated scanning."),
    report_format: str | None = typer.Option(None, "--report-format", help="Report format override."),
    no_progress: bool = typer.Option(False, "--no-progress", help="Disable the live progress view (CI-friendly)."),
) -> None:
    """Unified hunt: one command, three modes (Ultimate plan 2026-10-27, proposal 1).

    quick    — فحص سريع، تقرير في دقائق (سقف تكلفة منخفض)
    standard — فحص عميق متوازن (الافتراضي الموصى به)
    deep     — فحص شامل طويل لتطبيق كبير (الميزانية الديناميكية تاخد حقها)

    Runs the production graph with the closed learning loop (lessons
    consulted then extracted), the dynamic step budget (surface sized
    after crawling), live progress and instant CONFIRMED-finding lines.
    """
    from webpent.cli.unified_hunt import run_unified_hunt
    from webpent.state.unified_state import HUNT_MODES

    if mode.strip().lower() not in HUNT_MODES:
        err_console.print(
            f"[red]Error:[/red] unknown mode {mode!r} — accepted: "
            f"{', '.join(sorted(HUNT_MODES))}"
        )
        raise typer.Exit(1)
    try:
        summary = run_unified_hunt(
            url=url,
            mode=mode,
            authorization=authorization,
            client_id=client_id,
            engagement_id=engagement_id,
            thread_id=thread_id,
            auto_approve=auto_approve,
            no_llm=no_llm,
            creds=creds,
            cookies=cookies,
            report_format=report_format,
            progress=not no_progress,
            authorization_manifest=authorization_manifest,
            scope_file=scope_file,
        )
    except ValueError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc

    console.print("\n[bold green][✓] Unified hunt completed[/bold green]")
    console.print(
        f"  mode={summary.get('mode')} | findings confirmed: "
        f"{summary.get('findings_confirmed', 0)}/{summary.get('findings_total', 0)} "
        f"| dynamic budget: {summary.get('dynamic_step_budget') or 'flat'} "
        f"| lessons consulted: {summary.get('consulted_lessons')} "
        f"| detector results: {summary.get('detector_results', 0)}"
    )
    # Track 9.1 (2026-10-29): real elapsed + token tally; LLM cost stays
    # honestly unpriced (the runtime never invents a USD figure).
    console.print(
        f"  elapsed: {summary.get('elapsed_s', 0):g}s"
        f" | llm calls: {summary.get('llm_calls', 0)}"
        f" | llm tokens: {summary.get('llm_tokens_used', 0)} (unpriced)"
        f" | declared LLM ceiling: ${summary.get('llm_budget_usd', 0):g}"
    )
    if summary.get("thread_id"):
        console.print(f"  thread_id={summary['thread_id']}")


@app.command("graph")
def graph_command(
    action: str = typer.Argument("summary", help="summary or export."),
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
    output: str | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Show or export redacted Mental/Attack Graph summaries from a manifest."""
    path, document = _manifest_or_exit(manifest)
    if action not in {"summary", "export"}:
        err_console.print("[red]Error:[/red] graph action must be summary or export")
        raise typer.Exit(1)
    graph = document.get("graph") if isinstance(document.get("graph"), dict) else {}
    mental = graph.get("mental_model") if isinstance(graph.get("mental_model"), dict) else {}
    attack = graph.get("attack_graph") if isinstance(graph.get("attack_graph"), dict) else {}
    summary = {
        "mental_nodes": len(mental.get("nodes", {}))
        if isinstance(mental.get("nodes"), dict)
        else 0,
        "mental_edges": len(mental.get("edges", []))
        if isinstance(mental.get("edges"), list)
        else 0,
        "attack_nodes": len(attack.get("nodes", {}))
        if isinstance(attack.get("nodes"), dict)
        else 0,
        "attack_edges": len(attack.get("edges", []))
        if isinstance(attack.get("edges"), list)
        else 0,
    }
    if action == "summary":
        console.print(json.dumps(summary, indent=2))
        return
    if not output:
        err_console.print("[red]Error:[/red] graph export requires --output")
        raise typer.Exit(1)
    export_path = Path(output).expanduser()
    export_path.parent.mkdir(parents=True, exist_ok=True)
    export_path.write_text(
        json.dumps({"summary": summary, "graph": graph}, indent=2) + "\n", encoding="utf-8"
    )
    console.print(f"[green]Graph export written:[/green] {export_path}")


@app.command("findings")
def findings_command(
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
    status: str | None = typer.Option(None, "--status"),
    severity: str | None = typer.Option(None, "--severity"),
    confidence: str | None = typer.Option(None, "--confidence"),
) -> None:
    """List redacted finding metadata with optional lifecycle filters."""
    _path, document = _manifest_or_exit(manifest)
    rows = document.get("findings", [])
    if status:
        rows = [
            row
            for row in rows
            if isinstance(row, dict) and str(row.get("status", "")).lower() == status.lower()
        ]
    if severity:
        rows = [
            row
            for row in rows
            if isinstance(row, dict) and str(row.get("severity", "")).lower() == severity.lower()
        ]
    if confidence:
        rows = [
            row
            for row in rows
            if isinstance(row, dict)
            and str(row.get("confidence", "")).lower() == confidence.lower()
        ]
    if not rows:
        console.print("[dim]No matching findings.[/dim]")
        return
    table = Table(title=f"Findings ({len(rows)})", border_style="grey50", header_style="bold cyan")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Confidence")
    table.add_column("Title")
    for row in rows:
        if isinstance(row, dict):
            table.add_row(
                str(row.get("id", "")),
                str(row.get("severity", "")),
                str(row.get("status", "")),
                str(row.get("confidence", "")),
                str(row.get("title", ""))[:120],
            )
    console.print(table)


@app.command("evidence")
def evidence_command(
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
) -> None:
    """List canonical evidence references; raw bodies and secret values are never printed."""
    _path, document = _manifest_or_exit(manifest)
    refs = document.get("evidence_refs", [])
    if not refs:
        console.print("[dim]No evidence references recorded.[/dim]")
        return
    table = Table(title="Evidence References", border_style="grey50", header_style="bold cyan")
    table.add_column("ID")
    table.add_column("Kind")
    table.add_column("Hash")
    table.add_column("Redacted")
    for ref in refs:
        if isinstance(ref, dict):
            table.add_row(
                str(ref.get("id", "")),
                str(ref.get("kind", "")),
                str(ref.get("hash", ref.get("sha256", "")))[:32],
                "yes" if ref.get("redacted", True) else "no",
            )
    console.print(table)


@app.command("investigate")
def investigate_command(
    identifier: str = typer.Argument(..., help="Finding or hypothesis identifier."),
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
    reason: str = typer.Option("operator-requested revisit", "--reason", max=240),
) -> None:
    """Create a bounded revisit task; no PoC or network action is executed."""
    from webpent.cli.manifest import save_manifest

    path, document = _manifest_or_exit(manifest)
    tasks = document.setdefault("investigations", [])
    if any(isinstance(item, dict) and item.get("id") == identifier for item in tasks):
        console.print("[yellow]Investigation already exists; no duplicate task created.[/yellow]")
        return
    task = {
        "id": identifier,
        "status": "pending",
        "reason": reason,
        "max_depth": 1,
        "max_steps": 3,
        "destructive_poc": False,
        "approval_required": True,
        "created_at": __import__("datetime")
        .datetime.now(__import__("datetime").timezone.utc)
        .isoformat(),
    }
    tasks.append(task)
    save_manifest(path, document)
    console.print(f"[green]Bounded investigation queued:[/green] {identifier} (no execution)")


@app.command("report")
def report_command(
    manifest: str = typer.Option("webpent-engagement.json", "--manifest", "-f"),
    output: str | None = typer.Option(None, "--output", "-o"),
    format: str = typer.Option("json", "--format", help="json or html"),
) -> None:
    """Export a redacted manifest-backed report in JSON or HTML."""
    import html

    _path, document = _manifest_or_exit(manifest)
    if format not in {"json", "html"}:
        err_console.print("[red]Error:[/red] report format must be json or html")
        raise typer.Exit(1)
    output_path = Path(output).expanduser() if output else Path("webpent-report." + format)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if format == "json":
        output_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    else:
        title = html.escape(str(document.get("engagement", {}).get("name", "WebPent Report")))
        findings = document.get("findings", [])
        items = "".join(
            f"<li>{html.escape(str(item.get('title', item.get('id', ''))))}</li>"
            for item in findings
            if isinstance(item, dict)
        )
        output_path.write_text(
            "<!doctype html><meta charset='utf-8'><title>"
            + title
            + "</title><h1>"
            + title
            + "</h1><h2>Findings</h2><ul>"
            + items
            + "</ul>",
            encoding="utf-8",
        )
    console.print(f"[green]Report written:[/green] {output_path}")


@app.command("reports")
def bounty_reports_command(
    campaign_id: str = typer.Argument(..., help="Campaign/engagement identifier."),
    output: str | None = typer.Option(None, "--output", "-o"),
    format: str = typer.Option("markdown", "--format", help="markdown or json"),
    platform: str = typer.Option(
        "neutral",
        "--platform",
        help=(
            "Submission template: neutral (default), hackerone, or bugcrowd "
            "(Track 9.4/11.6 — same promotion-gated content, platform field layout)."
        ),
    ),
) -> None:
    """Print submission-ready reports from promoted ProofBundles only."""
    if format not in {"markdown", "json"}:
        err_console.print("[red]Error:[/red] reports format must be markdown or json")
        raise typer.Exit(1)
    if platform.strip().lower() not in {"neutral", "hackerone", "bugcrowd"}:
        err_console.print(
            "[red]Error:[/red] platform must be neutral, hackerone, or bugcrowd"
        )
        raise typer.Exit(1)
    thread_ids = get_thread_ids_by_engagement_id(campaign_id) or [campaign_id]
    try:
        findings = aggregate_findings(
            get_db_manager().get_findings_by_threads(thread_ids)
        )
        reports = generate_bounty_reports(findings, campaign_id=campaign_id)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] unable to load campaign reports: {exc}")
        raise typer.Exit(1) from exc
    if not reports:
        console.print("[dim]No submission-ready promoted ProofBundle reports found.[/dim]")
        return
    if format == "json":
        rendered = json.dumps([report.to_json() for report in reports], indent=2)
    else:
        rendered = "\n\n---\n\n".join(
            report.to_platform_markdown(platform) for report in reports
        )
    if output:
        path = Path(output).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
        console.print(f"[green]Submission reports written:[/green] {path}")
    else:
        console.print(rendered)


@app.command("agent-hunt")
def hunt_command(
    target: str = typer.Option(..., "--target", help="Authorized HTTP(S) target URL."),
    persona: str = typer.Option("stok", "--persona", help="nahamsec, stok, logic, or all."),
    engagement_id: str | None = typer.Option(None, "--engagement-id"),
    artifact_root: str | None = typer.Option(None, "--artifact-root"),
    max_hypotheses: int = typer.Option(12, min=1, max=100),
    max_decisions: int = typer.Option(12, min=1, max=100),
    max_llm_calls: int = typer.Option(40, min=1, max=100),
    max_cost_usd: float = typer.Option(5.0, min=0.01, max=5.0),
    families: str | None = typer.Option(
        None,
        "--families",
        help="Comma-separated existing experiment families; narrows the governed catalog only.",
    ),
    credentials: str | None = typer.Option(None, "--credentials", help="Operator-supplied principal JSON; never written to artifacts."),
    credentials_file: Path | None = typer.Option(None, "--credentials-file", help="Gitignored JSON file containing operator principal profiles."),
    client_id: str | None = typer.Option(None, "--client-id", help="Optional client scope for advisory lesson consultation/persistence."),
    scope_policy_file: Path | None = typer.Option(None, "--scope", "--scope-file", help="Required typed program-scope file for target hunting."),
) -> None:
    """Run the bounded three-agent hunter loop against an authorized target."""
    from webpent.agents.hunter_runner import run_hunter_campaign

    if scope_policy_file is None:
        err_console.print("[red]Hunter campaign blocked:[/red] --scope is required for target execution")
        raise typer.Exit(1)
    from webpent.scope import parse_scope_file
    try:
        scope_policy = parse_scope_file(scope_policy_file)
    except (OSError, ValueError) as exc:
        err_console.print(f"[red]Hunter campaign blocked:[/red] invalid scope: {exc}")
        raise typer.Exit(1) from exc

    campaign_id = engagement_id or f"hunter-{uuid4().hex[:12]}"
    principal_credentials = _load_hunter_principals(credentials, credentials_file)
    try:
        result = run_hunter_campaign(
            target_url=target,
            engagement_id=campaign_id,
            persona=persona,
            artifact_root=artifact_root,
            max_hypotheses=max_hypotheses,
            max_decisions=max_decisions,
            max_llm_calls=max_llm_calls,
            max_cost_usd=max_cost_usd,
            families=families,
            principal_credentials=principal_credentials,
            client_id=client_id,
            scope_policy=scope_policy,
        )
    except Exception as exc:
        err_console.print(f"[red]Hunter campaign blocked:[/red] {type(exc).__name__}: {exc}")
        raise typer.Exit(1) from exc
    summary = result["summary"]
    # WP-I (Dispatch #009-A): exit-code honesty (NF-L0-01) — never exit 0
    # on an incomplete production chain.
    _enforce_chain_honesty(
        summary.get("production_trace"),
        surface="AGENT-HUNT",
        terminal_summary=summary,
        pointer=(
            f"{artifact_root or 'artifacts/hunter-' + campaign_id}"
            "/campaign_summary.json"
        ),

    )
    console.print_json(json.dumps(summary, sort_keys=True, default=str))
