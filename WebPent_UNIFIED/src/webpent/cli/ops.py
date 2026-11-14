# src/webpent/cli/ops.py
"""webpent.cli.ops — Track 12 operations commands.

A Typer sub-app (the frozen-window protocol pattern used for
``retest``: NEW file in 0.24.0, minimal wiring in ``commands.py``).

v0.24.0 — READ-ONLY surface (no campaign behavior change):

* ``webpent ops governor``    — concurrency-governor snapshot (plus the
  cross-process lease view when phase-2 mode is enabled).
* ``webpent ops workers``     — multi-worker coordination snapshot and
  the tail of the append-only change log.
* ``webpent ops graph``       — build the redaction-first finding
  relation graph from the local DB and export it (html/json/dot).
* ``webpent ops calibration`` — per-class calibrated multipliers for one
  client (human-decision aggregates only; never raw data).
* ``webpent ops protection``  — the protection-controls posture: signal
  vocabulary, policy decisions, and the FORBIDDEN evasions list.

v0.25.0 — LIMITED WRITE surface behind RBAC (the 0.24.0 worklog's
"write commands behind RBAC when the operator asks" follow-up):

* ``webpent ops users bootstrap-admin|grant`` — local identity book
  (role + client memberships; admin-only; bootstrap only when empty).
* ``webpent ops review enqueue|claim|decide|pending`` — the multi-
  analyst review queue via the 0.23.0 engine (TRIAGE_FINDINGS +
  workspace membership enforced by the engine itself).
* ``webpent ops portfolio register|admit|spend|status`` — portfolio
  economics and the unified-budget ledger (lead/admin; caps fail-
  closed; every decision audit-logged).

v0.27.0 — LEARNING A/B LAB (docs/PRODUCTION_FIX_PLAN_0270.md, C-9/C-10):

* ``webpent ops learning-ab`` — the weekly control-vs-treatment
  scheduler for Track 6.5 (lesson-impact measurement):
  ``open`` (open this ISO week's two real windows), ``tick`` (execute
  at most ONE due window — dry-plan without ``--execute``), ``status``
  (weeks + verdicts + the declared numeric thresholds),
  ``record-metrics`` (post an arm's metrics explicitly).
  ``open``/``tick``/``record-metrics`` launch or evidence campaigns and
  sit behind the FROZEN ``run_campaign`` RBAC permission; ``status`` is
  read-only. The verdict thresholds are declared constants in
  ``memory/ab_lab.py`` — never operator-invented at runtime.

State lives in one JSON file (``--state``, mode 0600, atomic writes)
plus an append-only JSONL audit trail beside it (see
``production/ops_state.py``). Nothing here sends requests, mutates
campaigns, or bypasses any gate: authorization failures are typed
``OpsStateError`` exits (code 2) and are fail-closed.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

ops_app = typer.Typer(
    name="ops",
    help=(
        "Track 12 operations: read-only inspection (governor, workers, "
        "graph, calibration, protection) plus RBAC-gated write commands "
        "(users, review queue, portfolio budget)."
    ),
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)

__all__ = ["ops_app"]


@ops_app.command("governor")
def governor_status(
    as_json: bool = typer.Option(False, "--json", help="Render redacted JSON."),
) -> None:
    """Show the shared concurrency-governor snapshot (no changes made)."""
    from webpent.production.concurrency_governor import get_concurrency_governor

    governor = get_concurrency_governor()
    snap = governor.snapshot().as_dict()
    payload = {
        "max_global": governor.max_global,
        "max_per_target": governor.max_per_target,
        "cross_process_enabled": governor.lease_backend is not None,
        **snap,
    }
    if as_json:
        console.print_json(json.dumps(payload, default=str))
        return
    table = Table(title="Concurrency governor (Track 12.2)", border_style="grey50")
    table.add_column("metric")
    table.add_column("value", justify="right")
    table.add_row("global cap", str(payload["max_global"]))
    table.add_row("per-target cap", str(payload["max_per_target"]))
    table.add_row(
        "cross-process leases",
        "enabled" if payload["cross_process_enabled"] else "off (process-wide)",
    )
    table.add_row("active / waiting", f"{payload['active_total']} / {payload['waiting_total']}")
    table.add_row(
        "admitted / rejected / expired",
        f"{payload['admitted_total']} / {payload['rejected_total']} / {payload['expired_total']}",
    )
    console.print(table)
    cross = payload.get("cross_process")
    if isinstance(cross, dict):
        lease_table = Table(title="Cross-process lease slots", border_style="grey50")
        lease_table.add_column("metric")
        lease_table.add_column("value", justify="right")
        lease_table.add_row(
            "global slots (active/total)",
            f"{cross.get('global_slots_active', 0)} / {cross.get('global_slots_total', 0)}",
        )
        lease_table.add_row(
            "target slots (active/total)",
            f"{cross.get('target_slots_active', 0)} / {cross.get('target_slots_total', 0)}",
        )
        console.print(lease_table)


@ops_app.command("workers")
def workers_status(
    coord_dir: Path = typer.Option(
        ..., "--coord-dir", help="Worker-coordination runtime directory."
    ),
    log_tail: int = typer.Option(10, "--log-tail", min=1, max=200),
    as_json: bool = typer.Option(False, "--json", help="Render redacted JSON."),
) -> None:
    """Show worker-coordination state and the change-log tail."""
    from webpent.production.worker_coordination import WorkerCoordinator

    if not Path(coord_dir).exists():
        err_console.print(f"[yellow]coordination directory not found: {coord_dir}[/yellow]")
        raise typer.Exit(2)
    coordinator = WorkerCoordinator(coord_dir)
    snap = coordinator.snapshot()
    events = coordinator.read_change_log(limit=log_tail)
    if as_json:
        console.print_json(json.dumps({"snapshot": snap, "change_log_tail": events}, default=str))
        return
    table = Table(title="Worker coordination (Track 12.3)", border_style="grey50")
    table.add_column("metric")
    table.add_column("value", justify="right")
    table.add_row("this worker id", snap["worker_id"])
    table.add_row("active claims", str(snap["active_claims"]))
    table.add_row("claim files (total)", str(snap["total_claim_files"]))
    table.add_row("registered fingerprints", str(snap["registered_fingerprints"]))
    console.print(table)
    if events:
        log_table = Table(title=f"Change log (last {len(events)})", border_style="grey50")
        log_table.add_column("time")
        log_table.add_column("event")
        log_table.add_column("worker")
        for event in events:
            log_table.add_row(
                str(event.get("ts", "")),
                str(event.get("event", "")),
                str(event.get("worker_id", "")),
            )
        console.print(log_table)
    else:
        console.print("[dim]change log is empty.[/dim]")


@ops_app.command("graph")
def graph_export(
    out: Path = typer.Option(..., "--out", help="Output file path."),
    fmt: str = typer.Option(
        "html", "--format", "-f", help="Export format: html | json | dot."
    ),
    limit: int = typer.Option(200, "--limit", "-n", min=1, max=2000),
) -> None:
    """Export the redaction-first finding relation graph (read-only).

    Nodes carry identifiers and evidence HASHES only — payloads and
    evidence bodies never enter the graph; the report remains the
    evidence surface.
    """
    from webpent.memory.db import get_db_manager
    from webpent.production.finding_relation_graph import (
        build_finding_graph,
        graph_to_dot,
        graph_to_json,
        render_html,
    )

    fmt = fmt.strip().lower()
    if fmt not in {"html", "json", "dot"}:
        err_console.print(f"[red]unsupported format '{fmt}' — use html|json|dot[/red]")
        raise typer.Exit(2)
    findings = get_db_manager().get_all_findings()[:limit]
    if not findings:
        err_console.print("[yellow]no findings in the local DB — nothing to graph.[/yellow]")
        raise typer.Exit(2)
    graph = build_finding_graph(list(findings))
    content = {
        "html": render_html,
        "json": graph_to_json,
        "dot": graph_to_dot,
    }[fmt](graph)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    summary = graph.summary()
    console.print(
        f"[green]graph written:[/green] {out} ({fmt}) — "
        f"nodes={summary['nodes_total']} edges={summary['edges_total']} "
        f"({summary['nodes_by_kind']})"
    )


@ops_app.command("calibration")
def calibration_status(
    client: str = typer.Option(..., "--client", help="Client id to inspect."),
    store_dir: Path = typer.Option(
        ..., "--store-dir", help="Calibration store directory (per-client hashed)."
    ),
    classes: str = typer.Option(
        "", "--classes", help="Comma-separated vuln classes (empty = scan store)."
    ),
    candidates: str = typer.Option(
        "",
        "--candidates",
        help=(
            "Track 12.8 consume side (0.26.0): JSON list of [id, vuln_class, "
            "confidence] triples to reorder with the calibrated multipliers. "
            "Reordering only — raw confidence values are never modified."
        ),
    ),
    as_json: bool = typer.Option(False, "--json", help="Render redacted JSON."),
) -> None:
    """Show bounded per-class multipliers derived from human decisions.

    Read-only: aggregates (accepted/rejected counts) only — no raw
    finding data exists in the store by construction.
    """
    from webpent.production.confidence_calibration import ConfidenceCalibrator

    if not Path(store_dir).exists():
        err_console.print(f"[yellow]calibration store not found: {store_dir}[/yellow]")
        raise typer.Exit(2)
    from webpent.production.confidence_calibration import (
        MAX_MULTIPLIER,
        MIN_MULTIPLIER,
    )

    calibrator = ConfidenceCalibrator(store_dir)
    # Track 12.8 consume side (0.26.0): with --candidates, the command
    # becomes the calibrated_ranking consumer the roadmap wanted — the
    # calibrator's bounded multipliers reorder the operator's candidate
    # list (id, vuln_class, raw confidence) deterministically. Reordering
    # only; raw confidence is never modified.
    if candidates.strip():
        try:
            parsed = json.loads(candidates)
            triples = [(str(t[0]), str(t[1]), float(t[2])) for t in parsed]
        except (ValueError, TypeError, IndexError) as exc:
            err_console.print(
                f"[red]Error:[/red] --candidates must be a JSON list of "
                f"[id, vuln_class, confidence] triples: {exc}"
            )
            raise typer.Exit(2) from exc
        ordered = calibrator.calibrated_order(triples, client)
        if as_json:
            console.print_json(
                json.dumps(
                    {
                        "client": client,
                        "ordered": [
                            {"id": cid, "calibrated_confidence": conf}
                            for cid, conf in ordered
                        ],
                    },
                    default=str,
                )
            )
            return
        table = Table(
            title=f"Calibrated order for client '{client}' (Track 12.8)",
            border_style="grey50",
        )
        table.add_column("rank", justify="right")
        table.add_column("candidate")
        table.add_column("calibrated confidence", justify="right")
        for rank, (cid, conf) in enumerate(ordered, start=1):
            table.add_row(str(rank), cid, f"{conf:.4f}")
        console.print(table)
        console.print(
            "[dim]reordering only — raw confidence values were never modified.[/dim]"
        )
        return
    if classes.strip():
        class_names = [c.strip() for c in classes.split(",") if c.strip()]
    else:
        client_dir = calibrator._client_dir(client)
        class_names = sorted(
            p.stem.replace("class-", "") for p in client_dir.glob("class-*.json")
        )
    rows = []
    for class_digest in class_names:
        accepted, rejected = 0, 0
        path = calibrator._client_dir(client) / f"class-{class_digest}.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for record in data.get("records", []):
                if record.get("decision") == "accepted":
                    accepted += 1
                elif record.get("decision") == "rejected":
                    rejected += 1
        except (OSError, ValueError):
            pass
        # Multiplier needs the class NAME; the digest store maps names →
        # digests, so we report counts + the multiplier via the class
        # digest round-trip helper below.
        rows.append((class_digest, accepted, rejected, None))
    if as_json:
        console.print_json(json.dumps({"client": client, "classes": rows}, default=str))
        return
    table = Table(title=f"Calibration for client '{client}' (Track 12.8)", border_style="grey50")
    table.add_column("class (digest)")
    table.add_column("accepted", justify="right")
    table.add_column("rejected", justify="right")
    table.add_column("note")
    for digest, accepted, rejected, _multiplier in rows:
        note = "" if (accepted or rejected) else "cold (neutral 1.0)"
        table.add_row(digest, str(accepted), str(rejected), note)
    console.print(table)
    console.print(
        f"[dim]multiplier bounds: {MIN_MULTIPLIER}..{MAX_MULTIPLIER} — "
        "raw confidence is never modified; only candidate ORDER changes.[/dim]"
    )


@ops_app.command("protection")
def protection_posture(
    as_json: bool = typer.Option(False, "--json", help="Render redacted JSON."),
) -> None:
    """Show the protection-controls posture and the refusal list."""
    from webpent.production.protection_controls import (
        DEFAULT_POLITE_BACKOFF_SECONDS,
        FORBIDDEN_EVASIONS,
        MAX_POLITE_BACKOFF_SECONDS,
        RATE_LIMIT_ESCALATION_THRESHOLD,
    )

    payload = {
        "signals": ["waf_block", "rate_limit", "challenge", "backend_throttle"],
        "policy": {
            "block_or_challenge": "halt action + request human review (no evasion)",
            "rate_limit": (
                f"polite backoff honoring Retry-After "
                f"(default {DEFAULT_POLITE_BACKOFF_SECONDS:.0f}s, max "
                f"{MAX_POLITE_BACKOFF_SECONDS:.0f}s); escalation to review at "
                f"{RATE_LIMIT_ESCALATION_THRESHOLD} events"
            ),
            "backend_throttle": "halt action + request human review",
        },
        "forbidden_evasions": list(FORBIDDEN_EVASIONS),
    }
    if as_json:
        console.print_json(json.dumps(payload))
        return
    table = Table(title="Protection controls (Track 12.6)", border_style="grey50")
    table.add_column("signal")
    table.add_column("policy")
    table.add_row("waf_block / challenge", payload["policy"]["block_or_challenge"])
    table.add_row("rate_limit", payload["policy"]["rate_limit"])
    table.add_row("backend_throttle", payload["policy"]["backend_throttle"])
    console.print(table)
    console.print("[bold]Never implemented (refusal list):[/bold]")
    for item in payload["forbidden_evasions"]:
        console.print(f"  [red]✗[/red] {item}")


# ----------------------------------------------------------------------
# RBAC-gated WRITE commands (v0.25.0) — state-backed, fail-closed
# ----------------------------------------------------------------------
def _ops_state_or_exit(state_path: str) -> dict:
    """Load ops state; typed operator errors exit with code 2."""
    from webpent.production.ops_state import OpsStateError, load_state

    try:
        return load_state(state_path)
    except OpsStateError as exc:
        err_console.print(f"[red]ops state error:[/red] {exc}")
        raise typer.Exit(code=2) from None


def _authorized_role(state_path: str, state: dict, actor: str, permission: str):
    """Resolve the actor's role from the state book and check the frozen
    RBAC matrix. Unknown actor / denied permission -> typed exit 2."""
    from webpent.production.enterprise_operations import RbacPolicy
    from webpent.production.ops_state import OpsStateError, user_role

    try:
        role = user_role(state, actor)
    except OpsStateError as exc:
        err_console.print(f"[red]authorization refused:[/red] {exc}")
        raise typer.Exit(code=2) from None
    if not RbacPolicy.authorize(role, permission):
        err_console.print(
            f"[red]authorization refused:[/red] actor '{actor}' "
            f"({role.value}) lacks '{permission}'"
        )
        raise typer.Exit(code=2) from None
    return role


def _require_membership(state: dict, actor: str, client_id: str) -> None:
    """Workspace isolation for write commands that touch a client."""
    from webpent.production.ops_state import get_user

    memberships = {str(c) for c in get_user(state, actor).get("clients", [])}
    if client_id not in memberships:
        err_console.print(
            f"[red]authorization refused:[/red] actor '{actor}' is not a "
            f"member of client workspace '{client_id}'"
        )
        raise typer.Exit(code=2) from None


def _persist(state_path: str, state: dict, *, action: str, actor: str, **audit: object) -> None:
    from webpent.production.ops_state import append_ops_audit, save_state

    save_state(state_path, state)
    append_ops_audit(state_path, action=action, actor=actor, **audit)


# ----------------------------------------------------------------------
# users (local identity book)
# ----------------------------------------------------------------------
@ops_app.command("bootstrap-admin")
def ops_bootstrap_admin(
    state_path: str = typer.Option(..., "--state", help="Ops state JSON file."),
    actor: str = typer.Option(..., "--actor", help="Admin name to create."),
    client: list[str] = typer.Option(
        [], "--client", help="Workspace membership grant (repeatable)."
    ),
) -> None:
    """Create the FIRST admin — only while the users book is empty."""
    from webpent.production.ops_state import (
        OpsStateError,
        append_ops_audit,
        load_state,
        save_state,
        user_role,
    )

    state = _ops_state_or_exit(state_path)
    if state["users"]:
        err_console.print(
            "[red]bootstrap refused:[/red] users already exist — ask an "
            "admin to run 'ops users grant' instead"
        )
        raise typer.Exit(code=2) from None
    state["users"][actor] = {"role": "admin", "clients": sorted({str(c) for c in client})}
    save_state(state_path, state)
    append_ops_audit(
        state_path, action="users.bootstrap_admin", actor=actor, granted=actor
    )
    console.print(f"[green]admin '{actor}' bootstrapped[/green] ({state_path})")
    # Round-trip sanity: the persisted book must now know the actor.
    try:
        user_role(load_state(state_path), actor)
    except OpsStateError as exc:  # pragma: no cover — defensive
        err_console.print(f"[red]bootstrap verification failed:[/red] {exc}")
        raise typer.Exit(code=2) from None


@ops_app.command("users")
def ops_users(
    state_path: str = typer.Option(..., "--state", help="Ops state JSON file."),
    actor: str = typer.Option(..., "--actor", help="Acting admin (must hold manage_users)."),
    grantee: str = typer.Option(..., "--grantee", help="User to create or update."),
    role: str = typer.Option(..., "--role", help="viewer|analyst|lead|admin"),
    client: list[str] = typer.Option(
        [], "--client", help="Workspace membership grant (repeatable)."
    ),
    as_json: bool = typer.Option(False, "--json", help="Render redacted JSON."),
) -> None:
    """Grant a role (and optional client memberships) — admin only."""
    from webpent.production.ops_state import grant_user

    state = _ops_state_or_exit(state_path)
    _authorized_role(state_path, state, actor, "manage_users")
    try:
        record = grant_user(
            state, actor=actor, grantee=grantee, role=role, clients=[str(c) for c in client]
        )
    except Exception as exc:
        err_console.print(f"[red]grant refused:[/red] {exc}")
        raise typer.Exit(code=2) from None
    _persist(state_path, state, action="users.grant", actor=actor, grantee=grantee, role=role)
    if as_json:
        console.print_json(json.dumps({"grantee": grantee, **record}))
        return
    console.print(
        f"[green]granted[/green] '{grantee}' -> {record['role']} "
        f"(clients: {record['clients']})"
    )


# ----------------------------------------------------------------------
# review queue (0.23.0 engine, TRIAGE_FINDINGS + workspace enforced)
# ----------------------------------------------------------------------
@ops_app.command("review")
def ops_review(
    state_path: str = typer.Option(..., "--state", help="Ops state JSON file."),
    actor: str = typer.Option(..., "--actor", help="Acting analyst (must hold triage_findings)."),
    action: str = typer.Option(..., "--action", help="enqueue|claim|decide|pending"),
    client: str = typer.Option("", "--client", help="Client workspace (enqueue/pending)."),
    item: str = typer.Option("", "--item", help="Review item id (claim/decide)."),
    finding_ref: str = typer.Option("", "--finding-ref", help="Finding reference (enqueue)."),
    severity: str = typer.Option(
        "info", "--severity", help="info|low|medium|high|critical (enqueue)."
    ),
    approve: bool = typer.Option(False, "--approve", help="Decide: approve."),
    reject: bool = typer.Option(False, "--reject", help="Decide: reject."),
    calibration_store: Path = typer.Option(
        None,
        "--calibration-store",
        help=(
            "Track 12.8 (0.26.0): with --action decide, ALSO record this "
            "decision into the per-client calibration store (aggregates "
            "only; fail-open — a learning write never breaks a review)."
        ),
    ),
    vuln_class: str = typer.Option(
        "general",
        "--vuln-class",
        help="Vulnerability class recorded with the calibration decision.",
    ),
    as_json: bool = typer.Option(False, "--json", help="Render redacted JSON."),
) -> None:
    """Multi-analyst review queue (enqueue/claim/decide/pending)."""
    from webpent.production.ops_state import (
        OpsStateError,
        build_workspaces_and_queue,
        serialize_queue,
    )

    state = _ops_state_or_exit(state_path)
    _authorized_role(state_path, state, actor, "triage_findings")
    try:
        workspace, queue = build_workspaces_and_queue(state)
        result: dict = {}
        if action == "enqueue":
            if not client or not finding_ref:
                raise OpsStateError("enqueue requires --client and --finding-ref")
            _require_membership(state, actor, client)
            import uuid

            item_id = item.strip() or f"rev-{uuid.uuid4().hex[:12]}"
            created = queue.enqueue(item_id, client, finding_ref, severity=severity, actor=actor)
            if created is None:
                raise OpsStateError(f"enqueue refused for workspace '{client}'")
            result = {"action": "enqueued", **created.as_dict()}
        elif action == "claim":
            if not item:
                raise OpsStateError("claim requires --item")
            claimed = queue.claim(item, actor)
            if claimed is None:
                raise OpsStateError(f"claim refused for item '{item}' (state or workspace)")
            result = {"action": "claimed", **claimed.as_dict()}
        elif action == "decide":
            if not item or (approve == reject):
                raise OpsStateError("decide requires --item and exactly one of --approve/--reject")
            decided = queue.submit_decision(item, actor, approve=approve)
            if decided is None:
                raise OpsStateError(f"decision refused for item '{item}' (state or workspace)")
            result = {
                "action": "decided",
                "nominatable": queue.nominatable(item),
                **decided.as_dict(),
            }
        elif action == "pending":
            listing = queue.pending(client_id=client or None)
            result = {
                "action": "pending",
                "items": [entry.as_dict() for entry in listing],
                "required_approvals": queue.required_approvals,
            }
        else:
            raise OpsStateError(f"unknown review action '{action}'")
        if action != "pending":
            serialize_queue(state, queue)
            _persist(state_path, state, action=f"review.{action}", actor=actor,
                     item=str(result.get("item_id", item)), client=client)
            if action == "decide" and calibration_store is not None:
                # Track 12.8 write side (0.26.0): the human triage decision
                # also feeds the bounded calibrator (aggregates only: client,
                # class, decision, severity — no raw finding data exists in
                # the record type). Fail-open by contract: learning is a
                # side-effect, never a review dependency. Recorded AFTER the
                # state persist so the review of record is the authority.
                try:
                    from webpent.production.confidence_calibration import (
                        CalibrationRecord,
                        ConfidenceCalibrator,
                        HumanDecision,
                    )

                    decided_client = str(result.get("client_id") or client or "")
                    ConfidenceCalibrator(calibration_store).record_decision(
                        CalibrationRecord(
                            client_id=decided_client,
                            vuln_class=vuln_class.strip() or "general",
                            decision=HumanDecision.ACCEPTED if approve else HumanDecision.REJECTED,
                            severity=str(result.get("severity") or severity),
                        )
                    )
                except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
                    err_console.print(
                        "[yellow]calibration store write failed — review decision stands, "
                        "decision not recorded for calibration[/yellow]"
                    )
        if as_json:
            console.print_json(json.dumps(result, default=str))
            return
        if action == "pending":
            table = Table(title="Review queue (pending/claimed)", border_style="grey50")
            table.add_column("item")
            table.add_column("client")
            table.add_column("state")
            table.add_column("approvals", justify="right")
            for entry in result["items"]:
                table.add_row(
                    entry["item_id"],
                    entry["client_id"],
                    entry["state"],
                    str(len(entry["approvals"])),
                )
            console.print(table)
        else:
            console.print_json(json.dumps(result, default=str))
    except OpsStateError as exc:
        err_console.print(f"[red]review refused:[/red] {exc}")
        raise typer.Exit(code=2) from None


# ----------------------------------------------------------------------
# portfolio (lead/admin; unified budget, fail-closed caps)
# ----------------------------------------------------------------------
@ops_app.command("portfolio")
def ops_portfolio(
    state_path: str = typer.Option(..., "--state", help="Ops state JSON file."),
    actor: str = typer.Option(..., "--actor", help="Acting lead/admin."),
    action: str = typer.Option(..., "--action", help="register|admit|spend|status"),
    client: str = typer.Option("", "--client", help="Client id (register/admit/spend)."),
    program: str = typer.Option("", "--program", help="Program name (register/admit)."),
    campaign: str = typer.Option("", "--campaign", help="Campaign id (admit/spend)."),
    reward: float = typer.Option(0.0, "--reward", help="Expected reward (register)."),
    prob: float = typer.Option(0.0, "--prob", help="Success probability 0..1 (register)."),
    cost: float = typer.Option(0.0, "--cost", help="Estimated cost (register)."),
    amount: float = typer.Option(0.0, "--amount", help="Spend amount (spend)."),
    notes: str = typer.Option("", "--notes", help="Program notes (register)."),
    as_json: bool = typer.Option(False, "--json", help="Render redacted JSON."),
) -> None:
    """Portfolio economics + unified-budget ledger (lead/admin only)."""
    from webpent.production.ops_state import (
        PORTFOLIO_WRITE_ROLES,
        OpsStateError,
        build_portfolio,
        serialize_portfolio,
        user_role,
    )
    from webpent.production.portfolio_manager import AdmissionVerdict, ProgramEstimate

    state = _ops_state_or_exit(state_path)
    try:
        role = user_role(state, actor)
    except Exception as exc:
        err_console.print(f"[red]authorization refused:[/red] {exc}")
        raise typer.Exit(code=2) from None
    if role not in PORTFOLIO_WRITE_ROLES:
        err_console.print(
            f"[red]authorization refused:[/red] portfolio writes need "
            f"lead/admin (actor '{actor}' is {role.value})"
        )
        raise typer.Exit(code=2) from None
    try:
        manager = build_portfolio(state)
        result: dict = {}
        if action == "register":
            if not client or not program:
                raise OpsStateError("register requires --client and --program")
            _require_membership(state, actor, client)
            manager.register_program(
                ProgramEstimate(
                    program_name=program, client_id=client,
                    expected_reward=reward, success_probability=prob,
                    estimated_cost=cost, notes=notes,
                )
            )
            result = {"action": "registered", "program": program, "client": client}
        elif action == "admit":
            if not client or not program or not campaign:
                raise OpsStateError("admit requires --client, --program and --campaign")
            _require_membership(state, actor, client)
            decision = manager.admit(client, program, campaign)
            result = {
                "action": (
                    "admitted" if decision.verdict is AdmissionVerdict.ADMITTED else "refused"
                ),
                **decision.as_dict(),
            }
        elif action == "spend":
            if not client or not campaign or amount <= 0:
                raise OpsStateError("spend requires --client, --campaign and a positive --amount")
            _require_membership(state, actor, client)
            recorded, reason = manager.record_spend(client, campaign, amount)
            if not recorded:
                raise OpsStateError(f"spend refused: {reason}")
            state["portfolio"].setdefault("spend_entries", []).append(
                {"client_id": client, "campaign_id": campaign, "amount": amount}
            )
            result = {"action": "spent", "client": client, "campaign": campaign, "amount": amount}
        elif action == "status":
            result = {"action": "status", **manager.budget_snapshot()}
        else:
            raise OpsStateError(f"unknown portfolio action '{action}'")
        if action != "status":
            serialize_portfolio(state, manager)
            _persist(state_path, state, action=f"portfolio.{action}", actor=actor,
                     client=client, program=program, campaign=campaign)
        if as_json:
            console.print_json(json.dumps(result, default=str))
            return
        if action == "status":
            console.print_json(json.dumps(result, default=str))
        else:
            verdict = result.get("verdict") or result.get("action", "")
            console.print(
                f"[green]{action}[/green] -> {verdict}"
                + (f" ({result.get('reason')})" if result.get("reason") else "")
            )
    except OpsStateError as exc:
        err_console.print(f"[red]portfolio refused:[/red] {exc}")
        raise typer.Exit(code=2) from None


# ----------------------------------------------------------------------
# learning-ab (v0.27.0 — C-9/C-10; run_campaign RBAC for writes)
# ----------------------------------------------------------------------
@ops_app.command("learning-ab")
def ops_learning_ab(
    action: str = typer.Option(..., "--action", help="open|tick|status|record-metrics"),
    db: Path = typer.Option(
        Path("./memory/global/ab_lab.sqlite3"), "--db",
        help="Lesson A/B lab SQLite store path.",
    ),
    client: str = typer.Option("", "--client", help="Client id (open)."),
    target: str = typer.Option("", "--target", help="Target URL (open)."),
    mode: str = typer.Option("standard", "--mode", help="Hunt mode for both windows (open)."),
    authorization: str = typer.Option(
        "", "--authorization", help="Authorization REFERENCE passed to webpent hunt (open)."
    ),
    metrics_db: Path = typer.Option(
        Path("./memory/global/improvement_metrics.sqlite3"), "--metrics-db",
        help="ImprovementTracker DB consulted when a runner reports no metrics (tick).",
    ),
    run_id: str = typer.Option("", "--run-id", help="Lab run id (record-metrics)."),
    metrics: str = typer.Option(
        "", "--metrics",
        help=(
            'Metrics JSON for record-metrics, e.g. '
            '{"hypotheses_tested": 30, "findings_promoted": 3}.'
        ),
    ),
    execute: bool = typer.Option(
        False, "--execute",
        help=(
            "tick: actually execute the due window via a real webpent hunt "
            "subprocess (control = ENABLE_LESSON_CONSULTATION=false). "
            "Without it tick is a dry plan."
        ),
    ),
    state_path: str = typer.Option(
        "", "--state", help="Ops state JSON file (open/tick/record-metrics)."
    ),
    actor: str = typer.Option("", "--actor", help="Acting user (open/tick/record-metrics)."),
    as_json: bool = typer.Option(False, "--json", help="Render JSON."),
) -> None:
    """Weekly control-vs-treatment A/B scheduler for lesson impact (6.5).

    Declared verdict thresholds live in ``memory/ab_lab.AB_THRESHOLDS``
    (docs/PRODUCTION_FIX_PLAN_0270.md, C-10) — the CLI never invents
    decision numbers at runtime.
    """
    from webpent.memory.ab_lab import (
        LessonABLab,
        make_hunt_subprocess_runner,
        make_tracker_metrics_lookup,
    )
    from webpent.production.ops_state import OpsStateError  # noqa: F401 — typed exits parity

    lab = LessonABLab(str(db), metrics_lookup=make_tracker_metrics_lookup(str(metrics_db)))

    def _require_write_access() -> None:
        if not state_path or not actor:
            err_console.print(
                "[red]authorization refused:[/red] learning-ab "
                f"{action} needs --state and --actor (run_campaign permission)"
            )
            raise typer.Exit(code=2) from None
        state = _ops_state_or_exit(state_path)
        _authorized_role(state_path, state, actor, "run_campaign")

    if action == "open":
        _require_write_access()
        try:
            result = lab.open_week(
                client_id=client, target_url=target, mode=mode,
                authorization_ref=authorization,
            )
        except ValueError as exc:
            err_console.print(f"[red]learning-ab refused:[/red] {exc}")
            raise typer.Exit(code=2) from None
        if as_json:
            console.print_json(json.dumps(result, default=str))
            return
        week_runs = [run for run in lab.status()["runs"]
                     if run["week_key"] == result["week_key"]]
        console.print(
            f"[green]week {result['week_key']}[/green] open for "
            f"{result['client_id']} @ {result['target_url']} "
            f"(control=lessons OFF, treatment=lessons ON; already_open={result['already_open']})"
        )
        for run in week_runs:
            console.print(f"  run {run['run_id']} (arm={run['arm']}, lessons={run['lesson_flag']})")
        return

    if action == "tick":
        _require_write_access()
        runner = make_hunt_subprocess_runner() if execute else None
        try:
            result = lab.tick(runner=runner)
        except ValueError as exc:
            err_console.print(f"[red]learning-ab refused:[/red] {exc}")
            raise typer.Exit(code=2) from None
        if as_json:
            console.print_json(json.dumps(result, default=str))
            return
        if result["action"] == "none":
            console.print(f"[yellow]no due run[/yellow] ({result.get('reason')})")
        elif result["action"] == "planned_run":
            console.print(
                "[cyan]dry plan[/cyan] — would run "
                f"{result['run_id']} (arm={result['arm']}, lessons={result['lesson_flag']}); "
                "add --execute to launch the real hunt subprocess"
            )
        else:
            status_line = result.get("status") or result.get("error") or ""
            style = "green" if result["action"] == "run_executed" else "red"
            console.print(f"[{style}]{result['action']}[/{style}] {result.get('run_id')} "
                          f"(arm={result.get('arm')}) {status_line}")
        return

    if action == "status":
        snapshot = lab.status()
        if as_json:
            console.print_json(json.dumps(snapshot, default=str))
            return
        thresholds = snapshot["thresholds"]
        console.print("[bold]declared thresholds (C-10)[/bold]")
        console.print(
            f"  min_hypotheses_tested_per_arm={thresholds['min_hypotheses_tested_per_arm']}  "
            f"promotion_reduction_ratio={thresholds['promotion_reduction_ratio']:g}  "
            f"regression_tolerance_ratio={thresholds['regression_tolerance_ratio']:g}"
        )
        console.print(
            f"  require_no_confirmed_loss={thresholds['require_no_confirmed_loss']}  "
            f"max_inconclusive_weeks={thresholds['max_inconclusive_weeks']}"
        )
        console.print(
            f"[bold]lab[/bold] — consecutive_inconclusive="
            f"{snapshot['consecutive_inconclusive_weeks']} "
            f"paused_advisory={snapshot['paused_advisory']}"
        )
        table = Table(title="A/B weeks")
        for column in ("week", "client", "target", "mode", "status", "verdict"):
            table.add_column(column)
        for week in snapshot["weeks"]:
            verdict = (week.get("verdict") or {}).get("verdict", "-")
            table.add_row(week["week_key"], week["client_id"], week["target_url"],
                          week["mode"], week["status"], str(verdict))
        console.print(table)
        return

    if action == "record-metrics":
        _require_write_access()
        if not run_id or not metrics:
            err_console.print(
                "[red]learning-ab refused:[/red] record-metrics needs --run-id and --metrics"
            )
            raise typer.Exit(code=2) from None
        try:
            parsed = json.loads(metrics)
            result = lab.record_run_metrics(run_id, parsed)
        except (ValueError, TypeError) as exc:
            err_console.print(f"[red]learning-ab refused:[/red] {exc}")
            raise typer.Exit(code=2) from None
        if as_json:
            console.print_json(json.dumps(result, default=str))
            return
        console.print(f"[green]recorded[/green] {result['run_id']} -> {result['metrics']}")
        return

    err_console.print(f"[red]unknown action[/red] {action!r} — open|tick|status|record-metrics")
    raise typer.Exit(code=2)
