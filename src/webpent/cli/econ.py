"""Economist operator commands (NC-ECON-1, U-ECON-12).

``webpent econ`` is the operator console for the Economic Brain: every
command reads local state (portfolio yaml, radar SQLite DB, submission
journal), runs a deterministic advisory module, and prints JSON (or
markdown for the digest). Nothing is fetched (L-2), nothing is reported
(L-1), and every invocation is appended to the capped, redacted audit
log at ``<state-dir>/audit.jsonl`` (DoD).
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

from webpent.autonomous.hunt_contracts import redact
from webpent.econ.blind_spots import BlindSpotLocator
from webpent.econ.competitive import CompetitiveRadar
from webpent.econ.dashboard import Dashboard, load_portfolio_failsoft
from webpent.econ.learning_loop import LearningLoop
from webpent.econ.market_kb import MarketKB
from webpent.econ.portfolio import ACTIVE, STATES, WATCHING, PortfolioManager
from webpent.econ.roi_optimizer import ROIOptimizer, ValueContext
from webpent.econ.scope_negotiator import ScopeAnalysis
from webpent.econ.target_scorer import ScorerContext, TargetScorer
from webpent.econ.timing_advisor import TimingAdvisor, TimingContext

econ_app = typer.Typer(
    name="econ",
    help="The Economist: portfolio economics console (advisory only, local data).",
    no_args_is_help=True,
)
targets_app = typer.Typer(
    name="targets", help="Target scoring and ranking.", no_args_is_help=True
)
findings_app = typer.Typer(
    name="findings", help="Finding valuation and timing.", no_args_is_help=True
)
portfolio_app = typer.Typer(
    name="portfolio", help="Portfolio plan and transitions.", no_args_is_help=True
)
econ_app.add_typer(targets_app)
econ_app.add_typer(findings_app)
econ_app.add_typer(portfolio_app)

AUDIT_LIMIT = 1000
MAX_TEXT = 200


def _state_dir() -> Path:
    env = os.environ.get("WEBPENT_ECON_DIR")
    return Path(env) if env else Path("download/econ")


def _portfolio_path(explicit: Path | None) -> Path:
    if explicit is not None:
        return Path(explicit)
    env = os.environ.get("WEBPENT_ECON_PORTFOLIO")
    return Path(env) if env else Path("config/econ/portfolio.yaml")


def _journal_path(explicit: Path | None) -> Path:
    return Path(explicit) if explicit is not None else _state_dir() / "submissions.jsonl"


def _audit(*, command: str, **fields: object) -> None:
    """Append one redacted JSON line, then cap the log (DoD: every command audited)."""
    entry = {
        "ts": round(time.time(), 3),
        "command": redact(command)[:40],
        **{
            key: redact("" if value is None else str(value))[:MAX_TEXT]
            for key, value in fields.items()
        },
    }
    path = _state_dir() / "audit.jsonl"
    try:
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
    except OSError:
        pass  # audit is best-effort; the command's answer matters more (fail-soft)


def _emit(payload: object) -> None:
    typer.echo(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def _find_in_portfolio(target_id: str, portfolio_path: Path | None):
    portfolio = load_portfolio_failsoft(_portfolio_path(portfolio_path))
    return portfolio, portfolio.targets.get(str(target_id or "")[:120])


def _finding_from_row(row: dict, finding_id: str):
    from webpent.econ.roi_optimizer import Finding

    try:  # RT-10: corrupt numerics -> unparseable row, never a traceback
        return Finding(
            finding_id=str(finding_id),
            vuln_class=str(row.get("vuln_class") or ""),
            severity=str(row.get("severity") or "medium"),
            program_id=str(row.get("program_id") or ""),
            endpoint=str(row.get("endpoint") or ""),
            effort_hours=float(row.get("effort_hours") or 1.0),
            reputation_risk=float(row.get("reputation_risk") or 0.0),
            class_accept_rate=row.get("class_accept_rate"),
        )
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------------ targets
@targets_app.command("list")
def targets_list(
    tier: Annotated[str | None, typer.Option("--tier", help="Only this tier (S/A/B/C/D).")] = None,
    portfolio: Annotated[Path | None, typer.Option(
        "--portfolio", help="portfolio.yaml path."
    )] = None,
) -> None:
    """Score every portfolio target and list them, ranked (advisory)."""
    _audit(command="econ targets list", tier=tier)
    scorer = TargetScorer(MarketKB())
    now = time.time()
    rows = []
    pfolio = load_portfolio_failsoft(_portfolio_path(portfolio))
    for target_id in sorted(pfolio.targets):
        pt = pfolio.targets[target_id]
        score = scorer.score(pt.target, ScorerContext(now=now))
        rows.append({**score.as_dict(), "state": pt.state})
    if tier:
        rows = [r for r in rows if r["tier"] == str(tier).upper()]
    _emit({"count": len(rows), "targets": rows, "advisory": True})


@targets_app.command("score")
def targets_score(
    target_id: Annotated[str, typer.Argument(..., help="Target id from the portfolio.")],
    portfolio: Annotated[Path | None, typer.Option(
        "--portfolio", help="portfolio.yaml path."
    )] = None,
) -> None:
    """Full transparency score for one target (L-4)."""
    _audit(command="econ targets score", target=target_id)
    pfolio, pt = _find_in_portfolio(target_id, portfolio)
    if pt is None:
        _emit({"found": False, "target_id": target_id, "advisory": True})
        return
    score = TargetScorer(MarketKB()).score(pt.target, ScorerContext(now=time.time()))
    _emit({"found": True, **score.as_dict()})


# ----------------------------------------------------------------- findings
def _load_journal_finding(journal: Path, finding_id: str) -> dict | None:
    try:
        lines = Path(journal).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    row: dict | None = None
    # R2-econ-04: append-only journal - keep the TAIL of the file so the
    # newest records stay visible once it exceeds the cap.
    for line in lines[-4096:]:
        with suppress(ValueError):
            row = json.loads(line)
        if isinstance(row, dict) and str(row.get("finding_id") or "") == finding_id:
            return row
    return None


@findings_app.command("value")
def findings_value(
    finding_id: Annotated[str, typer.Argument(..., help="Finding id in the local journal.")],
    journal: Annotated[Path | None, typer.Option(
        "--journal", help="findings journal path."
    )] = None,
) -> None:
    """EV valuation of one finding (U-ECON-4), from the local journal."""
    _audit(command="econ findings value", finding=finding_id)
    row = _load_journal_finding(_journal_path(journal), finding_id)
    if row is None:
        _emit({"found": False, "finding_id": finding_id, "advisory": True})
        return
    finding = _finding_from_row(row, finding_id)
    if finding is None:  # RT-10: corrupt numerics -> answered as missing
        _emit({"found": False, "finding_id": finding_id, "advisory": True})
        return
    valuation = ROIOptimizer(MarketKB()).value(
        finding, ValueContext(now=time.time())
    )
    _emit({"found": True, **valuation.as_dict()})


@findings_app.command("timing")
def findings_timing(
    finding_id: Annotated[str, typer.Argument(..., help="Finding id in the local journal.")],
    journal: Annotated[Path | None, typer.Option(
        "--journal", help="findings journal path."
    )] = None,
) -> None:
    """Submission-timing decision for one finding (U-ECON-5)."""
    _audit(command="econ findings timing", finding=finding_id)
    row = _load_journal_finding(_journal_path(journal), finding_id)
    if row is None:
        _emit({"found": False, "finding_id": finding_id, "advisory": True})
        return
    finding = _finding_from_row(row, finding_id)
    if finding is None:  # RT-10: corrupt numerics -> answered as missing
        _emit({"found": False, "finding_id": finding_id, "advisory": True})
        return
    optimizer = ROIOptimizer(MarketKB())
    valuation = optimizer.value(finding, ValueContext(now=time.time()))
    decision = TimingAdvisor(MarketKB()).decide(
        finding, valuation, TimingContext(now=time.time())
    )
    _emit({"found": True, **decision.as_dict()})


# ---------------------------------------------------------------- portfolio
@portfolio_app.command("plan")
def portfolio_plan(
    hours: Annotated[float, typer.Option(
        "--hours", min=0.0, max=168.0, help="Weekly hours."
    )] = 40.0,
    portfolio: Annotated[Path | None, typer.Option(
        "--portfolio", help="portfolio.yaml path."
    )] = None,
) -> None:
    """One day's hour split across the portfolio (U-ECON-6/10)."""
    _audit(command="econ portfolio plan", hours=hours)
    pfolio = load_portfolio_failsoft(_portfolio_path(portfolio))
    # UM-DR-33 §3.2: runtime state honors WEBPENT_ECON_DIR (never the
    # tracked repository default) so operator/CI invocations cannot dirty
    # the working tree.
    plan = PortfolioManager(
        log_path=_state_dir() / "portfolio_transitions.jsonl",
    ).daily_plan(pfolio, hours)
    _emit(plan.as_dict())


@portfolio_app.command("transition")
def portfolio_transition(
    target_id: Annotated[str, typer.Argument(...)],
    new_state: Annotated[str, typer.Argument(...)],
    reason: Annotated[str, typer.Option(
        "--reason", help="Why the operator moves it."
    )] = "operator decision",
    portfolio: Annotated[Path | None, typer.Option(
        "--portfolio", help="portfolio.yaml path."
    )] = None,
) -> None:
    """Apply one portfolio state transition (human-in-the-loop, L-8)."""
    _audit(command="econ portfolio transition", target=target_id, state=new_state)
    pfolio, pt = _find_in_portfolio(target_id, portfolio)
    if pt is None:
        _emit({"found": False, "target_id": target_id, "advisory": True})
        raise typer.Exit(1)
    try:
        # UM-DR-33 §3.2: the transition journal is runtime state — it goes
        # to the operator-configured state dir (WEBPENT_ECON_DIR), never
        # to the tracked repository default. Regression: the full suite
        # must leave `git status` clean.
        manager = PortfolioManager(
            log_path=_state_dir() / "portfolio_transitions.jsonl",
        )
        manager.transition(pfolio, target_id, new_state, reason)
        manager.save(pfolio, _portfolio_path(portfolio))  # RT-02: persist the move
    except ValueError as exc:
        _emit({"moved": False, "error": str(exc), "legal_states": list(STATES), "advisory": True})
        raise typer.Exit(1) from exc
    _emit({
        "moved": True,
        "target_id": target_id,
        "from_state": pt.state,
        "to_state": new_state,
        "reason": reason,
        "advisory": True,
    })


# ------------------------------------------------------------------- digest
@econ_app.command("digest")
def digest(
    days: Annotated[int, typer.Option("--days", min=1, max=365, help="Look-back window.")] = 7,
    fmt: Annotated[str, typer.Option("--format", help="md or json.")] = "md",
    portfolio: Annotated[Path | None, typer.Option(
        "--portfolio", help="portfolio.yaml path."
    )] = None,
) -> None:
    """The daily digest: portfolio, opportunities, projection, alerts."""
    _audit(command="econ digest", days=days, fmt=fmt)
    portfolio_file = _portfolio_path(portfolio)
    board = Dashboard(portfolio_path=portfolio_file)
    pfolio = load_portfolio_failsoft(portfolio_file)
    spots: list[dict[str, object]] = []
    # RT-07: --days drives a real radar query for ACTIVE/WATCHING programs.
    seen_programs: set[str] = set()
    radar = CompetitiveRadar(_state_dir() / "competitive.db")
    for tid in sorted(pfolio.targets):
        if len(seen_programs) >= 8:
            break
        pt = pfolio.targets[tid]
        program = str(pt.target.program_id or "")
        if pt.state not in (ACTIVE, WATCHING) or not program or program in seen_programs:
            continue
        seen_programs.add(program)
        for opp in radar.find_opportunities(program, window_days=float(days))[:4]:
            spots.append({
                "kind": "radar_gap",
                "identifier": f"{opp.vuln_class} on {opp.program_id}",
                "estimated_ev": 0.0,
                "confidence": opp.confidence,
            })
    built = board.build_digest(hours_per_week=40.0, spots=spots)
    if str(fmt).lower() == "json":
        _emit(built.as_dict())
    else:
        typer.echo(board.as_markdown(built))


# ----------------------------------------------------------------- insights
@econ_app.command("insights")
def insights(
    since: Annotated[str, typer.Option("--since", help="Look-back, e.g. 30d.")] = "30d",
    journal: Annotated[Path | None, typer.Option(
        "--journal", help="submissions journal path."
    )] = None,
) -> None:
    """Learning-loop insights over the submission journal (U-ECON-11)."""
    _audit(command="econ insights", since=since)
    days = 30
    with suppress(ValueError):
        days = max(1, int(str(since).rstrip("dD")))
    loop = LearningLoop(_journal_path(journal), log_path=_state_dir() / "learning_insights.jsonl")
    found = loop.analyze(period_days=days)
    _emit({"count": len(found), "insights": [i.as_dict() for i in found], "advisory": True})


# --------------------------------------------------------------- blind spots
def _scope_for(target_row) -> ScopeAnalysis:
    return ScopeAnalysis(in_scope=[str(s) for s in (target_row.target.scope_entries or [])])


@econ_app.command("blind-spots")
def blind_spots(
    target_id: Annotated[str, typer.Argument(...)],
    portfolio: Annotated[Path | None, typer.Option(
        "--portfolio", help="portfolio.yaml path."
    )] = None,
) -> None:
    """Where the public hunters are NOT looking (U-ECON-9)."""
    _audit(command="econ blind-spots", target=target_id)
    pfolio, pt = _find_in_portfolio(target_id, portfolio)
    if pt is None:
        _emit({"found": False, "target_id": target_id, "spots": [], "advisory": True})
        return
    radar = CompetitiveRadar(_state_dir() / "competitive.db")
    locator = BlindSpotLocator()
    spots = locator.locate(pt.target, radar, _scope_for(pt))
    _emit({
        "target_id": target_id,
        "count": len(spots),
        "spots": [s.as_dict() for s in spots],
        "advisory": True,
    })


@econ_app.command("opportunities")
def opportunities(
    target_id: Annotated[str, typer.Argument(...)],
    portfolio: Annotated[Path | None, typer.Option(
        "--portfolio", help="portfolio.yaml path."
    )] = None,
) -> None:
    """Watched vuln classes with no public finding inside the window (U-ECON-7)."""
    _audit(command="econ opportunities", target=target_id)
    pfolio, pt = _find_in_portfolio(target_id, portfolio)
    if pt is None:  # RT-08: unknown target is answered, not silently probed
        _emit({
            "found": False,
            "target_id": target_id,
            "count": 0,
            "opportunities": [],
            "advisory": True,
        })
        return
    program = pt.target.program_id
    radar = CompetitiveRadar(_state_dir() / "competitive.db")
    found = radar.find_opportunities(program)
    _emit({
        "found": True,
        "program_id": program,
        "count": len(found),
        "opportunities": [o.as_dict() for o in found],
        "advisory": True,
    })


__all__ = ["econ_app"]
