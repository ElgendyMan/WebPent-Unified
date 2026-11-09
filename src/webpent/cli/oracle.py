"""THE ORACLE — CLI (v88, U-ORACLE-12).

House style mirrors cli/apex.py: a typer sub-app, the PREAMBLE_LINE printed
first on every command, one capped audit line appended per invocation, and
advisory-only behavior throughout (ORACLE-L-10). The package contains no
network primitive at all (ORACLE-L-2): `gather` ingests operator-collected
findings from a JSON file, or executes operator-injected fetchers from a
module the operator names — the framework itself never opens a socket.

State lives under --oracle-dir (default .oracle-state): audit.jsonl (capped),
report.json, stack.json, signals.json, graph.json, predictions.json,
proposals.json, traces.json, views.json, estimates.json, ledger.jsonl.
"""

from __future__ import annotations

import importlib.util
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import typer

from webpent.oracle import PREAMBLE_LINE
from webpent.oracle.chain_composer import ChainComposer
from webpent.oracle.dashboard import STAGE_KEYS, OracleDashboardSnapshot, render
from webpent.oracle.graph_builder import GraphBuilder
from webpent.oracle.impact_maximizer import ImpactMaximizer
from webpent.oracle.kill_chain import KillChainSimulator
from webpent.oracle.models import (
    OracleLawError,
    Target,
    canonical_hash,
    sanitize_payload,
    sha256_text,
)
from webpent.oracle.osint import (
    OSINTAggregator,
    OsintFinding,
    OsintReport,
    load_source_configs,
)
from webpent.oracle.path_predictor import PathPredictor
from webpent.oracle.perspectives import PerspectiveAnalyzer
from webpent.oracle.reporter import OracleReporter
from webpent.oracle.signal_aggregator import SignalAggregator
from webpent.oracle.stack_inferrer import StackInferrer
from webpent.oracle.validator import PredictionValidator

app = typer.Typer(help="The Oracle — passive advisory surface (v88)")
oracle_app = app

AUDIT_CAP = 1000


# -- shared helpers -----------------------------------------------------------

def _workdir() -> Path:
    return Path(os.environ.get("WEBPENT_ORACLE_WORKDIR", os.getcwd()))


def _oracle_dir(value: str | None) -> Path:
    return Path(value) if value else Path(".oracle-state")


def _config_dir() -> Path:
    return _workdir() / "config" / "oracle"


def _audit(oracle_dir: Path, command: str) -> None:
    path = oracle_dir / "audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = (path.read_text(encoding="utf-8").splitlines()
             if path.is_file() else [])
    lines.append(
        json.dumps(
            {"command": command, "ts": round(time.time(), 3)}, sort_keys=True
        )
    )
    if len(lines) > AUDIT_CAP:
        lines = lines[-AUDIT_CAP:]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _emit(
    oracle_dir: Path, command: str, payload: dict | None = None,
    human_lines: list[str] | None = None,
) -> None:
    """Print preamble, human lines, then the single-line JSON payload last;
    append one capped audit line."""
    typer.echo(PREAMBLE_LINE)
    for line in human_lines or []:
        typer.echo(line)
    if payload is not None:
        typer.echo(json.dumps(payload, sort_keys=False, separators=(",", ":")))
    _audit(oracle_dir, command)


def _artifact_path(oracle_dir: Path, stage: str) -> Path:
    return oracle_dir / f"{stage}.json"


def _save(oracle_dir: Path, stage: str, payload: dict) -> Path:
    path = _artifact_path(oracle_dir, stage)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    return path


def _stage_present(oracle_dir: Path, stage: str) -> bool:
    return _artifact_path(oracle_dir, stage).is_file()


def _load_report(oracle_dir: Path) -> OsintReport:
    path = _artifact_path(oracle_dir, "report")
    if not path.is_file():
        raise OracleLawError(
            "no gathered report in this oracle dir; run `oracle gather` first"
        )
    raw = json.loads(path.read_text(encoding="utf-8"))
    findings = [
        OsintFinding(
            source=f["source"],
            category=f["category"],
            raw_data=f["raw_data"],
            confidence=float(f["confidence"]),
            extracted_at=datetime.fromisoformat(f["extracted_at"]),
            evidence_hash=f["evidence_hash"],
            core_hash=f.get("core_hash", ""),
            is_verified=bool(f.get("is_verified", False)),
        )
        for f in raw["findings"]
    ]
    return OsintReport(
        target_id=raw["target_id"],
        sources_used=raw["sources_used"],
        findings=findings,
        duration_seconds=float(raw.get("duration_seconds", 0.0)),
        coverage=dict(raw.get("coverage", {})),
        zero_touch_proof=dict(raw.get("zero_touch_proof", {})),
    )


def _pipeline(oracle_dir: Path):
    """Deterministic passive pipeline from the recorded report onward."""
    report = _load_report(oracle_dir)
    sigs = _config_dir() / "attack_signatures.yaml"
    stack = StackInferrer(sigs).infer(report)
    stack = StackInferrer(sigs).enrich_with_cves(stack)
    signals = SignalAggregator(sigs).aggregate(report, stack)
    graph = GraphBuilder(
        _config_dir() / "graph_rules.yaml"
    ).build(report, stack_profile=stack, signals=signals)
    return report, stack, signals, graph


def _ingest_finding(entry: dict) -> OsintFinding:
    """Sanitize one operator-collected raw finding (ORACLE-L-3/L-4).
    RT-03: the old top-level pass let a nested
    {"meta": {"api_key": "sk-live-…"}} reach the ledger raw; the shared
    recursive sanitize_payload now walks every depth, here and in gather."""
    sanitized = sanitize_payload(dict(entry.get("raw_data") or {}))
    confidence = entry.get("confidence", 0.5)
    if not isinstance(confidence, (int, float)):
        confidence = 0.5
    return OsintFinding(
        source=str(entry.get("source") or "operator"),
        category=str(entry.get("category") or "note"),
        raw_data=sanitized,
        confidence=float(confidence),
        extracted_at=datetime.now(timezone.utc),
        evidence_hash=canonical_hash(sanitized),
        core_hash=canonical_hash(sanitized),
    )


# -- status (the dashboard) ----------------------------------------------------

@app.command("status")
def status(
    oracle_dir: str = typer.Option(".oracle-state", help="state directory"),
) -> None:
    """Render the operator dashboard from recorded state."""
    directory = _oracle_dir(oracle_dir)
    snapshot = _snapshot(directory)
    _emit(directory, "status", payload=snapshot.to_dict(),
          human_lines=[render(snapshot)])


def _snapshot(directory: Path) -> OracleDashboardSnapshot:
    stages = {stage: _stage_present(directory, stage) for stage in STAGE_KEYS}
    counts: dict[str, int] = {}
    sources: list[str] = []
    coverage: dict[str, str] = {}
    zero_touch: dict = {}
    target_id = ""
    if stages["report"]:
        report = _load_report(directory)
        target_id = report.target_id
        counts["findings"] = len(report.findings)
        sources = list(report.sources_used)
        coverage = dict(report.coverage)
        zero_touch = dict(report.zero_touch_proof)
        if stages["graph"]:
            graph_raw = json.loads(
                _artifact_path(directory, "graph").read_text(encoding="utf-8")
            )
            counts["nodes"] = len(graph_raw.get("nodes", []))
            counts["edges"] = len(graph_raw.get("edges", []))
        if stages["signals"]:
            signals_raw = json.loads(
                _artifact_path(directory, "signals").read_text(encoding="utf-8")
            )
            counts["signals"] = len(signals_raw.get("signals", []))
    for stage, count_key in (
        ("predictions", "predictions"), ("proposals", "proposals"),
        ("traces", "traces"), ("views", "perspectives"),
        ("estimates", "estimates"),
    ):
        if stages[stage]:
            raw = json.loads(
                _artifact_path(directory, stage).read_text(encoding="utf-8")
            )
            counts[count_key] = len(raw.get(stage if stage != "views"
                                             else "views", []))
    estimates: list = []
    if stages["estimates"]:
        estimates = json.loads(
            _artifact_path(directory, "estimates").read_text(encoding="utf-8")
        ).get("estimates", [])
    top = estimates[0] if estimates else None
    validation = _validation_status(directory)
    return OracleDashboardSnapshot(
        target_id=target_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        stages=stages,
        counts=counts,
        sources=sources,
        coverage=coverage,
        zero_touch=zero_touch,
        top_impact=top,
        validation=validation,
    )


def _validation_status(directory: Path) -> dict:
    ledger = directory / "ledger.jsonl"
    if not ledger.is_file():
        return {}
    validator = PredictionValidator(
        _config_dir() / "validator.yaml", ledger_path=ledger
    )
    claim = validator.accuracy()
    return {
        "resolved": validator.resolved_outcomes(),
        "claim": claim if claim is not None else None,
        "note": (
            "accuracy claimable only at the configured minimum sample size "
            "(ORACLE-L-8)"
        ) if claim is None else "",
    }


# -- gather ----------------------------------------------------------------------

@app.command("gather")
def gather(
    target: str = typer.Option(..., "--target", help="authorized target host"),
    scopes: str = typer.Option("", "--scopes",
                               help="comma-separated allowed scopes"),
    findings_json: str = typer.Option(
        None, "--findings-json",
        help="JSON of operator-collected raw findings to ingest"),
    fetcher_module: str = typer.Option(
        None, "--fetcher-module",
        help="operator-provided python module defining FETCHERS"),
    oracle_dir: str = typer.Option(".oracle-state", help="state directory"),
) -> None:
    """Ingest passive evidence. The framework never opens a socket: data
    arrives either pre-collected (--findings-json) or through operator-
    injected fetchers (--fetcher-module)."""
    directory = _oracle_dir(oracle_dir)
    if not findings_json and not fetcher_module:
        raise typer.BadParameter(
            "provide --findings-json or --fetcher-module; the oracle never "
            "reaches the network itself"
        )
    if findings_json:
        data = json.loads(Path(findings_json).read_text(encoding="utf-8"))
        entries = data.get("findings") if isinstance(data, dict) else data
        if not isinstance(entries, list):
            raise typer.BadParameter("findings JSON must hold a findings list")
        findings = [_ingest_finding(e) for e in entries]
        # RT-07 (ORACLE-L-5): a finding whose source has no documented legal
        # basis must never enter the ledger — fail closed, naming the id.
        known = {c.source_id for c in load_source_configs(
            _config_dir() / "osint_sources.yaml"
        )}
        unknown = sorted({f.source for f in findings} - known)
        if unknown:
            raise typer.BadParameter(
                "unknown source id(s) " + ", ".join(repr(u) for u in unknown)
                + " — not in osint_sources.yaml, no documented legal basis "
                "(ORACLE-L-5)"
            )
        guard_target = target
        report = OsintReport(
            target_id=target,
            sources_used=sorted({f.source for f in findings}),
            findings=findings,
            duration_seconds=0.0,
            coverage={},
            zero_touch_proof={
                "guard": "ZeroTouchGuard", "target": guard_target,
                "active": True,
            },
        )
    else:
        module_path = Path(fetcher_module)
        # RT-10: a missing file or a module without FETCHERS used to die
        # with a raw AttributeError; both failures are named explicitly.
        if not module_path.is_file():
            raise typer.BadParameter(
                f"fetcher module not found: {module_path}"
            )
        spec = importlib.util.spec_from_file_location(
            "oracle_operator_fetchers", module_path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if not hasattr(module, "FETCHERS"):
            raise typer.BadParameter(
                f"fetcher module {module_path} defines no FETCHERS mapping "
                "(source_id → callable); see the operator fetcher contract"
            )
        fetchers = getattr(module, "FETCHERS", {})
        api_keys = getattr(module, "API_KEYS", {})
        aggregator = OSINTAggregator(
            _config_dir() / "osint_sources.yaml",
            fetchers=fetchers, api_keys=api_keys,
        )
        scope_list = [s for s in scopes.split(",") if s] or [target]
        report = aggregator.gather(Target(host=target, allowed_scopes=scope_list))
    saved = _save(directory, "report", report.to_dict())
    _emit(
        directory, "gather",
        payload={
            "target_id": report.target_id,
            "findings": len(report.findings),
            "sources_used": report.sources_used,
            "coverage": report.coverage,
            "zero_touch_proof": report.zero_touch_proof,
            "artifact": saved.name,
        },
    )


# -- infer-stack --------------------------------------------------------------------

@app.command("infer-stack")
def infer_stack(
    oracle_dir: str = typer.Option(".oracle-state", help="state directory"),
) -> None:
    """Infer the technology stack from recorded evidence only."""
    directory = _oracle_dir(oracle_dir)
    report, stack, _signals, _graph = _pipeline(directory)
    saved = _save(directory, "stack", stack.to_dict())
    _emit(
        directory, "infer-stack",
        payload={
            "target_id": report.target_id,
            "components": len(stack.components),
            "cves_mapped": len(stack.cves),
            "artifact": saved.name,
        },
    )


# -- signals -----------------------------------------------------------------------

@app.command("signals")
def signals_cmd(
    oracle_dir: str = typer.Option(".oracle-state", help="state directory"),
) -> None:
    """Aggregate oracle signals from recorded evidence."""
    directory = _oracle_dir(oracle_dir)
    report, _stack, sig, _graph = _pipeline(directory)
    saved = _save(directory, "signals", {"signals": [s.to_dict() for s in sig]})
    _emit(
        directory, "signals",
        payload={
            "target_id": report.target_id,
            "count": len(sig),
            "artifact": saved.name,
        },
    )


# -- graph ---------------------------------------------------------------------------

@app.command("graph")
def graph_cmd(
    oracle_dir: str = typer.Option(".oracle-state", help="state directory"),
) -> None:
    """Build the attack graph from confirmed evidence (ORACLE-L-6)."""
    directory = _oracle_dir(oracle_dir)
    report, _stack, _sig, g = _pipeline(directory)
    saved = _save(directory, "graph", g.to_dict())
    _emit(
        directory, "graph",
        payload={
            "target_id": report.target_id,
            "nodes": len(g.nodes),
            "edges": len(g.edges),
            "artifact": saved.name,
        },
    )


# -- predict -------------------------------------------------------------------------

@app.command("predict")
def predict(
    oracle_dir: str = typer.Option(".oracle-state", help="state directory"),
) -> None:
    """Predict entry-to-target paths; record each for validation (L-8)."""
    directory = _oracle_dir(oracle_dir)
    _report, _stack, _sig, g = _pipeline(directory)
    predictions = PathPredictor(
        _config_dir() / "graph_rules.yaml"
    ).predict(g)
    saved = _save(
        directory, "predictions",
        {"predictions": [p.to_dict() for p in predictions]},
    )
    validator = PredictionValidator(
        _config_dir() / "validator.yaml",
        ledger_path=directory / "ledger.jsonl",
    )
    recorded = 0
    for p in predictions:
        prediction_id = sha256_text("|".join(p.path))[:16]
        try:
            validator.record(prediction_id, "path_prediction")
            recorded += 1
        except OracleLawError:
            recorded += 0   # already on the ledger; idempotent re-run
    _emit(
        directory, "predict",
        payload={
            "predictions": len(predictions),
            "recorded_for_validation": recorded,
            "artifact": saved.name,
        },
    )


# -- compose ------------------------------------------------------------------------

@app.command("compose")
def compose(
    oracle_dir: str = typer.Option(".oracle-state", help="state directory"),
) -> None:
    """Compose advisory chain proposals from the attack graph."""
    directory = _oracle_dir(oracle_dir)
    _report, _stack, _sig, g = _pipeline(directory)
    predictions = PathPredictor(
        _config_dir() / "graph_rules.yaml"
    ).predict(g)
    proposals = ChainComposer(
        _config_dir() / "attack_chains.yaml"
    ).compose(g, predictions)
    saved = _save(
        directory, "proposals",
        {"proposals": [p.to_dict() for p in proposals]},
    )
    _emit(
        directory, "compose",
        payload={"proposals": len(proposals), "artifact": saved.name},
    )


# -- simulate -------------------------------------------------------------------------

@app.command("simulate")
def simulate(
    oracle_dir: str = typer.Option(".oracle-state", help="state directory"),
) -> None:
    """Dry-run kill-chain simulations; nothing executes (executed=False)."""
    directory = _oracle_dir(oracle_dir)
    _report, _stack, _sig, g = _pipeline(directory)
    predictions = PathPredictor(
        _config_dir() / "graph_rules.yaml"
    ).predict(g)
    proposals = ChainComposer(
        _config_dir() / "attack_chains.yaml"
    ).compose(g, predictions)
    simulator = KillChainSimulator(_config_dir() / "kill_chain.yaml")
    traces = [simulator.simulate(g, p) for p in proposals]
    saved = _save(
        directory, "traces", {"traces": [t.to_dict() for t in traces]}
    )
    executed_any = any(t.executed for t in traces)
    if executed_any:
        raise OracleLawError("a simulation reported execution (ORACLE-L-10)")
    _emit(
        directory, "simulate",
        payload={
            "traces": len(traces),
            "executed": False,
            "artifact": saved.name,
        },
    )


# -- perspectives ----------------------------------------------------------------------

@app.command("perspectives")
def perspectives(
    oracle_dir: str = typer.Option(".oracle-state", help="state directory"),
) -> None:
    """Analyze the evidence from six minds (ORACLE-L-7)."""
    directory = _oracle_dir(oracle_dir)
    report, _stack, _sig, _g = _pipeline(directory)
    views = PerspectiveAnalyzer(
        _config_dir() / "perspectives.yaml"
    ).analyze(report)
    saved = _save(
        directory, "views", {"views": [v.to_dict() for v in views]}
    )
    _emit(
        directory, "perspectives",
        payload={"views": len(views), "artifact": saved.name},
    )


# -- impact ---------------------------------------------------------------------------

@app.command("impact")
def impact(
    oracle_dir: str = typer.Option(".oracle-state", help="state directory"),
) -> None:
    """Rank advisory proposals by business impact (ORACLE-L-9)."""
    directory = _oracle_dir(oracle_dir)
    _report, _stack, _sig, g = _pipeline(directory)
    predictions = PathPredictor(
        _config_dir() / "graph_rules.yaml"
    ).predict(g)
    proposals = ChainComposer(
        _config_dir() / "attack_chains.yaml"
    ).compose(g, predictions)
    estimates = ImpactMaximizer(
        _config_dir() / "impact_strategies.yaml"
    ).maximize(g, proposals)
    saved = _save(
        directory, "estimates",
        {"estimates": [e.to_dict() for e in estimates]},
    )
    _emit(
        directory, "impact",
        payload={
            "estimates": len(estimates),
            "top": estimates[0].to_dict() if estimates else None,
            "artifact": saved.name,
        },
    )


# -- validate ---------------------------------------------------------------------------

@app.command("validate")
def validate(
    record: str = typer.Option(None, "--record", help="prediction id"),
    kind: str = typer.Option(None, "--kind", help="prediction kind"),
    outcome: str = typer.Option(None, "--outcome", help="prediction id"),
    result: str = typer.Option(None, "--result", help="confirmed|refuted"),
    oracle_dir: str = typer.Option(".oracle-state", help="state directory"),
) -> None:
    """Record predictions and outcomes; no accuracy claim without samples."""
    directory = _oracle_dir(oracle_dir)
    validator = PredictionValidator(
        _config_dir() / "validator.yaml",
        ledger_path=directory / "ledger.jsonl",
    )
    payload: dict = {}
    if outcome and not result:
        # RT-04: the old default silently recorded "confirmed", so a typo
        # (`validate --outcome pred-x`, no --result) inflated the accuracy
        # ledger. An outcome is a judgment; it must be stated (ORACLE-L-8).
        raise typer.BadParameter(
            "recording an outcome requires --result confirmed|refuted; "
            "the oracle never defaults a judgment to confirmed"
        )
    if record:
        validator.record(record, kind or "path_prediction")
        payload["recorded"] = record
    if outcome:
        validator.record_outcome(outcome, result)
        payload["outcome"] = {"id": outcome, "result": result}
    claim = validator.accuracy()
    payload.update({
        "resolved": validator.resolved_outcomes(),
        "accuracy_claim": claim,
    })
    _emit(directory, "validate", payload=payload)


# -- report ------------------------------------------------------------------------------

@app.command("report")
def report(
    fmt: str = typer.Option("json", "--format", help="json|md|pdf"),
    out: str = typer.Option(None, "--out", help="output file for md/pdf"),
    oracle_dir: str = typer.Option(".oracle-state", help="state directory"),
) -> None:
    """Build the seven-section advisory report from recorded evidence."""
    directory = _oracle_dir(oracle_dir)
    rep, _stack, _sig, g = _pipeline(directory)
    predictions = PathPredictor(
        _config_dir() / "graph_rules.yaml"
    ).predict(g)
    proposals = ChainComposer(
        _config_dir() / "attack_chains.yaml"
    ).compose(g, predictions)
    simulator = KillChainSimulator(_config_dir() / "kill_chain.yaml")
    traces = [simulator.simulate(g, p) for p in proposals]
    views = PerspectiveAnalyzer(
        _config_dir() / "perspectives.yaml"
    ).analyze(rep)
    estimates = ImpactMaximizer(
        _config_dir() / "impact_strategies.yaml"
    ).maximize(g, proposals)
    validator = PredictionValidator(
        _config_dir() / "validator.yaml",
        ledger_path=directory / "ledger.jsonl",
    )
    reporter = OracleReporter(_config_dir() / "osint_sources.yaml")
    doc = reporter.build(
        rep, g, stack_profile=_stack, predictions=predictions,
        proposals=proposals, traces=traces, views=views,
        estimates=estimates,
        validator_claim=validator.accuracy(),
    )
    if fmt == "json":
        _emit(directory, "report", payload=doc.to_dict())
        return
    if fmt == "md":
        path = Path(out) if out else directory / "oracle_report.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(reporter.to_markdown(doc), encoding="utf-8")
    elif fmt == "pdf":
        if out is None:
            raise typer.BadParameter("--out is required for --format pdf")
        path = reporter.to_pdf(doc, Path(out))
    else:
        raise typer.BadParameter(f"unknown format {fmt!r}")
    _emit(
        directory, "report",
        payload={"format": fmt, "output": str(path)},
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
