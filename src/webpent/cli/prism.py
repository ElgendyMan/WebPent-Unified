# src/webpent/cli/prism.py
"""THE PRISM CLI (v89) — `webpent prism`.

Nine advisory commands over the Prism layers. Every command prints the
advisory preamble (PRISM-L-2) and never executes, blocks or decides
anything by itself. Config resolves from the working directory
(config/prism), overridable per command, mirroring the oracle CLI.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from webpent.prism import PREAMBLE_LINE
from webpent.prism.anomaly_filter import (
    AnomalyFilter,
    FilterContext,
    RawAnomaly,
)
from webpent.prism.classifier import EvidenceClassifier
from webpent.prism.ledger import CampaignLedger
from webpent.prism.metrics import MetricsEngine, Observation
from webpent.prism.patterns import PatternExtractor
from webpent.prism.rabbit_hole import (
    ExplorationState,
    RabbitHoleProtector,
)
from webpent.prism.rabbit_hole import (
    Signal as HoleSignal,
)
from webpent.prism.scorer import EvidenceScorer
from webpent.prism.taxonomy import EvidenceTaxonomy

prism_app = typer.Typer(
    name="prism",
    help="THE PRISM: advisory evidence scoring, learning and curiosity "
         "filters (never blocks, never executes).",
    no_args_is_help=True,
)
console = Console()

DEFAULT_DB = Path("download") / "prism" / "ledger.db"


def _workdir() -> Path:
    return Path(os.environ.get("WEBPENT_PRISM_WORKDIR", os.getcwd()))


def _config_dir() -> Path:
    return _workdir() / "config" / "prism"


def _layers() -> tuple[EvidenceTaxonomy, EvidenceClassifier,
                       EvidenceScorer]:
    taxonomy = EvidenceTaxonomy(_config_dir() / "taxonomy.yaml")
    classifier = EvidenceClassifier(
        _config_dir() / "classifier_patterns.yaml", taxonomy
    )
    scorer = EvidenceScorer(
        _config_dir() / "scorer_weights.yaml", taxonomy
    )
    return taxonomy, classifier, scorer


# -- 1. score ----------------------------------------------------------------------

@prism_app.command("score")
def score(
    evidence_hash: str = typer.Argument(..., help="SHA-256 of the evidence."),
    source: str = typer.Option(..., "--source",
                               help="crawler|probe|browser|oracle|validator"
                                    "|brain|operator|ledger"),
    signal_kind: str = typer.Option(..., "--signal-kind"),
    strength: str = typer.Option(..., "--strength"),
    reproducibility: str = typer.Option(..., "--reproducibility"),
    corroboration: str = typer.Option(..., "--corroboration"),
    rationale: str = typer.Option(..., "--rationale"),
) -> None:
    """Score one piece of evidence and print its tier + recommendation."""
    taxonomy, classifier, scorer = _layers()
    profile = taxonomy.profile(
        evidence_hash=evidence_hash, source=source,
        signal_kind=signal_kind, strength=strength,
        reproducibility=reproducibility, corroboration=corroboration,
        rationale=rationale,
    )
    result = scorer.score(profile)
    table = Table(title=f"Evidence score — {evidence_hash[:12]}")
    for column in ("Field", "Value"):
        table.add_column(column)
    for key, value in result.to_dict().items():
        if key != "components":
            table.add_row(key, str(value))
    console.print(table)
    console.print(PREAMBLE_LINE)


# -- 2. campaigns ---------------------------------------------------------------------

@prism_app.command("campaigns")
def campaigns(
    db: Annotated[Path, typer.Option(
        "--db", help="Ledger database."
    )] = DEFAULT_DB,
) -> None:
    """List campaigns from the local ledger (hashed targets only)."""
    ledger = CampaignLedger(db)
    try:
        rows = ledger._conn.execute(
            "SELECT campaign_id, name, opened_at FROM campaigns "
            "ORDER BY opened_at DESC"
        ).fetchall()
        if not rows:
            console.print("No campaigns recorded yet.")
            return
        table = Table(title="Campaigns")
        for column in ("Campaign", "Name", "Opened"):
            table.add_column(column)
        for row in rows:
            table.add_row(row["campaign_id"], row["name"],
                          row["opened_at"][:19])
        console.print(table)
    finally:
        ledger.close()
    console.print(PREAMBLE_LINE)


# -- 3. patterns list ------------------------------------------------------------------

@prism_app.command("patterns-list")
def patterns_list(
    records: Annotated[Path, typer.Option(
        "--records", help="JSON file of outcome records."
    )] = ...,
) -> None:
    """Extract and list learned patterns from outcome records."""
    extractor = PatternExtractor(_config_dir() / "learning_params.yaml")
    raw = json.loads(records.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc)
    patterns = extractor.extract(list(raw), now)
    if not patterns:
        console.print(
            "No patterns yet — nothing above min_samples (PRISM-L-3)."
        )
        return
    table = Table(title="Learned patterns")
    for column in ("Pattern", "Type", "Key", "Samples", "Rate",
                   "Confidence"):
        table.add_column(column)
    for pattern in patterns:
        table.add_row(
            pattern.pattern_id, pattern.pattern_type, pattern.key,
            str(pattern.samples), f"{pattern.success_rate:.2f}",
            f"{pattern.confidence:.2f}",
        )
    console.print(table)
    console.print(PREAMBLE_LINE)


# -- 4. patterns validate ----------------------------------------------------------------

@prism_app.command("patterns-validate")
def patterns_validate(
    pattern_id: str = typer.Argument(...),
    records: Annotated[Path, typer.Option(
        "--records", help="JSON file of outcome records."
    )] = ...,
) -> None:
    """Validate one learned pattern: min samples + confidence floor."""
    extractor = PatternExtractor(_config_dir() / "learning_params.yaml")
    raw = json.loads(records.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc)
    patterns = extractor.extract(list(raw), now)
    match = next((p for p in patterns if p.pattern_id == pattern_id), None)
    if match is None:
        console.print(
            f"Pattern {pattern_id} not found or below min_samples "
            f"(PRISM-L-3)."
        )
        raise typer.Exit(code=1)
    valid = (
        match.samples >= extractor.min_samples
        and match.confidence >= extractor.confidence_floor
    )
    console.print(
        f"pattern {match.pattern_id}: samples={match.samples} "
        f"confidence={match.confidence:.3f} → "
        f"{'VALID' if valid else 'INVALID'} (min_samples="
        f"{extractor.min_samples}, floor={extractor.confidence_floor})"
    )
    console.print(PREAMBLE_LINE)
    if not valid:
        raise typer.Exit(code=1)


# -- 5. priors show ------------------------------------------------------------------------

@prism_app.command("priors-show")
def priors_show(
    db: Annotated[Path, typer.Option(
        "--db", help="Ledger database."
    )] = DEFAULT_DB,
    campaign: str = typer.Option(..., "--campaign"),
) -> None:
    """Show prior adjustments recorded for a campaign."""
    ledger = CampaignLedger(db)
    try:
        data = ledger.export(campaign)
    finally:
        ledger.close()
    adjustments = data["adjustments"]
    if not adjustments:
        console.print("No prior adjustments recorded for this campaign.")
        return
    table = Table(title=f"Priors — campaign {campaign}")
    for column in ("Pattern", "Delta", "Confidence", "Reason"):
        table.add_column(column)
    for row in adjustments:
        table.add_row(row["pattern_id"], f"{row['delta']:+.3f}",
                      f"{row['confidence']:.3f}", row["reason"])
    console.print(table)
    console.print(PREAMBLE_LINE)


# -- 6. filter signals -----------------------------------------------------------------------

@prism_app.command("filter-signals")
def filter_signals(
    file: Annotated[Path, typer.Option(
        "--file", help="JSON file of raw anomalies."
    )] = ...,
    target_hash: str = typer.Option(..., "--target-hash"),
) -> None:
    """Rank raw anomalies by value and print pursue/hold/discard calls."""
    f = AnomalyFilter(_config_dir() / "curiosity_params.yaml")
    context = FilterContext(target_hash=target_hash)
    raw = json.loads(file.read_text(encoding="utf-8"))
    results = []
    for item in raw:
        anomaly = RawAnomaly(anomaly_id=item["anomaly_id"],
                             anomaly_type=item["anomaly_type"],
                             raw=item.get("raw", {}))
        # prior_probability and historical_success are ledger facts the
        # operator (or the campaign history) supplies per anomaly; they
        # may ride in the raw dict, otherwise config defaults apply.
        prior = item["raw"].get("prior") if item.get("raw") else None
        historical = (
            item["raw"].get("historical") if item.get("raw") else None
        )
        results.append(f.filter(
            anomaly, context,
            prior=float(prior) if prior is not None else None,
            historical=(
                float(historical) if historical is not None else None
            ),
        ))
    results.sort(key=lambda r: (-r.combined_value, r.anomaly_id))
    table = Table(title="Filtered signals")
    for column in ("Anomaly", "Type", "Value", "Decision"):
        table.add_column(column)
    for result in results:
        table.add_row(result.anomaly_id, result.anomaly_type,
                      f"{result.combined_value:.3f}", result.decision)
    console.print(table)
    console.print(PREAMBLE_LINE)


# -- 7. rabbit holes check ---------------------------------------------------------------------

@prism_app.command("rabbit-holes-check")
def rabbit_holes_check(
    signal_id: str = typer.Argument(...),
    anomaly_type: str = typer.Option(..., "--type"),
    depth: int = typer.Option(..., "--depth"),
    time_hours: float = typer.Option(..., "--time-hours"),
    requests: int = typer.Option(..., "--requests"),
    recent_evidence: str = typer.Option(
        "", "--recent-evidence",
        help="Comma-separated 0/1 per recent step, e.g. '1,0,1'."),
    reason: str = typer.Option("", "--reason",
                               help="Why keep going?"),
) -> None:
    """Check one exploration for rabbit-hole indicators."""
    p = RabbitHoleProtector(_config_dir() / "curiosity_params.yaml")
    recent = tuple(
        chunk.strip() == "1"
        for chunk in recent_evidence.split(",") if chunk.strip() != ""
    )
    state = ExplorationState(
        depth=depth, time_spent_hours=time_hours, requests_spent=requests,
        recent_new_evidence=recent, reason_for_continuing=reason,
    )
    result = p.check(HoleSignal(signal_id=signal_id,
                                anomaly_type=anomaly_type), state)
    for key, value in result.to_dict().items():
        console.print(f"{key}: {value}")
    console.print(PREAMBLE_LINE)


# -- 8. metrics ----------------------------------------------------------------------------------

@prism_app.command("metrics")
def metrics(
    observations: Annotated[Path, typer.Option(
        "--observations", help="JSON file of observations."
    )] = ...,
    period_days: int = typer.Option(30, "--period",
                                    help="Rolling window in days."),
) -> None:
    """Compute before/after Prism metrics (PRISM-L-10)."""
    engine = MetricsEngine(_config_dir() / "curiosity_params.yaml")
    for raw in json.loads(
        observations.read_text(encoding="utf-8")
    ):
        engine.record(Observation(
            phase=raw["phase"], accepted=raw["accepted"],
            time_hours=float(raw["time_hours"]),
            evidence_score=float(raw["evidence_score"]),
            rabbit_hole_avoided=bool(raw.get(
                "rabbit_hole_avoided", False)),
            recorded_on=str(raw.get("recorded_on", "")),
        ))
    result = engine.compute(datetime.now(timezone.utc), period_days)
    for key, value in result.to_dict().items():
        if key != "methodology":
            console.print(f"{key}: {value}")
    console.print(PREAMBLE_LINE)


# -- 9. dashboard ----------------------------------------------------------------------

@prism_app.command("dashboard")
def dashboard(
    db: Annotated[Path, typer.Option(
        "--db", help="Ledger database."
    )] = DEFAULT_DB,
) -> None:
    """Render the Prism learning dashboard."""
    from webpent.prism.dashboard import render_dashboard
    tier_distribution: dict[str, int] = {}
    ledger = CampaignLedger(db)
    try:
        rows = ledger._conn.execute(
            "SELECT tier, COUNT(*) AS n FROM evidence GROUP BY tier"
        ).fetchall()
        tier_distribution = {row["tier"]: row["n"] for row in rows}
    finally:
        ledger.close()
    text = render_dashboard(tier_distribution=tier_distribution)
    console.print(text)


__all__ = ["prism_app"]
