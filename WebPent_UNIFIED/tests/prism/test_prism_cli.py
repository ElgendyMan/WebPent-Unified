"""v89 PRISM — CLI tests for `webpent prism` (9 commands)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from webpent.cli.commands import app

WORK = Path(__file__).resolve().parents[2]
RUNNER = CliRunner()
ENV = {"WEBPENT_PRISM_WORKDIR": str(WORK)}


@pytest.fixture()
def mounted_app() -> typer.Typer:
    """The main CLI app with `prism` registered (via commands.py)."""
    return app


def _main(app_obj, args: list[str]) -> object:
    return RUNNER.invoke(app_obj, args, env=ENV)


# -- command surface -----------------------------------------------------------------

def test_all_cli_commands(mounted_app) -> None:
    commands = [
        ["prism", "score", "--help"],
        ["prism", "campaigns", "--help"],
        ["prism", "patterns-list", "--help"],
        ["prism", "patterns-validate", "--help"],
        ["prism", "priors-show", "--help"],
        ["prism", "filter-signals", "--help"],
        ["prism", "rabbit-holes-check", "--help"],
        ["prism", "metrics", "--help"],
        ["prism", "dashboard", "--help"],
    ]
    for args in commands:
        result = _main(mounted_app, args)
        assert result.exit_code == 0, f"{args}: {result.output}"
        assert "Usage" in result.output


# -- score -------------------------------------------------------------------------

def test_score_command(mounted_app) -> None:
    result = _main(mounted_app, [
        "prism", "score", "a" * 64,
        "--source", "probe", "--signal-kind", "direct_response",
        "--strength", "strong", "--reproducibility", "deterministic",
        "--corroboration", "independent_multiple",
        "--rationale", "payload echoed",
    ])
    assert result.exit_code == 0, result.output
    assert "tier" in result.output.lower()
    assert "PRISM advisory" in result.output


# -- campaigns / priors ---------------------------------------------------------------

def test_campaigns_command(mounted_app, tmp_path: Path) -> None:
    from webpent.prism.ledger import CampaignLedger
    db = tmp_path / "ledger.db"
    ledger = CampaignLedger(db)
    ledger.open_campaign("target.example", "proj")
    ledger.close()
    result = _main(mounted_app, [
        "prism", "campaigns", "--db", str(db),
    ])
    assert result.exit_code == 0, result.output
    # the raw target never appears (PRISM-L-6)
    assert "target.example" not in result.output
    assert "proj" in result.output


def test_priors_show_command(mounted_app, tmp_path: Path) -> None:
    from webpent.prism.ledger import CampaignLedger
    db = tmp_path / "ledger.db"
    ledger = CampaignLedger(db)
    campaign_id = ledger.open_campaign("target.example", "proj")
    ledger.record_adjustment(
        campaign_id, "pat-1", 0.12, "5/6 confirmed outcomes", 0.86
    )
    ledger.close()
    result = _main(mounted_app, [
        "prism", "priors-show", "--db", str(db), "--campaign", campaign_id,
    ])
    assert result.exit_code == 0, result.output
    assert "pat-1" in result.output
    assert "PRISM advisory" in result.output


# -- patterns ---------------------------------------------------------------------------

def test_patterns_list_command(mounted_app, tmp_path: Path) -> None:
    records = [
        {"technique": "sqli_union", "signal_kind": "direct_response",
         "stack": "nginx", "family": "sqli", "archetype": "fintech_api",
         "outcome": "confirmed"}
        for _ in range(6)
    ]
    path = tmp_path / "records.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    result = _main(mounted_app, [
        "prism", "patterns-list", "--records", str(path),
    ])
    assert result.exit_code == 0, result.output
    # the Key column is short enough to survive the 80-col default render;
    # the pattern_type column is asserted in the unit tests
    assert "sqli_union" in result.output
    assert "PRISM advisory" in result.output


def test_patterns_validate_command(mounted_app, tmp_path: Path) -> None:
    from webpent.prism.patterns import PatternExtractor
    records = [
        {"technique": "sqli_union", "signal_kind": "direct_response",
         "stack": "nginx", "family": "sqli", "archetype": "fintech_api",
         "outcome": "confirmed"}
        for _ in range(6)
    ]
    path = tmp_path / "records.json"
    path.write_text(json.dumps(records), encoding="utf-8")
    from datetime import datetime, timezone
    extractor = PatternExtractor(
        WORK / "config" / "prism" / "learning_params.yaml"
    )
    pattern = extractor.extract(records, datetime.now(timezone.utc))[0]
    result = _main(mounted_app, [
        "prism", "patterns-validate", pattern.pattern_id,
        "--records", str(path),
    ])
    assert result.exit_code == 0, result.output
    assert "VALID" in result.output


# -- filter / rabbit holes -----------------------------------------------------------------

def test_filter_signals_command(mounted_app, tmp_path: Path) -> None:
    anomalies = [
        {"anomaly_id": "an-1", "anomaly_type": "sqli_union",
         "raw": {"estimated_requests": 1, "estimated_impact": 0.9,
                 "context_match": 0.9, "prior": 0.9, "historical": 0.9}},
        {"anomaly_id": "an-2", "anomaly_type": "noise",
         "raw": {"estimated_requests": 50, "estimated_impact": 0.1}},
    ]
    path = tmp_path / "anomalies.json"
    path.write_text(json.dumps(anomalies), encoding="utf-8")
    result = _main(mounted_app, [
        "prism", "filter-signals", "--file", str(path),
        "--target-hash", "b" * 64,
    ])
    assert result.exit_code == 0, result.output
    assert "pursue" in result.output
    assert "discard" in result.output
    assert "PRISM advisory" in result.output


def test_rabbit_holes_check_command(mounted_app) -> None:
    result = _main(mounted_app, [
        "prism", "rabbit-holes-check", "sig-1",
        "--type", "endless_subdomain_enum",
        "--depth", "2", "--time-hours", "0.1", "--requests", "5",
        "--recent-evidence", "1,1",
    ])
    assert result.exit_code == 0, result.output
    assert "abandon" in result.output  # known hole pattern
    assert "PRISM advisory" in result.output


# -- metrics / dashboard ----------------------------------------------------------------------

def test_metrics_command(mounted_app, tmp_path: Path) -> None:
    observations = (
        [{"phase": "before", "accepted": True, "time_hours": 0.5,
          "evidence_score": 0.5, "recorded_on": "2026-10-18"}]
        * 4
        + [{"phase": "after", "accepted": True, "time_hours": 0.3,
            "evidence_score": 0.9, "recorded_on": "2026-10-18"}]
        * 6
    )
    path = tmp_path / "observations.json"
    path.write_text(json.dumps(observations), encoding="utf-8")
    result = _main(mounted_app, [
        "prism", "metrics", "--observations", str(path),
        "--period", "30",
    ])
    assert result.exit_code == 0, result.output
    assert "acceptance_after" in result.output
    assert "PRISM advisory" in result.output


def test_dashboard_command(mounted_app, tmp_path: Path) -> None:
    db = tmp_path / "ledger.db"
    result = _main(mounted_app, ["prism", "dashboard", "--db", str(db)])
    assert result.exit_code == 0, result.output
    assert "PRISM advisory" in result.output
    assert "evidence" in result.output
