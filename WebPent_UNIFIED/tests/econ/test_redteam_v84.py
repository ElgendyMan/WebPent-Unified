"""Red team v84 regression tests — repro-first (docs/plans/2026-10-16-v84-red-team.md)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from webpent.cli.econ import econ_app
from webpent.econ.budget_mapper import BudgetContext, BudgetMapper
from webpent.econ.competitive import CompetitiveRadar
from webpent.econ.dashboard import Dashboard
from webpent.econ.learning_loop import LearningLoop
from webpent.econ.portfolio import PortfolioManager

NOW = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
RUNNER = CliRunner()

PORTFOLIO_YAML = """targets:
- target_id: t-1
  program_id: example-corp
  state: WATCHING
  ev_per_hour: 10.0
  total_findings: 0
  total_payout_usd: 0
"""

FINDING_ROW = {
    "finding_id": "F-1",
    "vuln_class": "IDOR",
    "severity": "high",
    "program_id": "example-corp",
    "endpoint": "/api/v2/users/{id}",
    "effort_hours": 2.0,
    "reputation_risk": 0.1,
    "class_accept_rate": 0.8,
}


def _econ_env(tmp_path: Path, monkeypatch) -> dict[str, Path]:
    state = tmp_path / "state"
    state.mkdir()
    monkeypatch.setenv("WEBPENT_ECON_DIR", str(state))  # audit + radar db live here
    portfolio = tmp_path / "portfolio.yaml"
    portfolio.write_text(PORTFOLIO_YAML, encoding="utf-8")
    return {"state": state, "portfolio": portfolio}


# ---------------------------------------------------------------- RT-01
def test_cli_findings_survive_corrupt_first_journal_line(tmp_path, monkeypatch):
    env = _econ_env(tmp_path, monkeypatch)
    journal = env["state"] / "submissions.jsonl"
    journal.write_text(
        "{corrupt json line\n" + json.dumps(FINDING_ROW) + "\n",
        encoding="utf-8",
    )
    result = RUNNER.invoke(
        econ_app,
        ["findings", "value", "F-1", "--journal", str(journal)],
    )
    assert result.exit_code == 0, f"traceback instead of JSON: {result.output}"
    data = json.loads(result.output)
    assert data["advisory"] is True


# ---------------------------------------------------------------- RT-02
def test_cli_transition_persists_to_portfolio_yaml(tmp_path, monkeypatch):
    env = _econ_env(tmp_path, monkeypatch)
    result = RUNNER.invoke(
        econ_app,
        ["portfolio", "transition", "t-1", "ACTIVE", "--portfolio",
         str(env["portfolio"]), "--reason", "red team"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["moved"] is True
    # the transition must survive the command, not just live in memory
    text = env["portfolio"].read_text(encoding="utf-8")
    assert "state: ACTIVE" in text, f"transition not persisted: {text}"


def test_portfolio_manager_save_is_atomic_and_complete(tmp_path):
    src = tmp_path / "portfolio.yaml"
    src.write_text(PORTFOLIO_YAML, encoding="utf-8")
    mgr = PortfolioManager(now=NOW, log_path=tmp_path / "log.jsonl")
    pfolio = mgr.load(src)
    moved = mgr.transition(pfolio, "t-1", "ACTIVE", "signal")
    assert moved is not None
    out = tmp_path / "portfolio.yaml"
    mgr.save(pfolio, out)
    rows = out.read_text(encoding="utf-8")
    assert "state: ACTIVE" in rows
    assert "target_id: t-1" in rows
    assert "ev_per_hour: 10.0" in rows
    assert "program_id: example-corp" in rows
    assert "total_findings: 0" in rows
    assert "total_payout_usd: 0" in rows


# ---------------------------------------------------------------- RT-03
def test_radar_last_seen_ignores_clock_offset_lexicography(tmp_path):
    db = tmp_path / "c.db"
    radar = CompetitiveRadar(db)
    snap = tmp_path / "snap.json"
    # 13:00+03:00 is 10:00 UTC (older instant) yet sorts lexicographically
    # above 12:00+00:00; the true latest instant is 12:00 UTC.
    older_with_offset = {
        "program_id": "example-corp",
        "vuln_class": "XSS",
        "severity": "low",
        "endpoint_signature": "/a",
        "disclosed_at": "2026-10-16T13:00:00+03:00",
        "source": "hackerone_hacktivity",
    }
    newest_utc = {
        "program_id": "example-corp",
        "vuln_class": "XSS",
        "severity": "low",
        "endpoint_signature": "/b",
        "disclosed_at": "2026-10-16T12:00:00+00:00",
        "source": "hackerone_hacktivity",
    }
    snap.write_text(
        json.dumps(
            {"source": "hackerone_hacktivity", "findings": [older_with_offset, newest_utc]}
        ),
        encoding="utf-8",
    )
    report = radar.ingest(str(snap), dry_run=False)
    assert report.status == "ingested"
    seen = radar.last_seen("example-corp", "XSS")
    assert seen is not None
    assert seen.astimezone(timezone.utc) == datetime(
        2026, 10, 16, 12, 0, tzinfo=timezone.utc
    )


# ---------------------------------------------------------------- RT-04
def test_learning_loop_survives_non_numeric_payout(tmp_path):
    rows = []
    for i in range(12):
        row = {
            "finding_id": f"L-{i}",
            "vuln_class": "IDOR",
            "program_id": "example-corp",
            "submitted_at": (NOW - timedelta(days=3)).isoformat(),
            "resolved_at": (NOW - timedelta(days=1)).isoformat(),
            "status": "duplicate" if i < 11 else "accepted",
            "payout_usd": 100.0,
            "endpoint_signature": f"/api/x/{i % 3}",
        }
        if i == 5:
            row["payout_usd"] = "not-a-number"  # RT-04: must not sink analyze()
        rows.append(json.dumps(row))
    journal = tmp_path / "submissions.jsonl"
    journal.write_text("\n".join(rows) + "\n", encoding="utf-8")
    loop = LearningLoop(journal, log_path=tmp_path / "insights.jsonl", now=NOW)
    insights = loop.analyze(period_days=30)
    kinds = {ins.kind for ins in insights}
    assert "dup_pattern" in kinds  # the 12 clean rows still teach


# ---------------------------------------------------------------- RT-05
def test_auto_transition_reason_reports_true_staleness(tmp_path):
    from webpent.econ.portfolio import AutoContext

    src = tmp_path / "portfolio.yaml"
    stale_last = (NOW - timedelta(days=120)).isoformat()
    src.write_text(
        PORTFOLIO_YAML + f"  last_transition: {stale_last}\n", encoding="utf-8"
    )
    mgr = PortfolioManager(now=NOW, log_path=tmp_path / "log.jsonl")
    pfolio = mgr.load(src)
    applied = mgr.auto_transition(pfolio, AutoContext(now=NOW))
    dormant = [a for a in applied if a.to_state == "DORMANT"]
    assert dormant, "expected a WATCHING->DORMANT auto transition"
    assert "120 days" in dormant[0].reason, dormant[0].reason


# ---------------------------------------------------------------- RT-06
def test_allocate_rejects_duplicate_target_ids(tmp_path, monkeypatch):
    from webpent.econ.market_kb import Target

    bm = BudgetMapper(TargetScorerStub())
    ctx = BudgetContext(now=1758000000.0)
    dup = [
        Target(target_id="t-1", program_id="p", effort_estimate=2.0),
        Target(target_id="t-1", program_id="p", effort_estimate=1.0),
    ]
    with pytest.raises(ValueError, match="t-1"):
        bm.allocate(dup, 10.0, ctx)


# ---------------------------------------------------------------- RT-07
def test_find_opportunities_window_override(tmp_path, monkeypatch):
    radar = CompetitiveRadar(tmp_path / "c.db")
    snap = tmp_path / "snap.json"
    snap.write_text(
        json.dumps(
            {
                "source": "hackerone_hacktivity",
                "findings": [
                    {
                        "program_id": "example-corp",
                        "vuln_class": "XSS",
                        "severity": "low",
                        "endpoint_signature": "/a",
                        "disclosed_at": (NOW - timedelta(days=100)).isoformat(),
                        "source": "hackerone_hacktivity",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    radar.ingest(str(snap), dry_run=False)
    narrow = radar.find_opportunities("example-corp", now=NOW, window_days=30)
    # the XSS finding is 100 days old: outside a 30-day window it is a gap,
    # inside a 365-day window it is covered and no longer an opportunity.
    assert any(o.vuln_class == "XSS" for o in narrow)
    wide = radar.find_opportunities("example-corp", now=NOW, window_days=365)
    assert not any(o.vuln_class == "XSS" for o in wide)


def test_cli_digest_includes_radar_opportunities(tmp_path, monkeypatch):
    env = _econ_env(tmp_path, monkeypatch)
    state = env["state"]
    radar = CompetitiveRadar(state / "competitive.db")
    snap = state / "snap.json"
    snap.write_text(
        json.dumps(
            {
                "source": "hackerone_hacktivity",
                "findings": [
                    {
                        "program_id": "example-corp",
                        "vuln_class": "XSS",
                        "severity": "critical",
                        "endpoint_signature": "/admin/debug",
                        "disclosed_at": (NOW - timedelta(days=1)).isoformat(),
                        "source": "hackerone_hacktivity",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    radar.ingest(str(snap), dry_run=False)
    result = RUNNER.invoke(
        econ_app,
        ["digest", "--portfolio", str(env["portfolio"]), "--days", "30"],
    )
    assert result.exit_code == 0, result.output
    assert "RCE" in result.output, "digest never surfaces radar opportunities"
    assert result.exit_code == 0


def test_cli_opportunities_unknown_target_answers_found_false(tmp_path, monkeypatch):
    env = _econ_env(tmp_path, monkeypatch)
    result = RUNNER.invoke(
        econ_app,
        ["opportunities", "not-in-portfolio", "--portfolio",
         str(env["portfolio"])],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["found"] is False


# ---------------------------------------------------------------- RT-09
def test_audit_log_preserves_zero_values(tmp_path, monkeypatch):
    env = _econ_env(tmp_path, monkeypatch)
    RUNNER.invoke(
        econ_app,
        ["portfolio", "plan", "--portfolio", str(env["portfolio"]),
         "--hours", "0"],
    )
    audit = env["state"] / "audit.jsonl"
    line = audit.read_text(encoding="utf-8").strip().splitlines()[-1]
    entry = json.loads(line)
    assert str(entry.get("hours")) == "0.0", entry


# ---------------------------------------------------------------- RT-10
def test_cli_findings_value_treats_corrupt_row_as_missing(tmp_path, monkeypatch):
    env = _econ_env(tmp_path, monkeypatch)
    journal = env["state"] / "submissions.jsonl"
    corrupt = dict(FINDING_ROW, effort_hours="abc")
    journal.write_text(json.dumps(corrupt) + "\n", encoding="utf-8")
    result = RUNNER.invoke(
        econ_app,
        ["findings", "value", "F-1", "--journal", str(journal)],
    )
    assert result.exit_code == 0, f"traceback: {result.output}"
    data = json.loads(result.output)
    assert data["found"] is False


# ---------------------------------------------------------------- RT-11
def test_dashboard_markdown_survives_pipe_and_newline_injection(tmp_path):
    portfolio_file = tmp_path / "portfolio.yaml"
    hostile = "t-|x\ninjected row"
    portfolio_file.write_text(
        "targets:\n"
        f"- target_id: '{hostile}'\n"
        "  program_id: example-corp\n"
        "  state: ACTIVE\n"
        "  ev_per_hour: 10.0\n"
        "  total_findings: 1\n"
        "  total_payout_usd: 100\n",
        encoding="utf-8",
    )
    board = Dashboard(portfolio_path=portfolio_file, now=NOW)
    md = board.as_markdown(board.build_digest(hours_per_week=10.0))
    data_rows = [line for line in md.splitlines() if "injected row" in line]
    assert len(data_rows) == 1, f"markdown structure broken: {data_rows}"
    assert data_rows[0].count("|") % 3 == 2, data_rows[0]  # 5-col row cells


# -------------------------------------------------------------- helpers
class TargetScorerStub:
    def score(self, target, now=None, kb=None):  # pragma: no cover - unused path
        raise AssertionError("allocator must not re-score in this test")
