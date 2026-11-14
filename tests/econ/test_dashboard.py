"""U-ECON-12 — Dashboard + CLI tests (NC-ECON-1 charter, exact test names)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from typer.testing import CliRunner

from webpent.cli.econ import econ_app
from webpent.econ.dashboard import Dashboard, load_portfolio_failsoft
from webpent.econ.portfolio import ACTIVE, ARCHIVED, DORMANT, WATCHING

NOW = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
RUNNER = CliRunner()

PORTFOLIO_YAML = """targets:
- target_id: t-a
  program_id: corp-a
  state: ACTIVE
  ev_per_hour: 50.0
  total_findings: 2
  total_payout_usd: 700
- target_id: t-b
  program_id: corp-a
  state: ACTIVE
  ev_per_hour: 20.0
  total_findings: 1
  total_payout_usd: 100
- target_id: t-c
  program_id: corp-b
  state: WATCHING
  ev_per_hour: 10.0
  total_findings: 0
  total_payout_usd: 0
- target_id: t-d
  program_id: corp-b
  state: DORMANT
  ev_per_hour: 5.0
  total_findings: 0
  total_payout_usd: 0
- target_id: t-e
  program_id: corp-c
  state: DORMANT
  ev_per_hour: 0.0
  total_findings: 0
  total_payout_usd: 0
"""

JOURNAL_ROWS = [
    {
        "finding_id": "F-1",
        "vuln_class": "IDOR",
        "severity": "high",
        "program_id": "corp-a",
        "endpoint": "/api/v2/users/{id}",
        "effort_hours": 2.0,
        "reputation_risk": 0.1,
        "class_accept_rate": 0.8,
        "submitted_at": (NOW - timedelta(days=2)).isoformat(),
    },
    # learning-loop rows: 10 accepted IDOR submissions -> one class insight
    *[
        {
            "finding_id": f"L-{i}",
            "vuln_class": "IDOR",
            "program_id": "corp-a",
            "submitted_at": (NOW - timedelta(days=5 + i)).isoformat(),
            "resolved_at": (NOW - timedelta(days=5 + i - 10)).isoformat(),
            "status": "accepted",
            "payout_usd": 100.0,
            "endpoint_signature": f"/api/v2/users/{i}",
        }
        for i in range(1, 11)
    ],
]


@pytest.fixture()
def econ_env(tmp_path, monkeypatch):
    state = tmp_path / "state"
    portfolio_file = tmp_path / "portfolio.yaml"
    portfolio_file.write_text(PORTFOLIO_YAML, encoding="utf-8")
    journal = state / "submissions.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text(
        "".join(json.dumps(r) + "\n" for r in JOURNAL_ROWS), encoding="utf-8"
    )
    monkeypatch.setenv("WEBPENT_ECON_DIR", str(state))
    monkeypatch.chdir(tmp_path)
    return {"state": state, "portfolio": portfolio_file, "journal": journal}


def test_digest_generates_both_formats(tmp_path):
    portfolio_file = tmp_path / "portfolio.yaml"
    portfolio_file.write_text(PORTFOLIO_YAML, encoding="utf-8")
    board = Dashboard(portfolio_path=portfolio_file, now=NOW)
    built = board.build_digest(hours_per_week=40.0)
    md = board.as_markdown(built)
    # markdown carries every section of the digest (DoD)
    for section in ("Portfolio", "Top opportunities", "Bottom targets",
                    "Pipeline", "Earnings projection", "Alerts"):
        assert section in md
    # both formats are generated from the same digest object
    data = built.as_dict()
    assert data["advisory"] is True
    assert {"portfolio_counts", "top_opportunities", "bottom_targets", "pipeline",
            "earnings_projection", "alerts"} <= set(data)


def test_digest_totals_match_portfolio(tmp_path):
    portfolio_file = tmp_path / "portfolio.yaml"
    portfolio_file.write_text(PORTFOLIO_YAML, encoding="utf-8")
    portfolio = load_portfolio_failsoft(portfolio_file)
    board = Dashboard(portfolio_path=portfolio_file, now=NOW)
    digest = board.build_digest()
    assert digest.portfolio_counts[ACTIVE] == len(portfolio.by_state(ACTIVE))
    assert digest.portfolio_counts[WATCHING] == len(portfolio.by_state(WATCHING))
    assert digest.portfolio_counts[DORMANT] == len(portfolio.by_state(DORMANT))
    assert digest.portfolio_counts[ARCHIVED] == len(portfolio.by_state(ARCHIVED))
    assert sum(digest.portfolio_counts.values()) == len(portfolio.targets)
    # bottom targets only include states that consume hours (ACTIVE/WATCHING)
    assert all(t["state"] in (ACTIVE, WATCHING) for t in digest.bottom_targets)
    assert len(digest.bottom_targets) <= 5


def test_earnings_projection_math(tmp_path):
    portfolio_file = tmp_path / "portfolio.yaml"
    portfolio_file.write_text(PORTFOLIO_YAML, encoding="utf-8")
    portfolio = load_portfolio_failsoft(portfolio_file)
    board = Dashboard(portfolio_path=portfolio_file, now=NOW)
    projection = board.earnings_projection(portfolio, 10.0)
    # ACTIVE gets 60% of hours, split over 2 targets: 3h*50 + 3h*20 = 210
    # WATCHING gets 30% over 1 target: 3h*10 = 30 ; DORMANT gets 10% over 2
    # targets with EV/hour 5 and 0: 0.5h*5 = 2.5  -> weekly = 242.50 USD
    assert projection["projected_weekly_usd"] == 242.50
    assert projection["projected_monthly_usd"] == round(242.50 * 52 / 12, 2)
    assert projection["blended_ev_per_hour_usd"] == 24.25
    assert projection["advisory"] is True


def test_alerts_empty_on_clean_state(tmp_path):
    portfolio_file = tmp_path / "portfolio.yaml"
    rows = []
    for i in range(5):
        rows.append(
            f"- target_id: t-clean-{i}\n  program_id: corp-clean\n"
            f"  state: ACTIVE\n  ev_per_hour: {20.0 + i}\n"
            f"  total_findings: 1\n  total_payout_usd: 200\n"
        )
    portfolio_file.write_text("targets:\n" + "".join(rows), encoding="utf-8")
    board = Dashboard(portfolio_path=portfolio_file, now=NOW)
    digest = board.build_digest()
    assert digest.alerts == []


def test_cli_all_commands_work(econ_env):
    commands = [
        ["econ", "targets", "list", "--portfolio", str(econ_env["portfolio"])],
        ["econ", "targets", "list", "--tier", "S", "--portfolio",
         str(econ_env["portfolio"])],
        ["econ", "targets", "score", "t-a", "--portfolio", str(econ_env["portfolio"])],
        ["econ", "findings", "value", "F-1", "--journal", str(econ_env["journal"])],
        ["econ", "findings", "timing", "F-1", "--journal", str(econ_env["journal"])],
        ["econ", "portfolio", "plan", "--portfolio", str(econ_env["portfolio"])],
        ["econ", "portfolio", "transition", "t-c", "ACTIVE", "--portfolio",
         str(econ_env["portfolio"]), "--reason", "test"],
        ["econ", "digest", "--portfolio", str(econ_env["portfolio"])],
        ["econ", "digest", "--portfolio", str(econ_env["portfolio"]), "--format", "json"],
        ["econ", "insights", "--journal", str(econ_env["journal"])],
        ["econ", "blind-spots", "t-a", "--portfolio", str(econ_env["portfolio"])],
        ["econ", "opportunities", "corp-a", "--portfolio", str(econ_env["portfolio"])],
    ]
    for argv in commands:
        result = RUNNER.invoke(econ_app, argv[1:])
        assert result.exit_code == 0, f"{argv} failed: {result.output}"
    # every invocation landed in the capped audit log (DoD)
    audit = (econ_env["state"] / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(audit) == len(commands)
    parsed = [json.loads(line) for line in audit]
    assert all(p["command"].startswith("econ ") for p in parsed)
    assert all("ts" in p for p in parsed)


def test_cli_outputs_valid_json(econ_env):
    for argv in (
        ["targets", "list", "--portfolio", str(econ_env["portfolio"])],
        ["targets", "score", "t-a", "--portfolio", str(econ_env["portfolio"])],
        ["findings", "value", "F-1", "--journal", str(econ_env["journal"])],
        ["portfolio", "plan", "--portfolio", str(econ_env["portfolio"])],
        ["digest", "--portfolio", str(econ_env["portfolio"]), "--format", "json"],
        ["insights", "--journal", str(econ_env["journal"])],
        ["blind-spots", "t-a", "--portfolio", str(econ_env["portfolio"])],
        ["opportunities", "corp-a", "--portfolio", str(econ_env["portfolio"])],
    ):
        result = RUNNER.invoke(econ_app, argv)
        assert result.exit_code == 0, f"{argv} failed: {result.output}"
        data = json.loads(result.output)
        assert data["advisory"] is True
    # a bad transition is refused with a JSON explanation, not a traceback
    bad = RUNNER.invoke(econ_app, ["portfolio", "transition", "t-a", "ARCHIVED",
                                   "--portfolio", str(econ_env["portfolio"])])
    assert bad.exit_code == 1
    err = json.loads(bad.output)
    assert err["moved"] is False and err["error"]
