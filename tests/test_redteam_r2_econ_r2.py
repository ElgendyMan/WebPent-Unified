"""RED-TEAM ROUND 2 - econ C2+C3 batch, fail-first (0.34.0 window).

Every test below was written BEFORE its fix and fails on the baseline;
each corresponds to one Medium/Low finding from
docs/RED_TEAM_ROUND2_20261102.md sections 3-4:

    R2-econ-02   aware non-UTC `since` compared lexicographically against
                 UTC-normalized rows -> silently wrong results
    R2-econ-03   findings table has no UNIQUE constraint -> re-ingesting
                 the same snapshot double-counts rows
    R2-econ-04   journal cap keeps the OLDEST lines of an append-only
                 file -> newest submissions silently excluded
    R2-econ-05   path entries land in gray_zones but locate() reads only
                 in_scope -> path_region blind spots unreachable
    R2-econ-06   a PRESENT but non-numeric signal is silently dropped
                 while confidence stays 1.0 (L-4 lie)
    R2-econ-07   one corrupt numeric field silently erases the whole
                 portfolio target
    R2-econ-08   the no-data report masquerades as a perfect LOW score
    R2-econ-09   set input to parse_scope_entries -> process-dependent
                 ambiguity order (L-3 violation)
    R2-econ-10   HOLD uses the raw KB dup_rate instead of the
                 saturation-adjusted P_dup (decision_matrix rule 5)
    R2-econ-11   STALE_AFTER_DAYS is dead: stale KB entries drive EV
                 without any warning
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PARAMS = REPO_ROOT / "config" / "econ" / "competition_params.yaml"
SEED_CONFIG = REPO_ROOT / "config" / "econ" / "programs.yaml"
ROI_PARAMS = REPO_ROOT / "config" / "econ" / "roi_params.yaml"
SEED_CURVES = REPO_ROOT / "config" / "econ" / "payout_curves.yaml"
NOW = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
STALE_DAYS_90 = "90"


def _radar(tmp_path: Path, sub: str = "a"):
    from webpent.econ.competitive import CompetitiveRadar

    return CompetitiveRadar(
        tmp_path / "econ" / f"competitive_{sub}.db",
        params_path=PARAMS if PARAMS.exists() else None,
    )


def _snapshot(tmp_path: Path, findings: list[dict], name: str = "snap.json") -> Path:
    path = tmp_path / name
    path.write_text(
        json.dumps({"source": "hackerone_hacktivity", "findings": findings}),
        encoding="utf-8",
    )
    return path


def _finding(endpoint="/api/v2/users/{id}", vuln_class="IDOR", days_ago=3,
             disclosed_at=None):
    return {
        "program_id": "example-corp",
        "severity": "high",
        "vuln_class": vuln_class,
        "endpoint_signature": endpoint,
        "disclosed_at": disclosed_at or (NOW - timedelta(days=days_ago)).isoformat(),
    }


# ---------------------------------------------------------------------------
# R2-econ-02
# ---------------------------------------------------------------------------

def test_r2econ_02_aware_since_normalized_to_utc(tmp_path):
    """An aware non-UTC `since` must be UTC-normalized before the string
    comparison, else a finding disclosed AFTER the (UTC) cutoff is
    silently excluded."""
    radar = _radar(tmp_path)
    snap = _snapshot(
        tmp_path,
        [_finding(disclosed_at="2024-05-31T20:00:00+00:00")],
    )
    radar.ingest(str(snap), dry_run=False)
    # 2024-06-01T00:00:00+05:00 == 2024-05-31T19:00:00Z, so the finding
    # (20:00Z) must be returned.
    since = datetime(2024, 6, 1, 0, 0, 0, tzinfo=timezone(timedelta(hours=5)))
    got = radar.get_findings("example-corp", since)
    assert len(got) == 1, (
        f"aware non-UTC since leaked into the lexicographic comparison: {len(got)}"
    )
    assert got[0].endpoint_signature == "/api/v2/users/{id}"


# ---------------------------------------------------------------------------
# R2-econ-03
# ---------------------------------------------------------------------------

def test_r2econ_03_reingest_same_snapshot_does_not_double_count(tmp_path):
    """Re-ingesting the same snapshot must not double-count rows; the
    unique index dedups and the report says how many rows were ignored."""
    from webpent.econ.competitive import CompetitiveRadar

    findings = [
        _finding(endpoint=f"/api/v2/item{i}", days_ago=i + 1) for i in range(3)
    ]
    snap = _snapshot(tmp_path, findings)
    radar = _radar(tmp_path)
    r1 = radar.ingest(str(snap), dry_run=False)
    assert r1.status == "ingested"
    r2 = radar.ingest(str(snap), dry_run=False)
    assert r2.status == "ingested"
    # the report carries the ignored count (new field, default 0)
    assert r2.rows_ignored == 3
    assert r2.as_dict()["rows_ignored"] == 3
    assert radar.count_findings("example-corp") == 3, "rows double-counted"
    # the dedup index exists
    conn = sqlite3.connect(str(radar.db_path))
    try:
        names = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
                " AND tbl_name='findings'"
            )
        }
    finally:
        conn.close()
    assert "ux_findings" in names
    # legacy DB that already contains duplicate rows: index creation must
    # fail soft (warn, no index) and ingestion must still work (L-2/L-4)
    legacy = tmp_path / "legacy.db"
    lconn = sqlite3.connect(str(legacy))
    try:
        lconn.execute(
            "CREATE TABLE findings (program_id TEXT NOT NULL, severity TEXT NOT NULL,"
            " vuln_class TEXT NOT NULL, endpoint_signature TEXT NOT NULL,"
            " disclosed_at TEXT NOT NULL, source TEXT NOT NULL)"
        )
        row = (
            "example-corp", "high", "IDOR", "/api/v2/users/{id}",
            "2024-05-31T20:00:00+00:00", "hackerone_hacktivity",
        )
        lconn.execute("INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?)", row)
        lconn.execute("INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?)", row)
        lconn.commit()
    finally:
        lconn.close()
    radar2 = CompetitiveRadar(legacy, params_path=None)
    r3 = radar2.ingest(str(snap), dry_run=False)  # must not raise
    assert r3.status == "ingested"


# ---------------------------------------------------------------------------
# R2-econ-04
# ---------------------------------------------------------------------------

def test_r2econ_04_journal_cap_keeps_newest_records_tail(tmp_path):
    """The 4096-line cap must keep the TAIL of the append-only journal:
    once the journal exceeds the cap, the newest submissions (inside the
    lookback window) must still drive insights and CLI lookups."""
    from webpent.econ.learning_loop import (
        KIND_CLASS_FOCUS,
        LearningLoop,
    )

    old = {
        "finding_id": "old",
        "vuln_class": "IDOR",
        "program_id": "example-corp",
        "submitted_at": (NOW - timedelta(days=200)).isoformat(),
        "resolved_at": (NOW - timedelta(days=190)).isoformat(),
        "status": "accepted",
        "payout_usd": 0.0,
        "endpoint_signature": "/old/1",
    }
    new = [
        {
            "finding_id": f"new-{i}",
            "vuln_class": "IDOR",
            "program_id": "example-corp",
            "submitted_at": (NOW - timedelta(days=i + 1)).isoformat(),
            "resolved_at": (NOW - timedelta(days=i)).isoformat(),
            "status": "accepted",
            "payout_usd": 100.0,
            "endpoint_signature": f"/api/v2/new{i}",
        }
        for i in range(10)
    ]
    lines = [json.dumps(old)] * 4096 + [json.dumps(r) for r in new]
    journal = tmp_path / "journal.jsonl"
    journal.write_text("\n".join(lines) + "\n", encoding="utf-8")
    loop = LearningLoop(journal, log_path=tmp_path / "insights.jsonl", now=NOW)
    insights = loop.analyze()
    assert any(
        i.kind == KIND_CLASS_FOCUS and "IDOR" in i.recommendation
        for i in insights
    ), "newest submissions beyond the 4096-line head were excluded"

    # same bug in the CLI journal reader (cli/econ.py)
    from webpent.cli.econ import _load_journal_finding

    cli_lines = [json.dumps({"finding_id": f"filler-{i}"}) for i in range(4096)]
    cli_lines.append(
        json.dumps({
            "finding_id": "F-new",
            "vuln_class": "IDOR",
            "severity": "high",
            "program_id": "example-corp",
            "endpoint": "/api/v2/x",
        })
    )
    cli_journal = tmp_path / "cli_journal.jsonl"
    cli_journal.write_text("\n".join(cli_lines) + "\n", encoding="utf-8")
    row = _load_journal_finding(cli_journal, "F-new")
    assert row is not None and row["finding_id"] == "F-new", (
        "CLI journal reader kept the oldest lines and missed the newest record"
    )


# ---------------------------------------------------------------------------
# R2-econ-05
# ---------------------------------------------------------------------------

def test_r2econ_05_locate_consumes_gray_zone_path_entries(tmp_path):
    """The negotiator diverts path entries to gray_zones, so locate()
    must consume them (deduped with in_scope, same 256-entry bound) or
    the path_region blind-spot kind is unreachable via the documented
    pipeline."""
    from webpent.econ.blind_spots import BlindSpotLocator
    from webpent.econ.market_kb import Target
    from webpent.econ.scope_negotiator import ScopeAnalysis, ScopeNegotiator

    radar = _radar(tmp_path)
    snap = _snapshot(tmp_path, [_finding(endpoint="/api/v2/users/{id}")])
    radar.ingest(str(snap), dry_run=False)
    locator = BlindSpotLocator(params_path=PARAMS if PARAMS.exists() else None)

    # documented pipeline: paths end up in gray_zones, not in_scope
    analysis = ScopeNegotiator().analyze(
        "/api/v1/orders\n/api/v1/refunds\napi.example.com"
    )
    assert "/api/v1/orders" in analysis.gray_zones
    assert "/api/v1/orders" not in analysis.in_scope
    spots = locator.locate(
        Target("t-1", "example-corp"), radar, analysis, now=NOW
    )
    kinds = {(s.kind, s.identifier) for s in spots}
    assert ("path_region", "/api/v1/*") in kinds, (
        "path_region blind spots unreachable through the documented pipeline"
    )

    # gray-zone paths are deduped with in_scope entries
    dup_scope = ScopeAnalysis(
        in_scope=["/api/v1/orders"], gray_zones=["/api/v1/orders"]
    )
    spots2 = locator.locate(Target("t-1", "example-corp"), radar, dup_scope, now=NOW)
    by_kind = {(s.kind, s.identifier): s for s in spots2}
    assert by_kind[("path_region", "/api/v1/*")].estimated_ev == 400.0

    # the combined list is bounded by the same 256-entry cap
    cap_scope = ScopeAnalysis(
        in_scope=[], gray_zones=[f"/api/v1/p{i}" for i in range(300)]
    )
    spots3 = locator.locate(Target("t-1", "example-corp"), radar, cap_scope, now=NOW)
    by_kind3 = {(s.kind, s.identifier): s for s in spots3}
    assert by_kind3[("path_region", "/api/v1/*")].estimated_ev == 400.0 * 256

    # non-path gray zones (IP ranges, wildcards) are not invented into paths
    mixed = ScopeAnalysis(
        in_scope=["api.example.com"],
        gray_zones=["192.168.1.0/24", "*.wild.example.com"],
    )
    spots4 = locator.locate(Target("t-1", "example-corp"), radar, mixed, now=NOW)
    ids = {(s.kind, s.identifier) for s in spots4}
    assert ("subdomain", "192.168.1.0/24") not in ids
    assert ("subdomain", "*.wild.example.com") not in ids
    assert ("subdomain", "api.example.com") in ids


# ---------------------------------------------------------------------------
# R2-econ-06
# ---------------------------------------------------------------------------

def test_r2econ_06_corrupt_signal_counts_as_partial_not_silent(tmp_path):
    """A PRESENT but non-numeric signal must be treated like a missing
    one (recorded in partial, confidence dropped), never silently
    dropped with confidence 1.0 and an 'all three signals' claim."""
    from webpent.econ.market_kb import Target
    from webpent.econ.saturation import SaturationEstimator

    radar = _radar(tmp_path)
    snap = _snapshot(tmp_path, [_finding()], name="snap_sat.json")
    radar.ingest(str(snap), dry_run=False)
    est = SaturationEstimator(params_path=PARAMS if PARAMS.exists() else None)
    target = Target(target_id="t-1", program_id="example-corp")

    r = est.estimate(target, radar, now=NOW, mentions="many", reporters=4)
    assert r.confidence < 1.0, (
        f"corrupt mentions signal silently ignored, confidence {r.confidence}"
    )
    assert "mentions" in r.recommendation, "partial note missing for mentions"

    r2 = est.estimate(target, radar, now=NOW, mentions=10, reporters="lots")
    assert r2.confidence < 1.0
    assert "reporters" in r2.recommendation

    # sanity: clean signals still report full confidence
    r3 = est.estimate(target, radar, now=NOW, mentions=10, reporters=4)
    assert r3.confidence == 1.0


# ---------------------------------------------------------------------------
# R2-econ-07
# ---------------------------------------------------------------------------

def test_r2econ_07_corrupt_numeric_field_keeps_target(tmp_path, caplog):
    """One corrupt numeric field must not erase the whole portfolio
    target: coerce the field to its default, keep the target, and warn
    once per target."""
    from webpent.econ.portfolio import PortfolioManager

    path = tmp_path / "portfolio.yaml"
    path.write_text(
        "targets:\n"
        "  - target_id: t-bad\n"
        "    program_id: example-corp\n"
        "    state: WATCHING\n"
        "    ev_per_hour: \"n/a\"\n"
        "    total_findings: \"oops\"\n"
        "    total_payout_usd: 100\n"
        "  - target_id: t-good\n"
        "    program_id: example-corp\n"
        "    state: ACTIVE\n"
        "    ev_per_hour: 120.0\n"
        "    total_findings: 2\n"
        "    total_payout_usd: 900\n",
        encoding="utf-8",
    )
    manager = PortfolioManager(now=NOW, log_path=tmp_path / "log.jsonl")
    with caplog.at_level(logging.WARNING, logger="webpent.econ.portfolio"):
        portfolio = manager.load(path)
    assert "t-bad" in portfolio.targets, (
        "one corrupt numeric field silently dropped the whole target"
    )
    bad = portfolio.targets["t-bad"]
    assert bad.ev_per_hour == 0.0
    assert bad.total_findings == 0
    assert bad.total_payout_usd == 100.0
    assert "t-good" in portfolio.targets
    assert portfolio.targets["t-good"].ev_per_hour == 120.0
    # the coercion is visible, not silent (L-4)
    assert "t-bad" in caplog.text and "coerced" in caplog.text


# ---------------------------------------------------------------------------
# R2-econ-08
# ---------------------------------------------------------------------------

def test_r2econ_08_no_data_report_does_not_masquerade_as_low(tmp_path):
    """The no-data report must be distinguishable from a measured LOW
    saturation: tier NO_DATA, index 0.0, confidence 0.0."""
    from webpent.econ.market_kb import Target
    from webpent.econ.saturation import SaturationEstimator

    radar = _radar(tmp_path)  # empty DB for this program
    est = SaturationEstimator(params_path=PARAMS if PARAMS.exists() else None)
    r = est.estimate(Target("t-1", "example-corp"), radar, now=NOW)
    assert "insufficient_signal" in r.recommendation
    assert r.index == 0.0
    assert r.confidence == 0.0
    assert r.tier == "NO_DATA", (
        f"no-data report masquerades as a measured tier {r.tier!r}"
    )


# ---------------------------------------------------------------------------
# R2-econ-09
# ---------------------------------------------------------------------------

def test_r2econ_09_set_scope_entries_deterministic_order():
    """A set input must yield the same (sorted) parse order in every
    process; list/tuple order stays as-is (L-3)."""
    from webpent.econ.scope_negotiator import parse_scope_entries

    scope_set = {
        "app.example.com", "api.example.net", "vault.example.org",
        "blog.example.io", "shop.example.dev", "mail.example.biz",
        "cdn.example.tv", "auth.example.name", "git.example.info",
        "ns1.example.co", "hub.example.us", "edge.example.cn",
    }
    entries = parse_scope_entries(scope_set)
    assert len(entries) == len(scope_set)
    assert entries == sorted(entries), (
        "set input produced a process-dependent (unsorted) order"
    )
    # list/tuple order is preserved as-is
    assert parse_scope_entries(["z.example.com", "a.example.com"]) == [
        "z.example.com", "a.example.com"
    ]
    # and two processes with different hash seeds agree (set order is
    # PYTHONHASHSEED-dependent without the fix)
    script = (
        "from webpent.econ.scope_negotiator import parse_scope_entries; "
        "print('|'.join(parse_scope_entries(" + repr(scope_set) + ")))"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.environ.get("PYTHONPATH", "src")
    outputs = []
    for seed in ("0", "1"):
        proc = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True,
            env={**env, "PYTHONHASHSEED": seed}, cwd=str(REPO_ROOT),
        )
        assert proc.returncode == 0, proc.stderr
        outputs.append(proc.stdout.strip())
    assert outputs[0] == outputs[1], (
        f"set input parsed differently per process: {outputs}"
    )


# ---------------------------------------------------------------------------
# R2-econ-10
# ---------------------------------------------------------------------------

def test_r2econ_10_hold_dup_risk_saturation_adjusted():
    """When the caller injects saturation, HOLD must judge duplicate risk
    on the saturation-adjusted P_dup (kb dup_rate x saturation/100),
    mirroring the ROI optimizer; without it, behavior is unchanged."""
    from webpent.econ.market_kb import MarketKB
    from webpent.econ.roi_optimizer import Finding, FindingValuation
    from webpent.econ.timing_advisor import (
        HOLD,
        REPORT_SOON,
        TimingAdvisor,
        TimingContext,
    )

    advisor = TimingAdvisor(
        MarketKB(SEED_CONFIG, payout_curves_path=SEED_CURVES),
        params_path=ROI_PARAMS if ROI_PARAMS.exists() else None,
    )
    finding = Finding("F-1", "ATO", "high", "example-social")  # dup_rate 0.55
    valuation = FindingValuation(
        finding_id="F-1", ev_usd=500.0, ev_range=(250.0, 750.0),
        recommendation="submit", components={}, rationale="test",
    )
    complete = {"poc_ready": True, "evidence_points": 3}

    # no saturation injected -> unchanged: raw 0.55 > 0.5 -> HOLD
    d = advisor.decide(finding, valuation, TimingContext(now=1_800_000_000.0, **complete))
    assert d.action == HOLD
    assert "dup risk" in d.rationale

    # saturation 50% -> adjusted dup risk 0.275 <= 0.5 -> no HOLD
    d2 = advisor.decide(
        finding, valuation,
        TimingContext(now=1_800_000_000.0, saturation_pct=50.0, **complete),
    )
    assert d2.action == REPORT_SOON, (
        f"HOLD ignored the saturation-adjusted P_dup: {d2.rationale}"
    )

    # saturation 100% -> raw rate again -> HOLD; over 100 clamps to 100
    d3 = advisor.decide(
        finding, valuation,
        TimingContext(now=1_800_000_000.0, saturation_pct=100.0, **complete),
    )
    assert d3.action == HOLD
    d4 = advisor.decide(
        finding, valuation,
        TimingContext(now=1_800_000_000.0, saturation_pct=150.0, **complete),
    )
    assert d4.action == HOLD


# ---------------------------------------------------------------------------
# R2-econ-11
# ---------------------------------------------------------------------------

def test_r2econ_11_stale_kb_entry_warns(tmp_path, caplog):
    """STALE_AFTER_DAYS must not be dead: a KB entry whose last_updated
    is older than 90 days warns on the program-load path; unparseable
    dates are skipped (fail-soft)."""
    from webpent.econ.market_kb import MarketKB

    cfg = tmp_path / "programs.yaml"
    cfg.write_text(
        "programs:\n"
        "  - id: \"stale-corp\"\n"
        "    platform: \"hackerone\"\n"
        "    scope_url: \"https://hackerone.com/stale-corp\"\n"
        "    last_updated: \"2020-01-01\"\n"
        "  - id: \"fresh-corp\"\n"
        "    platform: \"hackerone\"\n"
        "    scope_url: \"https://hackerone.com/fresh-corp\"\n"
        "    last_updated: \"2999-01-01\"\n"
        "  - id: \"garbage-corp\"\n"
        "    platform: \"hackerone\"\n"
        "    scope_url: \"https://hackerone.com/garbage-corp\"\n"
        "    last_updated: \"not-a-date\"\n",
        encoding="utf-8",
    )
    kb = MarketKB(cfg)  # constructor load must not raise on garbage dates
    with caplog.at_level(logging.WARNING, logger="webpent.econ.market_kb"):
        kb.load(now=datetime(2026, 11, 2, 12, 0, 0, tzinfo=timezone.utc))
    messages = [record.getMessage() for record in caplog.records]
    stale = [m for m in messages if "stale-corp" in m and "stale" in m]
    assert stale, f"no stale warning for a 2020 KB entry: {messages}"
    assert STALE_DAYS_90 in stale[0]
    assert not any("fresh-corp" in m for m in messages)
    assert not any("garbage-corp" in m for m in messages)
