"""U-ECON-7 — CompetitiveRadar tests (NC-ECON-1 charter, exact test names)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from webpent.econ.competitive import (
    DEFAULT_DB_PATH,
    TRUSTED_FINDING_SOURCES,
    CompetitiveRadar,
)

NOW = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)


def _radar(tmp_path: Path) -> CompetitiveRadar:
    repo_params = (
        Path(__file__).resolve().parents[2] / "config" / "econ" / "competition_params.yaml"
    )
    return CompetitiveRadar(
        tmp_path / "econ" / "competitive.db",
        params_path=repo_params if repo_params.exists() else None,
    )


def _snapshot(tmp_path: Path, source: str, findings: list[dict]) -> Path:
    path = tmp_path / f"snap_{source}.json"
    path.write_text(
        json.dumps({"source": source, "findings": findings}), encoding="utf-8"
    )
    return path


def _finding(program="example-corp", vuln_class="IDOR", endpoint="/api/v2/users/{id}",
             days_ago=10, source=None):
    return {
        "program_id": program,
        "severity": "high",
        "vuln_class": vuln_class,
        "endpoint_signature": endpoint,
        "disclosed_at": (NOW - timedelta(days=days_ago)).isoformat(),
        "source": source or "hackerone_hacktivity",
    }


def test_ingest_dry_run_safe(tmp_path):
    radar = _radar(tmp_path)
    snap = _snapshot(tmp_path, "hackerone_hacktivity", [_finding(), _finding(days_ago=5)])
    report = radar.ingest(str(snap))  # dry_run defaults to True
    assert report.status == "would_ingest"
    assert report.programs_accepted == 2
    assert report.dry_run is True
    # dry run must not have created the database at all
    assert not radar.db_path.exists()
    # untrusted source is refused outright, dry run or not
    bad = _snapshot(tmp_path, "random_hunter_blog", [_finding()])
    assert radar.ingest(str(bad)).status == "rejected"


def test_findings_stored_with_source(tmp_path):
    radar = _radar(tmp_path)
    snap1 = _snapshot(tmp_path, "bugcrowd_crowdstream", [_finding(source=None)])
    snap1.write_text(json.dumps({
        "source": "bugcrowd_crowdstream",
        "findings": [_finding()],
    }), encoding="utf-8")
    snap2 = _snapshot(tmp_path, "github_advisories", [_finding(days_ago=3)])
    assert radar.ingest(str(snap1), dry_run=False).status == "ingested"
    assert radar.ingest(str(snap2), dry_run=False).programs_accepted == 1
    got = radar.get_findings("example-corp", NOW - timedelta(days=30))
    assert len(got) == 2
    sources = {f.source for f in got}
    assert sources == {"bugcrowd_crowdstream", "github_advisories"}
    # since filter cuts the older one out
    recent = radar.get_findings("example-corp", NOW - timedelta(days=7))
    assert len(recent) == 1
    assert recent[0].source == "github_advisories"


def test_opportunities_exclude_covered_classes(tmp_path):
    radar = _radar(tmp_path)
    snap = _snapshot(tmp_path, "hackerone_hacktivity", [
        _finding(vuln_class="IDOR", days_ago=2),
        _finding(vuln_class="IDOR", days_ago=40),
    ])
    radar.ingest(str(snap), dry_run=False)
    opps = radar.find_opportunities("example-corp", now=NOW)
    by_class = {o.vuln_class: o for o in opps}
    # IDOR has a public finding 2 days ago: inside the 90-day window
    assert "IDOR" not in by_class


def test_opportunities_include_uncovered_classes(tmp_path):
    radar = _radar(tmp_path)
    snap = _snapshot(tmp_path, "hackerone_hacktivity", [_finding(vuln_class="XSS", days_ago=2)])
    radar.ingest(str(snap), dry_run=False)
    opps = radar.find_opportunities("example-corp", now=NOW)
    by_class = {o.vuln_class: o for o in opps}
    # never seen -> opportunity with lower confidence
    assert "SQLI" in by_class
    assert by_class["SQLI"].last_seen is None
    assert by_class["SQLI"].confidence == 0.4
    assert by_class["SQLI"].reasoning
    # seen but beyond the window -> opportunity with higher confidence
    stale = _snapshot(tmp_path, "hackerone_hacktivity",
                      [_finding(vuln_class="RCE", days_ago=120)])
    radar.ingest(str(stale), dry_run=False)
    opps2 = radar.find_opportunities("example-corp", now=NOW)
    by_class2 = {o.vuln_class: o for o in opps2}
    assert "RCE" in by_class2
    assert by_class2["RCE"].confidence == 0.6
    assert by_class2["RCE"].last_seen is not None


def test_no_pii_in_db(tmp_path):
    radar = _radar(tmp_path)
    snap = _snapshot(tmp_path, "hackerone_hacktivity", [_finding()])
    radar.ingest(str(snap), dry_run=False)
    conn = sqlite3.connect(str(radar.db_path))
    columns = [row[1] for row in conn.execute("PRAGMA table_info(findings)")]
    conn.close()
    # schema carries exactly the six non-PII fields — nothing else can hide
    assert set(columns) == {
        "program_id", "severity", "vuln_class", "endpoint_signature",
        "disclosed_at", "source",
    }
    forbidden = ("hunter", "username", "user_name", "email", "avatar",
                 "profile", "reporter", "handle", "real_name")
    for col in columns:
        assert not any(word in col for word in forbidden)


def test_db_is_local_only(tmp_path):
    # a URL-ish path is refused: the DB can never point at a network host
    for bad in ("https://evil.example.com/x.db", "http://evil/db", "s3://bucket/db"):
        with pytest.raises(ValueError):
            CompetitiveRadar(bad)
    radar = _radar(tmp_path)
    assert "://" not in str(radar.db_path)
    # the documented default is a relative local workspace path
    assert DEFAULT_DB_PATH == "download/econ/competitive.db"
    # documented sources only, and at least two general ones (DoD)
    assert len(TRUSTED_FINDING_SOURCES) >= 2
