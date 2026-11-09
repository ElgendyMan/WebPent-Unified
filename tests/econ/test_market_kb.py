"""U-ECON-1 — MarketKB tests (NC-ECON-1 charter, exact test names)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from webpent.econ.market_kb import TRUSTED_SOURCES, MarketKB

REPO = Path(__file__).resolve().parents[2]
SEED_CONFIG = REPO / "config" / "econ" / "programs.yaml"
SEED_CURVES = REPO / "config" / "econ" / "payout_curves.yaml"

MIN_SCHEMA_KEYS = {
    "id",
    "platform",
    "scope_url",
    "last_updated",
    "payout_curves",
    "stats",
    "vuln_weights",
    "notes",
}


def _kb(tmp_path: Path) -> MarketKB:
    return MarketKB(
        SEED_CONFIG,
        payout_curves_path=SEED_CURVES,
        ingest_log_path=tmp_path / "ingest_log.jsonl",
    )


def _snapshot(tmp_path: Path, source: str) -> Path:
    path = tmp_path / f"snap_{source}.json"
    path.write_text(
        json.dumps(
            {
                "source": source,
                "programs": [
                    {
                        "id": "ingest-test-corp",
                        "platform": "hackerone",
                        "scope_url": "https://hackerone.com/ingest-test-corp",
                        "last_updated": "2026-10-01",
                        "payout_curves": {
                            "critical": {"min": 100, "max": 900, "typical": 500},
                        },
                        "stats": {"dup_rate": 0.1, "bounty_ratio": 0.9,
                                  "response_time_days": {"typical": 2, "p90": 7}},
                        "vuln_weights": {"ATO": 1.0},
                        "notes": "test snapshot",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_load_program_returns_full_schema():
    kb = _kb(Path("/tmp"))
    program = kb.load_program("example-corp")
    assert program.program_id == "example-corp"
    assert program.platform == "hackerone"
    assert program.scope_url.startswith("https://")
    assert program.last_updated
    assert set(program.payout_curves) == {"critical", "high", "medium", "low"}
    assert 0.0 <= program.dup_rate <= 1.0
    assert 0.0 <= program.bounty_ratio <= 1.0
    assert program.response.typical_days >= 0 and program.response.p90_days >= 0
    assert isinstance(program.vuln_weights, dict) and program.vuln_weights
    assert program.notes
    # the shipped seed carries the full documented schema for every program
    import yaml

    raw = yaml.safe_load(SEED_CONFIG.read_text(encoding="utf-8"))
    assert isinstance(raw, dict) and len(raw["programs"]) >= 10  # final DoD #1
    for row in raw["programs"]:
        assert set(row) >= MIN_SCHEMA_KEYS, f"missing schema keys in {row.get('id')}"


def test_payout_range_returns_min_max_typical():
    kb = _kb(Path("/tmp"))
    curve = kb.get_payout_range("example-corp", "critical")
    assert curve.minimum == 5000 and curve.maximum == 25000 and curve.typical == 10000
    assert curve.minimum <= curve.typical <= curve.maximum
    # global fallback when the program lacks a curve for that severity
    kb_fallback = MarketKB(
        None, payout_curves_path=SEED_CURVES, ingest_log_path=None
    )
    fallback = kb_fallback.get_payout_range("nonexistent", "high")
    assert fallback.minimum <= fallback.typical <= fallback.maximum
    # unknown severity -> zero range, never a raise
    zero = kb.get_payout_range("example-corp", "nonexistent")
    assert (zero.minimum, zero.typical, zero.maximum) == (0.0, 0.0, 0.0)


def test_unknown_program_raises_clear_error():
    kb = _kb(Path("/tmp"))
    with pytest.raises(KeyError) as excinfo:
        kb.load_program("definitely-not-a-program")
    assert "unknown program" in str(excinfo.value).lower()
    assert "programs.yaml" in str(excinfo.value)


def test_ingest_dry_run_does_not_write(tmp_path):
    log = tmp_path / "ingest_log.jsonl"
    kb = MarketKB(SEED_CONFIG, payout_curves_path=SEED_CURVES, ingest_log_path=log)
    snap = _snapshot(tmp_path, "hackerone")
    before = kb.list_programs()
    report = kb.ingest_snapshot(snap, dry_run=True)
    assert report.dry_run is True
    assert report.status == "would_ingest"
    assert not log.exists(), "dry run must not touch the ingest log"
    assert kb.list_programs() == before, "dry run must not mutate the KB"
    with pytest.raises(KeyError):
        kb.load_program("ingest-test-corp")


def test_ingest_rejects_untrusted_source(tmp_path):
    log = tmp_path / "ingest_log.jsonl"
    kb = MarketKB(SEED_CONFIG, payout_curves_path=SEED_CURVES, ingest_log_path=log)
    snap = _snapshot(tmp_path, "random-blog-scrape")
    report = kb.ingest_snapshot(snap, dry_run=False)
    assert report.status == "rejected"
    assert "untrusted source" in report.reason
    assert not log.exists(), "rejected ingests are never logged as fetches"
    with pytest.raises(KeyError):
        kb.load_program("ingest-test-corp")
    # every trusted source is documented: the trusted list itself is bounded
    assert frozenset(
        {"hackerone", "hackerone_hacktivity", "bugcrowd", "cvss_public", "program_policy_page"}
    ) == TRUSTED_SOURCES


def test_ingest_log_is_append_only(tmp_path):
    log = tmp_path / "ingest_log.jsonl"
    kb = MarketKB(SEED_CONFIG, payout_curves_path=SEED_CURVES, ingest_log_path=log)
    first = _snapshot(tmp_path, "hackerone")
    report = kb.ingest_snapshot(first, dry_run=False)
    assert report.status == "ingested"
    assert kb.load_program("ingest-test-corp").dup_rate == 0.1
    lines_after_first = log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines_after_first) == 1
    # a second ingest appends; the first record is untouched
    second = _snapshot(tmp_path, "bugcrowd")
    kb.ingest_snapshot(second, dry_run=False)
    lines_after_second = log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines_after_second) == 2
    assert lines_after_second[0] == lines_after_first[0]
    record = json.loads(lines_after_second[1])
    assert record["source"] == "bugcrowd"
    assert record["accepted"] == 1
