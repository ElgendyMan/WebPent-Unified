"""U-FORGE-1 — The Multi-Source Ingester (10 tests per spec).

The ingester parses PRE-FETCHED content only: zero live network from
the core (FORGE-L-1 INGEST_DONT_INVENT, FORGE-L-9 SCHEDULED_INGESTION).
Every stored payload carries its license and attribution.
"""
from __future__ import annotations

import pytest

from forge.conftest import DUPLICATED_TXT
from webpent.forge.ingester import MultiSourceIngester
from webpent.forge.indexer import PayloadIndexer


@pytest.fixture
def indexer():
    return PayloadIndexer()


@pytest.fixture
def ingester(indexer):
    return MultiSourceIngester(indexer=indexer)


# ---------------------------------------------------------------------------
# Per-source parsing (tests 1-5)
# ---------------------------------------------------------------------------

def test_parse_payloadsallthethings(ingester, sample_contents):
    report = ingester.ingest(
        "payloadsallthethings", content=sample_contents["payloadsallthethings"],
        dry_run=True)
    assert report.payloads_found >= 3
    families = {p.family for p in report.payloads}
    assert any(f.value == "SQLI" for f in families)


def test_parse_hacktricks(ingester, sample_contents):
    report = ingester.ingest(
        "hacktricks", content=sample_contents["hacktricks"], dry_run=True)
    assert report.payloads_found >= 2
    families = {p.family for p in report.payloads}
    assert any(f.value == "SSRF" for f in families)


def test_parse_seclists(ingester, sample_contents):
    report = ingester.ingest(
        "seclists", content=sample_contents["seclists"], dry_run=True)
    assert report.payloads_found == 3


def test_parse_hackerone_disclosures(ingester, sample_contents):
    report = ingester.ingest(
        "hackerone_disclosures",
        content=sample_contents["hackerone_disclosures"], dry_run=True)
    assert report.payloads_found >= 1
    payload = report.payloads[0]
    assert "UNION SELECT" in payload.raw
    assert payload.attribution.original_source == "hackerone_disclosures"


def test_parse_exploitdb(ingester, sample_contents):
    report = ingester.ingest(
        "exploitdb", content=sample_contents["exploitdb"], dry_run=True)
    assert report.payloads_found == 2
    assert report.source_trust == pytest.approx(0.85)


# ---------------------------------------------------------------------------
# Normalization, dedup, attribution, dry-run (tests 6-10)
# ---------------------------------------------------------------------------

def test_normalization_consistent(ingester, sample_contents):
    """Same content ingested twice yields identical payload ids (L-6)."""
    content = sample_contents["payloadsallthethings"]
    first = ingester.ingest("payloadsallthethings", content=content, dry_run=True)
    second = ingester.ingest("payloadsallthethings", content=content, dry_run=True)
    assert [p.payload_id for p in first.payloads] == \
        [p.payload_id for p in second.payloads]


def test_duplicate_detection(ingester, indexer):
    report = ingester.ingest("seclists", content=DUPLICATED_TXT, dry_run=True)
    assert report.duplicates_removed == 1
    assert report.payloads_found == 3


def test_license_tracked(ingester, sample_contents):
    for source_id, content in sample_contents.items():
        report = ingester.ingest(source_id, content=content, dry_run=True)
        for payload in report.payloads:
            assert payload.attribution.license, f"{source_id} lost its license"


def test_attribution_preserved(ingester, sample_contents):
    for source_id, content in sample_contents.items():
        report = ingester.ingest(source_id, content=content, dry_run=True)
        for payload in report.payloads:
            assert payload.attribution.original_source == source_id
            assert payload.attribution.source_trust > 0.0


def test_dry_run_no_store(ingester, indexer, sample_contents):
    report = ingester.ingest(
        "payloadsallthethings",
        content=sample_contents["payloadsallthethings"], dry_run=True)
    assert report.payloads_stored == 0
    assert indexer.count_all() == 0

    report = ingester.ingest(
        "payloadsallthethings",
        content=sample_contents["payloadsallthethings"], dry_run=False)
    assert report.payloads_stored == report.payloads_found
    assert indexer.count_all() == report.payloads_stored
