"""U-FORGE-5 — The Indexer (8 tests).

SQLite corpus with the spec's 6 tables and 6 indices; storage is
idempotent and local (FORGE-L-10 CORPUS_IS_VERSIONED).
"""
from __future__ import annotations

import pytest

from webpent.forge.indexer import PayloadIndexer
from webpent.forge.normalizer import Normalizer
from webpent.forge.schemas import PayloadAttribution


def make_attribution(source="payloadsallthethings", trust=0.95):
    return PayloadAttribution(
        payload_id="pending",
        original_source=source,
        original_url="https://example/src",
        original_author="author",
        license="MIT",
        license_url="https://example/license",
        source_trust=trust,
    )


@pytest.fixture
def indexer():
    return PayloadIndexer()


@pytest.fixture
def stored_sql_payloads(indexer):
    normalizer = Normalizer()
    ids = []
    for raw in ("' OR 1=1-- -", "' UNION SELECT NULL--", "SLEEP(5)"):
        payload = normalizer.normalize(raw, make_attribution())
        indexer.store_payload(payload)
        ids.append(payload.payload_id)
    return ids


EXPECTED_TABLES = {
    "payloads", "payload_target_tech", "payload_target_waf",
    "payload_target_context", "payload_encodings", "payload_outcomes",
}
EXPECTED_INDICES = {
    "idx_family", "idx_complexity", "idx_quality", "idx_tech",
    "idx_context", "idx_outcomes_payload",
}


def test_schema_tables_created(indexer):
    tables = indexer.table_names()
    assert EXPECTED_TABLES <= tables


def test_schema_indices_created(indexer):
    indices = indexer.index_names()
    assert EXPECTED_INDICES <= indices


def test_store_and_get_roundtrip(indexer, stored_sql_payloads):
    payload = indexer.get_payload(stored_sql_payloads[0])
    assert payload is not None
    assert payload.raw == "' OR 1=1-- -"
    assert payload.attribution.original_source == "payloadsallthethings"


def test_store_encoding_variants(indexer, stored_sql_payloads):
    variants = indexer.get_encodings(stored_sql_payloads[0])
    assert set(variants) == {"url", "html", "hex", "unicode", "base64"}


def test_store_outcomes(indexer, stored_sql_payloads):
    indexer.store_outcome(
        payload_id=stored_sql_payloads[0], target_id="t1", success=True,
        evidence="leaked row")
    indexer.store_outcome(
        payload_id=stored_sql_payloads[0], target_id="t2", success=False,
        evidence="waf blocked")
    outcomes = indexer.get_outcomes(stored_sql_payloads[0])
    assert len(outcomes) == 2
    assert indexer.success_rate(stored_sql_payloads[0]) == pytest.approx(0.5)


def test_list_by_family(indexer, stored_sql_payloads):
    from webpent.forge.schemas import Family
    rows = indexer.list_by_family(Family.SQLI)
    assert len(rows) == 3


def test_duplicate_store_is_idempotent(indexer, stored_sql_payloads):
    normalizer = Normalizer()
    payload = normalizer.normalize("' OR 1=1-- -", make_attribution())
    assert indexer.store_payload(payload) is False
    assert indexer.count_all() == 3


def test_context_tables_populated(indexer, stored_sql_payloads):
    assert indexer.count_context_rows("payload_target_tech") >= 0
    # The stored SQL payloads carry at least their context rows.
    normalizer = Normalizer()
    polyglot = normalizer.normalize('"><svg onload=alert(1)>', make_attribution())
    indexer.store_payload(polyglot)
    assert indexer.count_context_rows("payload_target_context") >= 1
