"""U-FORGE-9 — The Chaining Engine (red tests).

Chains payloads so they work across contexts. Every variant carries
the original payload's attribution (FORGE-L-3 ATTRIBUTION_IS_SACRED);
the chain itself is a transformation, not a new anonymous payload.
"""
from __future__ import annotations

import pytest

from forge.conftest import PAYLOADSALLTHETHINGS_MD
from webpent.forge.chaining import CHAIN_TYPES, chain
from webpent.forge.indexer import PayloadIndexer
from webpent.forge.ingester import MultiSourceIngester


@pytest.fixture
def payload():
    indexer = PayloadIndexer()
    ingester = MultiSourceIngester(indexer)
    ingester.ingest("payloadsallthethings",
                    content=PAYLOADSALLTHETHINGS_MD, dry_run=False)
    return min(indexer.list_all(), key=lambda p: p.payload_id)


def test_chain_types_documented_and_total():
    assert set(CHAIN_TYPES) == {
        "polyglot", "double_encoding", "split_payload", "prefix_bypass",
        "context_break"}
    assert CHAIN_TYPES["polyglot"]["contexts"] == ["javascript", "url"]
    assert CHAIN_TYPES["double_encoding"]["works_against"] == \
        ["waf_that_decodes_once"]
    assert CHAIN_TYPES["context_break"]["contexts"] == ["html_in_script"]


def test_polyglot_chain(payload):
    variants = chain(payload, "polyglot")
    assert variants
    out = variants[0]
    assert out.raw.startswith("javascript:") and out.raw.endswith("//")
    assert payload.raw in out.raw
    assert out.is_polyglot is True
    assert set(out.target_context) >= {"javascript", "url"}


def test_double_encoding_verbatim(payload):
    variants = chain(payload, "double_encoding")
    sqli = next(v for v in variants if "'" in payload.raw)
    assert "%2527" in sqli.raw


def test_split_payload_across_params(payload):
    variants = chain(payload, "split_payload")
    assert len(variants) == 2
    assert all("multiple_params" in v.target_context for v in variants)
    assert "".join(v.raw for v in variants).replace(" ", "") == \
        payload.raw.replace(" ", "")


def test_prefix_bypass(payload):
    variants = chain(payload, "prefix_bypass")
    assert variants[0].raw.startswith("safe")
    assert payload.raw in variants[0].raw


def test_context_break_verbatim(payload):
    script = "<script>alert(1)</script>"
    variants = chain(payload, "context_break", raw_override=script)
    assert variants[0].raw == "</script><script>alert(1)</script>"


def test_unknown_chain_type_raises(payload):
    with pytest.raises(KeyError):
        chain(payload, "no_such_chain")


def test_attribution_is_sacred(payload):
    for chain_type in CHAIN_TYPES:
        for variant in chain(payload, chain_type):
            assert variant.attribution is not None
            assert variant.attribution.original_source == \
                payload.attribution.original_source
            assert variant.attribution.license == payload.attribution.license


def test_variants_deterministic(payload):
    a = chain(payload, "polyglot")
    b = chain(payload, "polyglot")
    assert [(v.raw, v.payload_id) for v in a] == \
        [(v.raw, v.payload_id) for v in b]


def test_variant_ids_distinct_from_origin(payload):
    seen = {payload.payload_id}
    for chain_type in CHAIN_TYPES:
        for variant in chain(payload, chain_type):
            assert variant.payload_id not in seen
            seen.add(variant.payload_id)
