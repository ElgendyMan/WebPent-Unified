"""U-FORGE-12 — The Adversarial Generator (red tests).

Generates WAF-specific bypass variants of a payload. The WAF corpora
are documented verbatim (cloudflare / akamai / aws_waf / imperva); an
unknown WAF yields nothing rather than a guess. Spec examples are
reproduced exactly for the canonical payload.
"""
from __future__ import annotations

import pytest

from forge.conftest import PAYLOADSALLTHETHINGS_MD
from webpent.forge.adversarial import WAF_BYPASSES, generate_bypasses
from webpent.forge.indexer import PayloadIndexer
from webpent.forge.ingester import MultiSourceIngester

CANONICAL = "<script>alert(1)</script>"


@pytest.fixture
def payload():
    indexer = PayloadIndexer()
    ingester = MultiSourceIngester(indexer)
    ingester.ingest("payloadsallthethings",
                    content=PAYLOADSALLTHETHINGS_MD, dry_run=False)
    return min(indexer.list_all(), key=lambda p: p.payload_id)


def test_waf_bypasses_documented():
    assert set(WAF_BYPASSES) == {
        "cloudflare", "akamai", "aws_waf", "imperva"}
    assert len(WAF_BYPASSES["cloudflare"]) == 5
    assert len(WAF_BYPASSES["akamai"]) == 3
    assert len(WAF_BYPASSES["aws_waf"]) == 2
    assert len(WAF_BYPASSES["imperva"]) == 2


def test_cloudflare_split_keywords_verbatim(payload):
    variants = generate_bypasses(payload, "cloudflare", raw_override=CANONICAL)
    assert variants[0].raw == \
        "<scr<script>ipt>alert(1)</scr</script>ipt>"


def test_cloudflare_all_five_variants(payload):
    variants = generate_bypasses(payload, "cloudflare",
                                 raw_override=CANONICAL)
    assert len(variants) == 5
    assert any("\\u003c" in v.raw for v in variants)
    assert any("/**/" in v.raw for v in variants)


def test_akamai_hex_and_double_url(payload):
    variants = generate_bypasses(payload, "akamai", raw_override=CANONICAL)
    assert len(variants) == 3
    assert any("%3C" in v.raw for v in variants)
    assert any("%253C" in v.raw for v in variants)


def test_aws_waf_base64_wrap(payload):
    variants = generate_bypasses(payload, "aws_waf", raw_override=CANONICAL)
    assert len(variants) == 2
    assert any(v.raw.startswith("data:text/html;base64,") for v in variants)


def test_imperva_whitespace(payload):
    variants = generate_bypasses(payload, "imperva", raw_override=CANONICAL)
    assert len(variants) == 2
    assert any("<script\t>" in v.raw for v in variants)


def test_unknown_waf_yields_nothing(payload):
    assert generate_bypasses(payload, "barracuda") == []


def test_attribution_is_sacred(payload):
    for waf in WAF_BYPASSES:
        for variant in generate_bypasses(payload, waf):
            assert variant.attribution.original_source == \
                payload.attribution.original_source


def test_variants_deterministic(payload):
    a = generate_bypasses(payload, "cloudflare")
    b = generate_bypasses(payload, "cloudflare")
    assert [(v.raw, v.payload_id) for v in a] == \
        [(v.raw, v.payload_id) for v in b]


def test_variants_are_normalized(payload):
    variant = generate_bypasses(payload, "aws_waf")[0]
    assert variant.source == "forge-adversarial"
    assert variant.family == payload.family
