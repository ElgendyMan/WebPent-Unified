"""U-FORGE-4 — The Normalizer (10 tests).

One schema for every payload: deterministic ids, five encoding
variants, documented family / complexity / novelty arithmetic, and
polyglot detection (FORGE-L-6 DETERMINISTIC_CORE).
"""
from __future__ import annotations

import base64
import urllib.parse

import pytest

from webpent.forge.normalizer import Normalizer
from webpent.forge.schemas import PayloadAttribution


def make_attribution(source="payloadsallthethings", trust=0.95):
    return PayloadAttribution(
        payload_id="pending",
        original_source=source,
        original_url=f"https://example/{source}",
        original_author="author",
        license="MIT",
        license_url="https://example/license",
        source_trust=trust,
    )


@pytest.fixture
def normalizer():
    return Normalizer()


def test_generates_all_encoding_variants(normalizer):
    payload = normalizer.normalize("' OR 1=1-- -", make_attribution())
    variants = payload.encoded_variants
    assert set(variants) == {"url", "html", "hex", "unicode", "base64"}
    assert variants["url"] == urllib.parse.quote("' OR 1=1-- -")
    assert variants["base64"] == base64.b64encode(
        "' OR 1=1-- -".encode()).decode()


def test_detect_family_auto_sqli(normalizer):
    payload = normalizer.normalize("' UNION SELECT NULL--", make_attribution())
    assert payload.family.value == "SQLI"


def test_detect_family_auto_xss(normalizer):
    payload = normalizer.normalize("<script>alert(1)</script>", make_attribution())
    assert payload.family.value == "XSS"


def test_explicit_family_wins(normalizer):
    from webpent.forge.schemas import Family
    payload = normalizer.normalize(
        "<script>alert(1)</script>", make_attribution(), family=Family.SSRF)
    assert payload.family == Family.SSRF


def test_complexity_simple(normalizer):
    payload = normalizer.normalize("admin", make_attribution())
    assert payload.complexity == "simple"


def test_complexity_advanced_on_obfuscation(normalizer):
    payload = normalizer.normalize("UNION SELECT char(0x41)", make_attribution())
    assert payload.complexity == "advanced"


def test_polyglot_is_expert(normalizer):
    payload = normalizer.normalize(
        '"><svg onload=alert(1)>', make_attribution())
    assert payload.is_polyglot is True
    assert payload.complexity == "expert"


def test_tech_requirements_extracted(normalizer):
    payload = normalizer.normalize("WAITFOR DELAY '0:0:5'", make_attribution())
    assert "mssql" in payload.target_tech
    payload = normalizer.normalize("SLEEP(5)", make_attribution())
    assert "mysql" in payload.target_tech


def test_id_deterministic_and_distinct(normalizer):
    a = normalizer.normalize("' OR 1=1-- -", make_attribution())
    b = normalizer.normalize("' OR 1=1-- -", make_attribution())
    c = normalizer.normalize("' OR 1=2-- -", make_attribution())
    assert a.payload_id == b.payload_id
    assert a.payload_id != c.payload_id


def test_novelty_scored_and_common_reduced(normalizer):
    common = normalizer.normalize("' or 1=1--", make_attribution())
    rare = normalizer.normalize(
        "' UNION SELECT version(),@@hostname,2-- -", make_attribution())
    assert 0.0 <= common.novelty_score <= 1.0
    assert 0.0 <= rare.novelty_score <= 1.0
    assert rare.novelty_score > common.novelty_score
