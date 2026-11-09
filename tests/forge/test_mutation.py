"""U-FORGE-10 — The Mutation Engine (red tests).

Single-pass mutations first, structural replacements second, then sort
by predicted quality and return the top-N. Case-change uses a fixed
seed so output is deterministic. Variants stay attributed (L-3).
"""
from __future__ import annotations

import pytest

from forge.conftest import PAYLOADSALLTHETHINGS_MD
from webpent.forge.mutation import (
    MUTATIONS,
    MUTATION_SEED,
    mutate,
)
from webpent.forge.schemas import NormalizedPayload, PayloadAttribution


def _attribution():
    return PayloadAttribution(
        payload_id="mut-origin", original_source="test-fixture",
        original_url="https://example.test/corpus", original_author=None,
        license="MIT", license_url="https://example.test/MIT")


def _payload():
    return NormalizedPayload(
        payload_id="mut-origin", family="SQLI", subfamily="tautology",
        raw="' AND 1=1 <script>alert(1)</script>", encoded_variants=(),
        target_tech=(), target_waf=None, target_context=("url",),
        complexity=1, source="test", attribution=_attribution(),
        quality_score=0.5, novelty_score=0.5, is_polyglot=False,
        chains_with=(), requires=())


@pytest.fixture
def payload():
    return _payload()


def test_mutations_documented():
    for name in ("case_change", "char_replace", "whitespace_insert",
                 "comment_insert"):
        assert callable(MUTATIONS[name])
    assert set(MUTATIONS["tag_alternatives"]["<script>"]) == \
        {"<svg>", "<img>", "<iframe>", "<body>", "<details>"}
    assert set(MUTATIONS["alert_alternatives"]["alert(1)"]) == \
        {"confirm(1)", "prompt(1)", "eval('alert(1)')"}
    assert set(MUTATIONS["operator_swap"]["="]) == \
        {"LIKE", "IN", "BETWEEN"}
    assert set(MUTATIONS["operator_swap"]["AND"]) == \
        {"&&", "OR NOT", "||"}
    assert len(MUTATIONS["sql_injection_variants"]) == 5
    assert MUTATION_SEED == 1337


def test_char_replace():
    assert MUTATIONS["char_replace"]("<b>") == "%3Cb%3E"


def test_whitespace_insert():
    assert MUTATIONS["whitespace_insert"]("a b") == "a  b"


def test_comment_insert():
    assert MUTATIONS["comment_insert"]("a b") == "a/*x*/b"


def test_case_change_deterministic():
    first = MUTATIONS["case_change"]("<script>alert(1)</script>")
    second = MUTATIONS["case_change"]("<script>alert(1)</script>")
    assert first == second


def test_mutate_single_pass_mutations(payload):
    variants = mutate(payload, max_variants=50)
    raws = [v.raw for v in variants]
    assert "%3C" in "".join(raws)
    assert any(raw == payload.raw.replace(" ", "  ") for raw in raws)
    assert any("/*x*/" in raw for raw in raws)


def test_structural_mutations_named(payload):
    variants = mutate(payload, max_variants=100)
    names = {v.subfamily for v in variants}
    assert "replace_<script>_with_<svg>" in names
    assert "operator_=_to_LIKE" in names


def test_mutate_top_n(payload):
    assert len(mutate(payload, max_variants=7)) == 7


def test_mutate_sorted_by_predicted_quality(payload):
    variants = mutate(payload, max_variants=100)
    scores = [v.quality_score for v in variants]
    assert scores == sorted(scores, reverse=True)


def test_attribution_is_sacred(payload):
    for variant in mutate(payload, max_variants=5):
        assert variant.attribution.original_source == \
            payload.attribution.original_source


def test_deterministic(payload):
    a = mutate(payload, max_variants=20)
    b = mutate(payload, max_variants=20)
    assert [(v.raw, v.payload_id) for v in a] == \
        [(v.raw, v.payload_id) for v in b]
