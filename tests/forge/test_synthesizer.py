"""U-FORGE-11 — The Novel Synthesizer (red tests).

Generates every grammar combination, filters by validity, and marks
every payload honestly: source "forge-synthesis", original_source
"synthesized" (FORGE-L-1 INGEST_DONT_INVENT applies to the corpus,
not to the operator's own generation — but nothing synthesized may
pose as ingested).
"""
from __future__ import annotations

import pytest

from webpent.forge.synthesizer import (
    SQLI_GRAMMAR,
    SYNTHESIS_STRATEGIES,
    generate,
)


def test_strategies_documented():
    assert set(SYNTHESIS_STRATEGIES) == {
        "grammar_based", "learned_from_writeups", "bypass_by_mutation",
        "cross_family"}


def test_grammar_verbatim():
    assert len(SQLI_GRAMMAR["prefix"]) == 5
    assert len(SQLI_GRAMMAR["operator"]) == 4
    assert len(SQLI_GRAMMAR["condition"]) == 5
    assert len(SQLI_GRAMMAR["suffix"]) == 5
    assert len(SQLI_GRAMMAR["union_clause"]) == 3


def test_generate_total_combinations():
    assert generate()["total_combinations"] == 5 * 4 * 5 * 5 * 3


def test_generate_valid_payloads():
    result = generate()
    assert result["valid_payloads"]
    for payload in result["valid_payloads"]:
        assert payload.raw
        assert payload.family.value == "sqli"


def test_union_payloads_contain_union_select():
    result = generate()
    union = [p for p in result["valid_payloads"]
             if "UNION SELECT" in p.raw]
    assert union


def test_payloads_deduplicated():
    result = generate()
    raws = [p.raw for p in result["valid_payloads"]]
    assert len(raws) == len(set(raws))


def test_synth_not_posed_as_ingested():
    result = generate()
    for payload in result["valid_payloads"]:
        assert payload.source == "forge-synthesis"
        assert payload.attribution.original_source == "synthesized"
        assert payload.attribution.license == "generated"


def test_deterministic():
    a = generate()
    b = generate()
    assert [(p.raw, p.payload_id) for p in a["valid_payloads"]] == \
        [(p.raw, p.payload_id) for p in b["valid_payloads"]]


def test_limit_parameter():
    result = generate(limit=25)
    assert len(result["valid_payloads"]) <= 25


def test_validity_filter_removes_conflicts():
    # A prefix that already closes a quote combined with a condition
    # that opens another must not survive the validity filter.
    result = generate()
    assert "' AND (SELECT" not in {p.raw for p in result["valid_payloads"]}
