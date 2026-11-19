"""U-FORGE-8 — The Encoding Engine (red tests).

Generate encoded variants of a payload with the spec's documented
encoding table plus WAF combo strategies. Pure functions; zero network.
"""
from __future__ import annotations

import urllib.parse

import pytest

from webpent.forge.encoding_engine import ENCODINGS, EncodedVariant, \
    encode, generate_variants


def test_encodings_documented_and_total():
    assert set(ENCODINGS) == {
        "url", "url_double", "url_unicode",
        "html_entities", "html_numeric", "html_hex",
        "hex", "base64", "base64_url", "unicode_escape",
        "upper", "lower", "case_alternate",
        "no_whitespace", "comment_split", "tab_split", "newline_split",
    }


def test_url_encoding():
    assert encode("<x>", "url") == urllib.parse.quote("<x>")


def test_url_double_encoding():
    once = urllib.parse.quote("<x>")
    assert encode("<x>", "url_double") == urllib.parse.quote(once)


def test_base64_encoding_round_trip():
    import base64
    out = encode("alert(1)", "base64")
    assert base64.b64decode(out).decode() == "alert(1)"


def test_case_alternate_formula():
    # Spec formula: even index lower, odd index upper.
    assert encode("abcd", "case_alternate") == "aBcD"


def test_comment_split():
    assert encode("union select", "comment_split") == "union/**/select"


def test_variants_exclude_identity():
    variants = generate_variants("AbC")
    assert variants
    assert all(v.encoded != "AbC" for v in variants)


def test_variant_names_unique():
    variants = generate_variants("<script>alert(1)</script>")
    names = [v.name for v in variants]
    assert len(names) == len(set(names))


def test_deterministic():
    a = generate_variants("alert(1)")
    b = generate_variants("alert(1)")
    assert [(v.name, v.encoded) for v in a] == \
        [(v.name, v.encoded) for v in b]


def test_encoded_variant_frozen():
    v = EncodedVariant(name="upper", encoded="A")
    with __import__("pytest").raises(Exception):
        v.name = "x"


# -- FULL SWEEP 2026-10-20 fix (F-04) --------------------------------------
# An encoder's internal bug must fail loud; only the documented
# contract violations (non-str input, lone-surrogate Unicode) may be
# skipped silently.


def test_unexpected_encoder_error_propagates(monkeypatch):
    from webpent.forge import encoding_engine

    def broken(_x):
        raise RuntimeError("internal encoder bug")

    monkeypatch.setitem(ENCODINGS, "broken", broken)
    with pytest.raises(RuntimeError):
        encoding_engine.generate_variants("probe")


def test_lone_surrogate_skips_only_unencodable_variants():
    from webpent.forge.encoding_engine import generate_variants
    variants = generate_variants("\ud800x")
    assert all(isinstance(v.encoded, str) for v in variants)
    assert "base64" not in {v.name for v in variants}
