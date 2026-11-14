"""U-FORGE-7 — The Contextualizer (red tests).

Adapt a payload to a target context (json / html_attribute /
javascript / xml) or WAF (cloudflare / akamai / aws_waf) using the
spec's documented rules. Pure string work; zero network.
"""
from __future__ import annotations

import pytest

from webpent.forge.contextualizer import ADAPTATION_RULES, Contextualizer

ORIGINAL = "<script>alert(1)</script>"


def test_rules_documented_and_total():
    assert set(ADAPTATION_RULES) == {
        "json", "html_attribute", "javascript", "xml",
        "cloudflare", "akamai", "aws_waf"}


def test_json_unicode_escapes():
    # Spec example, verbatim.
    assert Contextualizer().adapt(ORIGINAL, "json") == \
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"


def test_json_escapes_quotes():
    # JSON escaping keeps the quote character but escapes it.
    out = Contextualizer().adapt('say "hi" <b>', "json")
    assert out == 'say \\"hi\\" \\u003cb\\u003e'


def test_cloudflare_split_keywords():
    # Spec example, verbatim.
    assert Contextualizer().adapt(ORIGINAL, "cloudflare") == \
        "<scr<script>ipt>alert(1)</scr<script>ipt>"


def test_html_attribute_event_based():
    # Spec example, verbatim.
    assert Contextualizer().adapt(ORIGINAL, "html_attribute") == \
        "<img src=x onerror=alert(1)>"


def test_html_attribute_no_double_quotes_no_semicolons():
    out = Contextualizer().adapt('var a="x";alert(1)', "html_attribute")
    assert '"' not in out
    assert ";" not in out


def test_javascript_template_literal():
    # Spec example, verbatim.
    assert Contextualizer().adapt(ORIGINAL, "javascript") == \
        "`${alert(1)}`"


def test_javascript_no_double_slashes():
    out = Contextualizer().adapt("a//b", "javascript")
    assert "//" not in out


def test_xml_escapes_angles():
    out = Contextualizer().adapt(ORIGINAL, "xml")
    assert "<" not in out and ">" not in out


def test_akamai_case_alternation():
    out = Contextualizer().adapt(ORIGINAL, "akamai")
    assert out != ORIGINAL
    # The hex-wrapped body carries the case-alternated payload.
    assert out.startswith("\\x")
    decoded = bytes.fromhex(out[2:]).decode()
    assert decoded != ORIGINAL
    assert any(c.isupper() for c in decoded)


def test_aws_waf_base64_variant():
    out = Contextualizer().adapt(ORIGINAL, "aws_waf")
    assert "base64" in out.lower()


def test_unknown_context_raises():
    with pytest.raises(KeyError):
        Contextualizer().adapt(ORIGINAL, "webrtc")


def test_deterministic():
    c = Contextualizer()
    assert c.adapt(ORIGINAL, "cloudflare") == \
        c.adapt(ORIGINAL, "cloudflare")
