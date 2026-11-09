"""U-FORGE-8 — The Encoding Engine.

Generate encoded variants of a payload with the spec's documented
encoding table. Variants are candidates for testing, never proven
results (FORGE-L-1 INGEST_DONT_INVENT). Pure functions; zero network.
"""
from __future__ import annotations

import base64
import binascii
import html
import urllib.parse
from dataclasses import dataclass


def _case_alternate(text: str) -> str:
    return "".join(
        c.upper() if i % 2 else c.lower()
        for i, c in enumerate(text))


def _hex_encode(text: str) -> str:
    return binascii.hexlify(text.encode("utf-8")).decode("ascii")


def _url_unicode(text: str) -> str:
    return "".join(
        f"%u{ord(c):04x}" if ord(c) > 127 else urllib.parse.quote(c, safe="")
        for c in text)


ENCODINGS: dict[str, object] = {
    "url": lambda x: urllib.parse.quote(x, safe=""),
    "url_double": lambda x: urllib.parse.quote(
        urllib.parse.quote(x, safe=""), safe=""),
    "url_unicode": _url_unicode,
    "html_entities": lambda x: html.escape(x),
    "html_numeric": lambda x: "".join(f"&#{ord(c)};" for c in x),
    "html_hex": lambda x: "".join(f"&#x{ord(c):x};" for c in x),
    "hex": _hex_encode,
    "base64": lambda x: base64.b64encode(x.encode()).decode(),
    "base64_url": lambda x: base64.urlsafe_b64encode(x.encode()).decode(),
    "unicode_escape": lambda x: x.encode("unicode_escape").decode(),
    "upper": lambda x: x.upper(),
    "lower": lambda x: x.lower(),
    "case_alternate": _case_alternate,
    "no_whitespace": lambda x: x.replace(" ", ""),
    "comment_split": lambda x: x.replace(" ", "/**/"),
    "tab_split": lambda x: x.replace(" ", "\t"),
    "newline_split": lambda x: x.replace(" ", "\n"),
}


@dataclass(frozen=True)
class EncodedVariant:
    """One encoded candidate; ``needs_testing`` until proven on a target."""
    name: str
    encoded: str
    needs_testing: bool = True


def encode(payload: str, name: str) -> str:
    return ENCODINGS[name](payload)  # unknown name -> KeyError


def generate_variants(payload: str) -> list[EncodedVariant]:
    """Single encodings only for anything whose output differs.

    Combinations are combinatorial explosion; the corpus generates
    single documented encodings and lets the evolution engine propose
    candidates from real failures (U-FORGE-14).
    """
    variants: list[EncodedVariant] = []
    for name, fn in ENCODINGS.items():
        try:
            encoded = fn(payload)
        except (TypeError, UnicodeError):
            # Only the documented contract violations are skipped
            # (non-str input, lone-surrogate payloads an encoder
            # cannot represent). Anything else is an encoder bug and
            # fails loud (corrected 2026-10-20: this was a bare
            # `except Exception`, which silently swallowed them).
            continue
        if encoded != payload:
            variants.append(EncodedVariant(name=name, encoded=encoded))
    return variants
