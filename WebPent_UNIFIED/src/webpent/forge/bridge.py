"""Bridge — the FORGE corpus into advisory probe strategies.

Pure functions: a ranked list of ScoredPayload hits becomes a plain
text probe strategy. Every payload line carries its source and license
(FORGE-L-7 ATTRIBUTION_IS_SACRED — nothing leaves the corpus
anonymously), lines are ordered by the published score, and the whole
output is marked advisory-only (FORGE-L-4 ADVISORY_ONLY). Zero
network, zero mutation, deterministic.
"""
from __future__ import annotations

from webpent.forge.schemas import Family, ScoredPayload, TargetContext


def ranked_for(engine, family: Family, target_context: TargetContext,
               limit: int) -> list[ScoredPayload]:
    """Ranked corpus hits for one family against one target context."""
    return engine.find(family, target_context, limit=limit)


def _payload_line(index: int, scored: ScoredPayload) -> str:
    payload = scored.payload
    attribution = payload.attribution
    if attribution is None:
        raise ValueError(
            f"payload {payload.payload_id} has no attribution "
            "(FORGE-L-7 ATTRIBUTION_IS_SACRED)")
    return (
        f"{index}. [{payload.family.value}/{payload.subfamily}] "
        f"{payload.raw!r} "
        f"(source: {attribution.original_source}, "
        f"license: {attribution.license}, "
        f"score: {scored.score:.4f})")


def probe_strategy(ranked: list[ScoredPayload]) -> str:
    """Render ranked hits as an advisory-only probe strategy text."""
    if not ranked:
        return ""
    lines = [
        "Advisory-only probe strategy (FORGE corpus; no "
        "auto-exploitation — each candidate is replayed by the "
        "operator against an authorized target):",
    ]
    for index, scored in enumerate(ranked, start=1):
        lines.append(_payload_line(index, scored))
    return "\n".join(lines)
