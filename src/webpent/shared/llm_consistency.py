# src/webpent/shared/llm_consistency.py
"""webpent.shared.llm_consistency

Ultimate plan 2026-10-27, proposal 8 — self-consistency checking for
high-stakes LLM decisions.

The framework's philosophy is "the one who proposes is not the one who
decides": deterministic validators make the verdicts, and the LLM only
proposes analysis. But some of those proposals (e.g., "does this
response indicate a real SQL injection?") feed directly into
severity/priority decisions, and a single moody LLM call can silently
skew them. This module adds a cheap, deterministic safety layer: ask
the SAME question through N semantically-equivalent prompt phrasings
and measure how much the answers agree.

**ADVISORY-ONLY CONTRACT (critical):** a :class:`ConsistencyResult` is
METADATA. It NEVER changes, blocks, gates, or overrides any validator
verdict, finding promotion, or routing decision. It is attached to
findings/evidence as an extra confidence annotation (exactly like
``novelty_score``) via :func:`annotate_finding_confidence`. Wiring this
module in must produce ZERO behavioural change other than the extra
annotation field — which is why ``enable_llm_consistency_check``
defaults to ``False`` (it multiplies LLM cost on the checked
decisions).

Comparison heuristic (honest proxy): responses are compared pairwise
after deterministic normalisation (strip whitespace, lowercase,
collapse punctuation, collapse internal whitespace). A pair "agrees"
when the normalised forms are exactly equal OR the token-set Jaccard
similarity of the two normalised forms is >= 0.8. This is a
deliberately crude lexical proxy for semantic agreement — it can miss
paraphrases that use entirely different vocabulary and it can be
fooled by two different answers that share >= 80% of their tokens.
It is NOT an embedding-based semantic similarity; it is deterministic,
cheap, offline, and testable, which is what an advisory annotation
needs. Documented as a proxy, not a guarantee.

Fail-closed: if any invocation of the injected ``invoke_fn`` raises one
of the expected invocation-failure exception types (see
``INVOKE_FAILURE_EXCEPTIONS`` — a deliberately narrow tuple; this
project forbids blanket ``except Exception``), the result is
"inconclusive" with the error recorded. "Inconclusive" is the honest
answer: no agreement claim is made when we could not collect the
responses. The function never raises and never blocks anything.

Pure stdlib. No imports from ``shared/llm.py`` — the LLM invocation is
dependency-injected by the caller (``invoke_fn``), which keeps this
module pure, offline-testable, and decoupled from provider plumbing.
"""

from __future__ import annotations

import re
import string
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ConsistencyResult",
    "INVOKE_FAILURE_EXCEPTIONS",
    "MAX_PROMPT_VARIANTS",
    "MIN_PROMPT_VARIANTS",
    "RESPONSE_SNIPPET_MAX_CHARS",
    "annotate_finding_confidence",
    "verify_llm_consistency",
]

# Bounds (documented caps — proposal 8 keeps the cost multiplier small).
MIN_PROMPT_VARIANTS = 2
"""Fewer than 2 variants yields no pairs, so no agreement claim is
possible; the function returns an honest "inconclusive" instead."""

MAX_PROMPT_VARIANTS = 5
"""More than 5 variants is truncated: the agreement estimate converges
quickly and each extra variant is a real LLM cost multiplier."""

RESPONSE_SNIPPET_MAX_CHARS = 200
"""Each stored response is truncated to 200 chars — enough to audit
what was compared, never enough to leak a full target response."""

_JACCARD_AGREEMENT_THRESHOLD = 0.8
"""Token-set Jaccard similarity above which two normalised responses
count as "agreeing" (documented lexical proxy for semantic equality)."""

_PUNCTUATION_RE = re.compile(r"[" + re.escape(string.punctuation) + r"]+")
_WHITESPACE_RE = re.compile(r"\s+")

# Narrow, explicit tuple of exception types an LLM invocation path can
# realistically raise (provider/LLM-layer failures in this codebase are
# ValueError/TypeError/RuntimeError/OSError-flavoured; the shared/llm.py
# provider router itself raises ValueError when disabled/unconfigured).
# This project's governance forbids blanket ``except Exception`` — truly
# exotic exception types are allowed to propagate so programming errors
# stay visible instead of being silently converted to "inconclusive".
INVOKE_FAILURE_EXCEPTIONS: tuple[type[BaseException], ...] = (
    ValueError,
    TypeError,
    RuntimeError,
    OSError,
    KeyError,
    IndexError,
    AttributeError,
    TimeoutError,
    ArithmeticError,
    UnicodeError,
)


@dataclass
class ConsistencyResult:
    """Outcome of a self-consistency check over prompt variants.

    Attributes:
        agreement_score: Fraction of response pairs that agree, in
            [0.0, 1.0]. Exactly 0.0 when the check is inconclusive
            (fail-closed: no data → no agreement claim).
        responses: The collected raw responses, each truncated to
            ``RESPONSE_SNIPPET_MAX_CHARS`` chars (bounded, auditable).
        variants_used: How many prompt variants were actually used
            (after the 2..5 bound is applied).
        threshold: The agreement threshold this check was evaluated
            against (``agreement_score >= threshold`` → "consistent").
        interpretation: One of ``"consistent"``, ``"inconsistent"``,
            or ``"inconclusive"`` (inconclusive = an invocation failed
            or there were too few variants to compare).
        error: ``None`` on success; otherwise a short description of
            why the check was inconclusive.
    """

    agreement_score: float = 0.0
    responses: list[str] = field(default_factory=list)
    variants_used: int = 0
    threshold: float = 0.67
    interpretation: str = "inconclusive"
    error: str | None = None


def _normalise(text: str) -> str:
    """Deterministically normalise an LLM response for comparison.

    Strips outer whitespace, lowercases, collapses every punctuation
    run to a single space, and collapses internal whitespace. Purely
    lexical — documented as a proxy, not semantic understanding.
    """
    lowered = str(text).strip().lower()
    without_punct = _PUNCTUATION_RE.sub(" ", lowered)
    return _WHITESPACE_RE.sub(" ", without_punct).strip()


def _token_set(normalised: str) -> set[str]:
    """Split a normalised response into its whitespace token set."""
    if not normalised:
        return set()
    return set(normalised.split(" "))


def _pair_agrees(left: str, right: str) -> bool:
    """Decide whether two raw responses agree (documented heuristic).

    Agreement = identical normalised forms, OR token-set Jaccard
    similarity >= ``_JACCARD_AGREEMENT_THRESHOLD`` (0.8). The Jaccard
    path catches minor phrasing/word-order differences; it will NOT
    catch full paraphrases with disjoint vocabulary — that limitation
    is the price of staying deterministic and offline, and it is
    acceptable because the score is advisory metadata only.
    """
    left_norm = _normalise(left)
    right_norm = _normalise(right)
    if left_norm == right_norm:
        return True
    left_tokens = _token_set(left_norm)
    right_tokens = _token_set(right_norm)
    if not left_tokens or not right_tokens:
        # An empty response never "agrees" with a non-empty one.
        return False
    union = left_tokens | right_tokens
    if not union:
        return False
    intersection = left_tokens & right_tokens
    similarity = len(intersection) / len(union)
    return similarity >= _JACCARD_AGREEMENT_THRESHOLD


def verify_llm_consistency(
    invoke_fn: Callable[[str], str],
    prompt_variants: list[str],
    *,
    threshold: float = 0.67,
) -> ConsistencyResult:
    """Measure self-consistency of an LLM decision across prompt variants.

    Calls ``invoke_fn(prompt)`` once per prompt variant (the caller
    injects whichever ``shared/llm.py`` entry point is appropriate —
    this module never imports the LLM stack) and scores how much the
    answers agree pairwise.

    **Advisory only: the returned score NEVER changes a validator
    verdict or any other decision.** It is meant to be attached as
    metadata via :func:`annotate_finding_confidence`. Callers MUST NOT
    use it to block, gate, or re-rank findings — that would invert the
    project's "deterministic code decides, LLM proposes" principle.

    Bounds:
      * ``prompt_variants`` is clamped to 2..5 entries: more than
        ``MAX_PROMPT_VARIANTS`` (5) is truncated; fewer than
        ``MIN_PROMPT_VARIANTS`` (2) yields an honest "inconclusive"
        (no pairs → no agreement claim) rather than a fake score.
      * Stored responses are truncated to 200 chars each.

    Fail-closed: if any invocation raises one of the types in
    ``INVOKE_FAILURE_EXCEPTIONS``, the function returns
    ``ConsistencyResult(agreement_score=0.0, interpretation=
    "inconclusive", error=...)`` and never raises. "Inconclusive" is
    the honest answer when the data could not be collected.

    Args:
        invoke_fn: Injected callable taking a prompt string and
            returning the LLM's text answer.
        prompt_variants: Semantically-equivalent phrasings of the same
            question (bounded to 2..5 as described above).
        threshold: Agreement score at or above which the responses are
            interpreted as "consistent". Defaults to 0.67; production
            callers should read ``llm_consistency_agreement_threshold``
            from settings instead of hardcoding.

    Returns:
        A :class:`ConsistencyResult` with the pairwise agreement score
        and interpretation ("consistent" / "inconsistent" /
        "inconclusive").
    """
    bounded_threshold = min(1.0, max(0.0, float(threshold)))
    all_variants = list(prompt_variants or [])
    variants = all_variants[:MAX_PROMPT_VARIANTS]
    variants_used = len(variants)

    if variants_used < MIN_PROMPT_VARIANTS:
        return ConsistencyResult(
            agreement_score=0.0,
            responses=[],
            variants_used=variants_used,
            threshold=bounded_threshold,
            interpretation="inconclusive",
            error=(
                f"at least {MIN_PROMPT_VARIANTS} prompt variants are "
                f"required to measure agreement (got {variants_used})"
            ),
        )

    collected: list[str] = []
    for variant in variants:
        try:
            collected.append(str(invoke_fn(variant)))
        except INVOKE_FAILURE_EXCEPTIONS as exc:
            # Fail-closed: never crash, never block, honest status.
            return ConsistencyResult(
                agreement_score=0.0,
                responses=[r[:RESPONSE_SNIPPET_MAX_CHARS] for r in collected],
                variants_used=variants_used,
                threshold=bounded_threshold,
                interpretation="inconclusive",
                error=f"{type(exc).__name__}: {exc}"[:RESPONSE_SNIPPET_MAX_CHARS],
            )

    agreeing_pairs = 0
    total_pairs = 0
    for i in range(len(collected)):
        for j in range(i + 1, len(collected)):
            total_pairs += 1
            if _pair_agrees(collected[i], collected[j]):
                agreeing_pairs += 1

    agreement_score = agreeing_pairs / total_pairs if total_pairs else 0.0
    interpretation = "consistent" if agreement_score >= bounded_threshold else "inconsistent"
    return ConsistencyResult(
        agreement_score=agreement_score,
        responses=[r[:RESPONSE_SNIPPET_MAX_CHARS] for r in collected],
        variants_used=variants_used,
        threshold=bounded_threshold,
        interpretation=interpretation,
        error=None,
    )


def annotate_finding_confidence(
    finding: dict[str, Any],
    consistency: ConsistencyResult,
) -> dict[str, Any]:
    """Return a NEW dict: the finding plus an advisory consistency annotation.

    Never mutates the input ``finding`` (defensive copy — findings are
    shared across pipeline stages and mutation here would be a hidden
    side channel). The added key ``"llm_consistency"`` carries the
    agreement score, the interpretation, and an explicit
    ``advisory_only: True`` marker so every downstream consumer (and
    every human reading the evidence) can see that this field is
    metadata, not a verdict.

    Args:
        finding: The finding/evidence dict to annotate.
        consistency: The result of :func:`verify_llm_consistency`.

    Returns:
        A new dict with all original keys plus ``"llm_consistency"``:
        ``{"agreement_score": float, "interpretation": str,
        "advisory_only": True}``.
    """
    annotated = dict(finding)
    annotated["llm_consistency"] = {
        "agreement_score": float(consistency.agreement_score),
        "interpretation": str(consistency.interpretation),
        "advisory_only": True,
    }
    return annotated
