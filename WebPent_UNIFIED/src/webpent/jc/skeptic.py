"""Judgment Council — U-JC-3: the Skeptic.

A permanent devil's advocate against every argument. For each argument the
skeptic builds a challenge with (a) counter-evidence, (b) detected bias
flags from the documented set of 7, and (c) a mandatory alternative
hypothesis — never a bare rejection. Severity is deterministic and capped
at 0.9 (guard: an advocate that survives the challenge still passes).

Documented flag set (``SKEPTIC_FLAGS``): the 7 ``BIAS_FLAGS`` plus
``general_doubt`` — the healthy-doubt flag emitted when no specific bias
fires, so ``bias_flags`` is never empty.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from webpent.jc.contracts import (
    BIAS_FLAGS,
    MAX_CHALLENGE_SEVERITY,
    Argument,
    Challenge,
    Evidence,
    utc,
)

#: severity added per triggered bias flag
FLAG_SEVERITY = 0.15
#: baseline severity when no specific bias fires (healthy doubt)
BASE_SEVERITY = 0.10
#: an argument resting on no evidence at all
EMPTY_SEVERITY = 0.25
#: evidence older than this many days trips the recency flag
RECENCY_DAYS = 30

#: documented flag -> (counter-claim template, alternative hypothesis)
_FLAG_TEXT: dict[str, tuple[str, str]] = {
    "confirmation": (
        "all cited evidence is of one kind; the case may be built to confirm a prior opinion",
        "the signal is an artifact of the single evidence kind used, not an independent fact",
    ),
    "recency": (
        # text mentions RECENCY_DAYS; keep the two in step
        "the newest cited evidence is older than 30 days; the case rests on stale data",
        "the situation changed after the evidence was observed, so the claim no longer holds",
    ),
    "anchoring": (
        ("the confidence sits at a hard extreme, which is the signature "
         "of an anchor, not a measurement"),
        "the confidence was set by the first impression and never recalculated from evidence",
    ),
    "availability": (
        "the argument cites no evidence at all; it is available-story reasoning",
        "the claim is plausible only because it comes to mind easily, not because it was verified",
    ),
    "overconfidence": (
        "confidence is high while the evidence base is thin",
        "the true confidence given this evidence base is materially lower than claimed",
    ),
    "sampling": (
        "the evidence comes from a different target than the one under discussion",
        "the pattern held on another target and may not transfer to this one",
    ),
    "cherry_picking": (
        "the argument cites fewer evidence items than the context pool offers",
        "uncited evidence in the same pool contradicts or dilutes the claim",
    ),
}

#: healthy doubt when no specific bias fires
_GENERAL_TEXT = (
    "no specific bias detected, but every claim must survive independent reproduction",
    "an independent check could fail to reproduce the claim, so treat it as provisional",
)


class Skeptic:
    """Deterministic adversarial challenger (JC-L-2, JC-L-4, JC-L-5)."""

    def __init__(self, skeptic_id: str = "skeptic", *, now: Any = None) -> None:
        self.id = str(skeptic_id)[:60]
        self._now = utc(now)

    # ------------------------------------------------------------- detect
    def _detect_flags(self, arg: Argument, context: dict) -> list[str]:
        flags: list[str] = []
        # R2-jc-07: normalize once — a non-dict context degrades to the
        # defaults instead of AttributeError on context.get below.
        ctx = context if isinstance(context, dict) else {}
        now = utc(ctx.get("now")) if ctx else self._now
        evidence = arg.evidence
        if not evidence:
            flags.append("availability")
        else:
            if len({e.kind for e in evidence}) == 1 and len(evidence) >= 2:
                flags.append("confirmation")
            newest = max(e.observed_at for e in evidence)
            if now - newest > timedelta(days=RECENCY_DAYS):
                flags.append("recency")
            if arg.confidence in (0.0, 1.0):
                flags.append("anchoring")
            if arg.confidence > 0.7 and len(evidence) < 2:
                flags.append("overconfidence")
            target_id = str(ctx.get("target_id") or "")
            if target_id and any(e.source != target_id for e in evidence):
                flags.append("sampling")
            pool = ctx.get("evidence_pool")
            if isinstance(pool, list) and len(pool) > len(evidence):
                flags.append("cherry_picking")
        if not flags:
            flags = ["general_doubt"]
        return flags

    def _counter_evidence(self, arg: Argument) -> list[Evidence]:
        """Turn the argument's own evidence into its counter-evidence."""
        counters: list[Evidence] = []
        for e in arg.evidence:
            counters.append(
                Evidence(
                    kind="prior",
                    content=f"unverified: {e.content}",
                    source=e.source,
                    observed_at=e.observed_at,
                    confidence=1.0 - e.confidence,
                    specificity=max(0.1, e.specificity - 0.3),
                )
            )
        if not counters:
            counters = [
                Evidence(
                    kind="prior",
                    content="no evidence was cited; absence of evidence is the counter",
                    source="skeptic",
                    observed_at=self._now,
                    confidence=0.5,
                    specificity=0.4,
                )
            ]
        return counters

    # ---------------------------------------------------------- challenge
    def challenge(self, arg: Argument, context: dict) -> Challenge:
        """Challenge one argument; never returns an empty challenge."""
        flags = self._detect_flags(arg, context)
        texts = [_FLAG_TEXT.get(f, _GENERAL_TEXT) for f in flags]
        counter_claim = "; ".join(t[0] for t in texts)[:290]
        alternative = "; ".join(t[1] for t in texts)[:290]
        if flags == ["general_doubt"]:
            severity = BASE_SEVERITY
        elif flags == ["availability"]:
            severity = EMPTY_SEVERITY
        else:
            severity = round(min(MAX_CHALLENGE_SEVERITY, FLAG_SEVERITY * len(flags)), 6)
        return Challenge(
            target_advocate_id=arg.advocate_id,
            counter_claim=counter_claim,
            counter_evidence=self._counter_evidence(arg),
            bias_flags=flags,
            alternative_hypothesis=alternative,
            challenge_severity=severity,
            timestamp=utc(context.get("now")) if isinstance(context, dict) else self._now,
        )

    def challenge_all(self, args: list[Argument], context: dict) -> list[Challenge]:
        """Challenge every argument, in the order given (deterministic)."""
        return [self.challenge(a, context) for a in args]


#: the full documented flag set the skeptic may emit (RT-06): the 7
#: BIAS_FLAGS plus general_doubt (healthy doubt when nothing specific fires)
SKEPTIC_FLAGS = BIAS_FLAGS + ("general_doubt",)


__all__ = [
    "BIAS_FLAGS",
    "RECENCY_DAYS",
    "SKEPTIC_FLAGS",
    "Skeptic",
]
