"""Judgment Council — shared data contracts (v85, NC-JC charter).

Every JC dataclass is deterministic, advisory-only (JC-L-1) and carries its
full transparency envelope (L-4). Nothing here performs I/O or network
calls (L-2): the JC consumes injected context only.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

#: documented source reliability table (U-JC-4): kind -> factor in [0.3, 1.0]
SOURCE_RELIABILITY: dict[str, float] = {
    "signal": 1.0,
    "metric": 0.9,
    "lesson": 0.7,
    "prior": 0.5,
    "unknown": 0.3,
}

EVIDENCE_KINDS = ("signal", "metric", "lesson", "prior", "unknown")

#: the 7 documented skeptic bias flags (U-JC-3)
BIAS_FLAGS = (
    "confirmation",
    "recency",
    "anchoring",
    "availability",
    "overconfidence",
    "sampling",
    "cherry_picking",
)

MAX_CHALLENGE_SEVERITY = 0.9  # guard: the skeptic never rejects everything


def clamp01(value: Any, default: float = 0.0) -> float:
    """Coerce to a float in [0, 1]; failures fall back to ``default``."""
    try:
        num = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(num) or math.isinf(num):
        return default
    return min(1.0, max(0.0, num))


def utc(value: datetime | None) -> datetime:
    """Normalize a datetime to tz-aware UTC; None/naive -> epoch/UTC."""
    if value is None:
        return EPOCH
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _canonical_default(obj: Any) -> Any:
    """Deterministic fallback for non-JSON types (R2-jc-03).

    ``str({...})`` on a set depends on PYTHONHASHSEED and made
    context_hash — and therefore session ids — process-dependent,
    breaking the L-3 determinism contract. Sets serialize as a
    str-sorted list instead; everything else keeps the old str() fallback.
    """
    if isinstance(obj, (set, frozenset)):
        return sorted(str(item) for item in obj)
    return str(obj)


def canonical_json(obj: Any) -> str:
    """Stable serialization: the basis of every deterministic hash (L-3)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=_canonical_default, ensure_ascii=False)


def context_hash(context: dict) -> str:
    """Deterministic fingerprint of a context dict (U-JC-9)."""
    return hashlib.sha256(canonical_json(context).encode("utf-8")).hexdigest()


def deterministic_id(*parts: Any, length: int = 16) -> str:
    """Short stable id derived from the parts (no randomness, JC-L-2)."""
    digest = hashlib.sha256(
        ("\x1f".join(canonical_json(p) for p in parts)).encode("utf-8")
    ).hexdigest()
    return digest[:length]


@dataclass
class Evidence:
    """One piece of evidence offered by an advocate (L-4 envelope)."""

    kind: str
    content: str
    source: str
    observed_at: datetime
    confidence: float = 0.5
    specificity: float = 0.5

    def __post_init__(self) -> None:
        self.kind = str(self.kind or "unknown").lower()
        if self.kind not in SOURCE_RELIABILITY:
            self.kind = "unknown"
        self.content = str(self.content or "")[:300]
        self.source = str(self.source or "unknown")[:120]
        self.observed_at = utc(self.observed_at)
        self.confidence = clamp01(self.confidence, 0.5)
        self.specificity = clamp01(self.specificity, 0.5)

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "content": self.content,
            "source": self.source,
            "observed_at": self.observed_at.isoformat(),
            "confidence": round(self.confidence, 4),
            "specificity": round(self.specificity, 4),
        }


@dataclass
class Argument:
    """One advocate's case: claim, evidence, reasoning, confidence."""

    advocate_id: str
    claim: str
    evidence: list[Evidence]
    reasoning: str
    confidence: float
    alternatives: list[str]
    timestamp: datetime

    def __post_init__(self) -> None:
        self.advocate_id = str(self.advocate_id or "unknown")[:60]
        self.claim = str(self.claim or "")[:300]
        self.evidence = list(self.evidence or [])
        self.reasoning = str(self.reasoning or "")[:600]
        self.confidence = clamp01(self.confidence, 0.0)
        self.alternatives = [str(a)[:200] for a in (self.alternatives or [])]
        self.timestamp = utc(self.timestamp)

    def as_dict(self) -> dict[str, Any]:
        return {
            "advocate_id": self.advocate_id,
            "claim": self.claim,
            "evidence": [e.as_dict() for e in self.evidence],
            "reasoning": self.reasoning,
            "confidence": round(self.confidence, 4),
            "alternatives": self.alternatives,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Challenge:
    """The skeptic's adversarial response to one argument (U-JC-3)."""

    target_advocate_id: str
    counter_claim: str
    counter_evidence: list[Evidence]
    bias_flags: list[str]
    alternative_hypothesis: str
    challenge_severity: float
    timestamp: datetime

    def __post_init__(self) -> None:
        self.target_advocate_id = str(self.target_advocate_id or "")[:60]
        self.counter_claim = str(self.counter_claim or "")[:300]
        self.counter_evidence = list(self.counter_evidence or [])
        self.bias_flags = [str(f)[:40] for f in (self.bias_flags or [])]
        self.alternative_hypothesis = str(self.alternative_hypothesis or "")[:300]
        self.challenge_severity = min(
            MAX_CHALLENGE_SEVERITY, clamp01(self.challenge_severity, 0.0)
        )
        self.timestamp = utc(self.timestamp)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_advocate_id": self.target_advocate_id,
            "counter_claim": self.counter_claim,
            "counter_evidence": [e.as_dict() for e in self.counter_evidence],
            "bias_flags": self.bias_flags,
            "alternative_hypothesis": self.alternative_hypothesis,
            "challenge_severity": round(self.challenge_severity, 4),
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class WeightedEvidence:
    """Evidence with its transparent weight breakdown (U-JC-4, L-4)."""

    evidence: Evidence
    weight: float
    components: dict[str, float]
    rationale: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "evidence": self.evidence.as_dict(),
            "weight": round(self.weight, 4),
            "components": {k: round(v, 4) for k, v in self.components.items()},
            "rationale": self.rationale,
        }


@dataclass
class DissentingView:
    """A minority voice preserved by the register (U-JC-6, JC-L-5)."""

    advocate_id: str
    claim: str
    reasoning: str
    confidence: float
    outcome: str | None = None

    def __post_init__(self) -> None:
        self.advocate_id = str(self.advocate_id or "")[:60]
        self.claim = str(self.claim or "")[:300]
        self.reasoning = str(self.reasoning or "")[:600]
        self.confidence = clamp01(self.confidence, 0.0)
        self.outcome = None if self.outcome is None else str(self.outcome)[:20]

    def as_dict(self) -> dict[str, Any]:
        return {
            "advocate_id": self.advocate_id,
            "claim": self.claim,
            "reasoning": self.reasoning,
            "confidence": round(self.confidence, 4),
            "outcome": self.outcome,
        }


@dataclass
class Verdict:
    """The judge's ruling on one session (U-JC-5)."""

    action: str
    reasoning: str
    confidence: float
    confidence_tier: str
    dissent: list[DissentingView]
    escalate: bool
    escalation_reason: str | None
    advocates_summary: dict[str, Any]
    session_id: str
    timestamp: datetime

    def __post_init__(self) -> None:
        self.action = str(self.action or "none")[:300]
        self.reasoning = str(self.reasoning or "")[:4000]
        self.confidence = clamp01(self.confidence, 0.0)
        self.confidence_tier = str(self.confidence_tier or "low")
        self.dissent = list(self.dissent or [])
        self.escalate = bool(self.escalate)
        self.escalation_reason = (
            None if self.escalation_reason is None
            else str(self.escalation_reason)[:300]
        )
        if self.escalate and not self.escalation_reason:
            self.escalation_reason = "escalated (reason unspecified)"
        self.advocates_summary = dict(self.advocates_summary or {})
        self.session_id = str(self.session_id or "")[:64]
        self.timestamp = utc(self.timestamp)

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reasoning": self.reasoning,
            "confidence": round(self.confidence, 4),
            "confidence_tier": self.confidence_tier,
            "dissent": [d.as_dict() for d in self.dissent],
            "escalate": self.escalate,
            "escalation_reason": self.escalation_reason,
            "advocates_summary": self.advocates_summary,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat(),
            "advisory": True,
        }


@dataclass
class CouncilSession:
    """One convened debate: question, context, arguments, challenges."""

    session_id: str
    question: str
    context: dict[str, Any]
    arguments: list[Argument] = field(default_factory=list)
    challenges: list[Challenge] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    deadline: datetime | None = None
    closed: bool = False
    verdict: Verdict | None = None

    def __post_init__(self) -> None:
        self.session_id = str(self.session_id or "")[:64]
        self.question = str(self.question or "")[:300]
        self.context = dict(self.context or {})
        self.arguments = list(self.arguments or [])
        self.challenges = list(self.challenges or [])
        self.started_at = utc(self.started_at)
        self.deadline = None if self.deadline is None else utc(self.deadline)
        self.closed = bool(self.closed)

    def as_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "question": self.question,
            "context_hash": context_hash(self.context),
            "arguments": [a.as_dict() for a in self.arguments],
            "challenges": [c.as_dict() for c in self.challenges],
            "started_at": self.started_at.isoformat(),
            "deadline": None if self.deadline is None else self.deadline.isoformat(),
            "closed": self.closed,
            "verdict": None if self.verdict is None else self.verdict.as_dict(),
            "advisory": True,
        }


__all__ = [
    "BIAS_FLAGS",
    "Argument",
    "Challenge",
    "CouncilSession",
    "DissentingView",
    "EPOCH",
    "Evidence",
    "MAX_CHALLENGE_SEVERITY",
    "SOURCE_RELIABILITY",
    "Verdict",
    "WeightedEvidence",
    "canonical_json",
    "clamp01",
    "context_hash",
    "deterministic_id",
    "utc",
]
