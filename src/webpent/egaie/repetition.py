"""EGAIE repetition detection.

Tracks per-signature outcomes so the selector can penalize repeated
uninformative probes and trigger a strategy switch once a signature is
exhausted. Non-decidable outcomes ("inconclusive", "blocked") count as
uninformative: a confirmed or clean verdict is information, a
blocked/inconclusive probe taught us nothing about that signature.
"""
from __future__ import annotations

import collections

UNINFORMATIVE_OUTCOMES = ("inconclusive", "blocked")
EXHAUSTION_THRESHOLD = 2


class RepetitionRegister:
    """Deterministic outcome ledger keyed by experiment signature."""

    def __init__(self) -> None:
        self._outcomes: dict[str, list[str]] = (
            collections.defaultdict(list))

    def record(self, signature: str, outcome: str) -> None:
        self._outcomes[signature].append(outcome)

    def uninformative_count(self, signature: str) -> int:
        return sum(
            1 for outcome in self._outcomes.get(signature, ())
            if outcome in UNINFORMATIVE_OUTCOMES
        )

    def is_exhausted(self, signature: str) -> bool:
        return self.uninformative_count(signature) >= EXHAUSTION_THRESHOLD
