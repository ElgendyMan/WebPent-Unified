"""Deterministic hypothesis lifecycle transitions.

This module is a state-management boundary only. It never executes a tool,
promotes a Finding, or treats an LLM assertion as proof. Validation outcomes
must carry explicit causal and negative-control signals before a hypothesis can
be resolved.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from webpent.models.hypothesis import Hypothesis, HypothesisStatus


@dataclass(frozen=True)
class TransitionResult:
    """Auditable result of a requested hypothesis transition."""

    hypothesis: Hypothesis
    previous_status: str
    new_status: str
    accepted: bool
    reason: str
    evidence_added: tuple[str, ...] = ()


class HypothesisEngine:
    """Apply an explicit, bounded lifecycle to one structured hypothesis."""

    _ALLOWED: dict[str, frozenset[str]] = {
        HypothesisStatus.UNEXPLORED.value: frozenset(
            {HypothesisStatus.INVESTIGATING.value, HypothesisStatus.ABANDONED.value}
        ),
        HypothesisStatus.INVESTIGATING.value: frozenset(
            {
                HypothesisStatus.PROMOTED.value,
                HypothesisStatus.ABANDONED.value,
                HypothesisStatus.RESOLVED_TRUE.value,
                HypothesisStatus.RESOLVED_FALSE.value,
            }
        ),
        HypothesisStatus.PROMOTED.value: frozenset(
            {
                HypothesisStatus.RESOLVED_TRUE.value,
                HypothesisStatus.RESOLVED_FALSE.value,
            }
        ),
        HypothesisStatus.RESOLVED_TRUE.value: frozenset({HypothesisStatus.LEARNED.value}),
        HypothesisStatus.RESOLVED_FALSE.value: frozenset({HypothesisStatus.LEARNED.value}),
        HypothesisStatus.ABANDONED.value: frozenset(),
        HypothesisStatus.LEARNED.value: frozenset(),
    }

    @staticmethod
    def coerce(value: Hypothesis | dict[str, Any]) -> Hypothesis:
        """Load a model or checkpoint-restored dict, failing closed on bad data."""
        if isinstance(value, Hypothesis):
            return value
        if isinstance(value, dict):
            return Hypothesis.model_validate(value)
        raise TypeError("hypothesis must be a Hypothesis or a checkpoint-restored dict")

    @staticmethod
    def _status_value(value: HypothesisStatus | str) -> str:
        return value.value if isinstance(value, HypothesisStatus) else str(value)

    @classmethod
    def transition(
        cls,
        hypothesis: Hypothesis | dict[str, Any],
        target_status: HypothesisStatus | str,
        *,
        reason: str,
        evidence_refs: list[str] | tuple[str, ...] = (),
    ) -> TransitionResult:
        """Request a lifecycle transition without performing any side effect."""
        current = cls.coerce(hypothesis)
        previous = cls._status_value(current.status)
        target = (
            target_status.value
            if isinstance(target_status, HypothesisStatus)
            else str(target_status)
        ).lower()
        refs = tuple(dict.fromkeys(str(ref)[:240] for ref in evidence_refs if str(ref).strip()))
        if target == previous:
            return TransitionResult(current, previous, target, True, "idempotent transition", refs)
        if target not in cls._ALLOWED.get(previous, frozenset()):
            return TransitionResult(
                current,
                previous,
                previous,
                False,
                f"transition {previous} -> {target} is not allowed",
                (),
            )
        if target in {
            HypothesisStatus.RESOLVED_TRUE.value,
            HypothesisStatus.RESOLVED_FALSE.value,
        } and not (refs or current.evidence_refs):
            return TransitionResult(
                current,
                previous,
                previous,
                False,
                "resolution requires at least one evidence reference",
                (),
            )
        merged_refs = list(dict.fromkeys([*current.evidence_refs, *refs]))
        updated = current.model_copy(
            update={
                "status": target,
                "evidence_refs": merged_refs,
                "updated_at": datetime.now(timezone.utc),
            }
        )
        return TransitionResult(updated, previous, target, True, reason[:240], refs)

    @classmethod
    def record_experiment(
        cls,
        hypothesis: Hypothesis | dict[str, Any],
        observation: dict[str, Any],
    ) -> TransitionResult:
        """Map an explicit experiment observation to a safe lifecycle transition.

        ``validated`` and ``rejected`` outcomes require a strict boolean
        negative-control signal. A causal signal is additionally required for
        ``validated``. Any malformed or inconclusive observation remains open.
        """
        current = cls.coerce(hypothesis)
        if not isinstance(observation, dict):
            return TransitionResult(
                current,
                str(current.status),
                str(current.status),
                False,
                "experiment observation must be a mapping",
            )
        outcome = str(observation.get("outcome") or "inconclusive").strip().lower()
        refs_value = observation.get("evidence_refs") or ()
        refs = (
            tuple(str(ref)[:240] for ref in refs_value if str(ref).strip())
            if isinstance(refs_value, (list, tuple, set))
            else ()
        )
        causal_signal = observation.get("causal_signal") is True
        negative_control = observation.get("negative_control_complete") is True
        if outcome == "validated":
            if not causal_signal or not negative_control:
                return TransitionResult(
                    current,
                    cls._status_value(current.status),
                    cls._status_value(current.status),
                    False,
                    "validated outcome requires causal_signal and negative_control_complete",
                    (),
                )
            return cls.transition(
                current,
                HypothesisStatus.RESOLVED_TRUE,
                reason="experiment validated with causal and negative-control evidence",
                evidence_refs=refs,
            )
        if outcome == "rejected":
            if not negative_control:
                return TransitionResult(
                    current,
                    cls._status_value(current.status),
                    cls._status_value(current.status),
                    False,
                    "rejected outcome requires negative_control_complete",
                    (),
                )
            return cls.transition(
                current,
                HypothesisStatus.RESOLVED_FALSE,
                reason="experiment rejected with a completed negative control",
                evidence_refs=refs,
            )
        if outcome == "learned":
            return cls.transition(
                current,
                HypothesisStatus.LEARNED,
                reason="experiment outcome recorded as reusable learning",
                evidence_refs=refs,
            )
        if (
            outcome in {"inconclusive", "unknown"}
            and cls._status_value(current.status) == HypothesisStatus.UNEXPLORED.value
        ):
            return cls.transition(
                current,
                HypothesisStatus.INVESTIGATING,
                reason="experiment was inconclusive; investigation remains open",
                evidence_refs=refs,
            )
        return TransitionResult(
            current,
            str(current.status),
            str(current.status),
            False,
            "experiment outcome did not meet a lifecycle transition contract",
            (),
        )
