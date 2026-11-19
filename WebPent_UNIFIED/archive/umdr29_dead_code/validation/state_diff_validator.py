"""Pure state-difference validation for candidate evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class StateDiffAssessment(BaseModel):
    """A bounded assessment that is deliberately not promotion-eligible."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    valid: bool = False
    differential_signal: bool = False
    status: str = "inconclusive"
    reason: str = Field(default="", max_length=240)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    promotion_eligible: bool = False


def _refs(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        values = (value,)
    elif isinstance(value, (list, tuple, set)):
        values = tuple(value)
    else:
        values = ()
    return tuple(
        dict.fromkeys(str(item).strip()[:240] for item in values if str(item).strip())
    )[:32]


def validate_state_diff(
    baseline: Mapping[str, Any] | None,
    variant: Mapping[str, Any] | None,
) -> StateDiffAssessment:
    """Assess a supplied state diff without treating it as causal confirmation."""
    if not isinstance(baseline, Mapping) or not isinstance(variant, Mapping):
        return StateDiffAssessment(reason="state_observations_required")
    for key in ("engagement_id", "target_id"):
        left = baseline.get(key)
        right = variant.get(key)
        if left is not None and right is not None and str(left) != str(right):
            return StateDiffAssessment(reason=f"{key}_mismatch")
    left = str(baseline.get("state_fingerprint") or baseline.get("state") or "").strip()
    right = str(variant.get("state_fingerprint") or variant.get("state") or "").strip()
    refs = _refs(baseline.get("evidence_refs")) + _refs(variant.get("evidence_refs"))
    refs = tuple(dict.fromkeys(refs))[:32]
    if not left or not right:
        return StateDiffAssessment(evidence_refs=refs, reason="state_fingerprints_required")
    if left == right:
        return StateDiffAssessment(
            differential_signal=False,
            status="no_state_difference",
            evidence_refs=refs,
            reason="state_fingerprints_match",
        )
    if not refs:
        return StateDiffAssessment(
            differential_signal=True,
            status="candidate_evidence_missing_refs",
            reason="state_difference_requires_evidence_refs",
        )
    return StateDiffAssessment(
        valid=True,
        differential_signal=True,
        status="candidate_state_difference",
        evidence_refs=refs,
        reason="state_fingerprints_differ",
    )


__all__ = ["StateDiffAssessment", "validate_state_diff"]
