"""Fail-closed identity differential validator for candidate evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IdentityValidationResult(BaseModel):
    """Identity differential result; central proof gates remain mandatory."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    differential_signal: bool = False
    status: str = "inconclusive"
    reason: str = Field(default="", max_length=240)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    required_validation: tuple[str, ...] = (
        "target_backed_causal_signal",
        "independent_negative_control",
        "central_sealed_replayable_proof_bundle",
    )
    promotion_eligible: bool = False


def _status(value: Any) -> int | None:
    try:
        status = int(value)
    except (TypeError, ValueError):
        return None
    return status if 100 <= status <= 599 else None


def _refs(*values: Any) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        if isinstance(value, str):
            values_iter = (value,)
        elif isinstance(value, (list, tuple, set)):
            values_iter = value
        else:
            values_iter = ()
        result.extend(str(item).strip()[:240] for item in values_iter if str(item).strip())
    return tuple(dict.fromkeys(result))[:32]


def validate_identity_differential(
    baseline: Mapping[str, Any] | None,
    variant: Mapping[str, Any] | None,
) -> IdentityValidationResult:
    """Return a candidate signal only for a scoped, identity-separated differential."""
    if not isinstance(baseline, Mapping) or not isinstance(variant, Mapping):
        return IdentityValidationResult(reason="identity_observations_required")
    for key in ("engagement_id", "target_id"):
        left = baseline.get(key)
        right = variant.get(key)
        if left is not None and right is not None and str(left) != str(right):
            return IdentityValidationResult(reason=f"{key}_mismatch")
    left_identity = str(baseline.get("identity_id") or baseline.get("identity_ref") or "")
    right_identity = str(variant.get("identity_id") or variant.get("identity_ref") or "")
    refs = _refs(baseline.get("evidence_refs"), variant.get("evidence_refs"))
    if not left_identity or not right_identity or left_identity == right_identity:
        return IdentityValidationResult(
            evidence_refs=refs,
            reason="two_distinct_identity_contexts_required",
        )
    baseline_status = _status(baseline.get("status_code", baseline.get("status")))
    variant_status = _status(variant.get("status_code", variant.get("status")))
    if baseline_status == 403 and variant_status is not None and 200 <= variant_status < 300:
        return IdentityValidationResult(
            differential_signal=True,
            status="candidate_validation_required",
            reason="expected_denial_differs_from_variant_success",
            evidence_refs=refs,
        )
    if baseline_status is None or variant_status is None:
        return IdentityValidationResult(
            evidence_refs=refs,
            reason="comparable_status_codes_required",
        )
    return IdentityValidationResult(
        status="no_confirmed_identity_violation",
        evidence_refs=refs,
        reason="identity_differential_not_sufficient",
    )


__all__ = ["IdentityValidationResult", "validate_identity_differential"]
