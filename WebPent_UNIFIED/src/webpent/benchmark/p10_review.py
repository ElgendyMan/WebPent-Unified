"""Fail-closed validation for the external, mapping-only P10 review record.

The validator authenticates the shape and provenance of a mapping review. It does
not approve live results, calculate metrics, or confer P10/VIP qualification.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

_REQUIRED_EXCLUSIONS = frozenset(
    {
        "live_precision_recall",
        "p10_qualification",
        "vip_qualification",
        "http_200_as_finding",
        "blocked_inventory_rows_as_tp",
    }
)
_SIMULATION_REVIEWER_MARKERS = ("simulation", "synthetic", "fixture", "test-reviewer")


def _text(value: Any) -> str:
    return " ".join(str(value or "").split())


def _values(value: Any) -> frozenset[str]:
    if value is None or isinstance(value, (str, bytes)):
        return frozenset()
    try:
        return frozenset(_text(item) for item in value if _text(item))
    except TypeError:
        return frozenset()


def validate_mapping_review(
    review: Mapping[str, Any],
    *,
    expected_mapping_hash: str,
    expected_oracle_contract_hash: str,
    expected_case_ids: Sequence[str],
    expected_class_count: int,
    expected_out_of_scope_case_ids: Sequence[str],
) -> dict[str, Any]:
    """Validate mapping-only approval without treating it as P10 approval."""
    reasons: list[str] = []
    reviewer_id = _text(review.get("reviewer_id"))
    reviewer_type = _text(review.get("reviewer_type"))
    scope = _text(review.get("approval_scope"))
    exclusions = _values(review.get("explicitly_not_approving"))
    approved_cases = _values(review.get("approved_case_ids"))
    expected_cases = frozenset(_text(item) for item in expected_case_ids if _text(item))
    expected_oos = frozenset(
        _text(item) for item in expected_out_of_scope_case_ids if _text(item)
    )
    observed_oos = _values(review.get("out_of_scope_confirmed"))

    if not reviewer_id:
        reasons.append("mapping_review_reviewer_id_missing")
    if any(marker in reviewer_id.lower() for marker in _SIMULATION_REVIEWER_MARKERS):
        reasons.append("simulation_reviewer_cannot_approve_mapping")
    if reviewer_type != "external_mapping_reviewer_non_human_identifier":
        reasons.append("mapping_review_reviewer_type_invalid")
    if scope != "case_mapping_and_safety_posture_only":
        reasons.append("mapping_review_scope_invalid")
    if review.get("approved") is not True:
        reasons.append("mapping_review_not_approved")
    if review.get("full_p10_qualification_approved") is True:
        reasons.append("mapping_review_cannot_claim_full_p10_qualification")
    if _text(review.get("mapping_hash")) != expected_mapping_hash:
        reasons.append("mapping_review_hash_mismatch")
    if _text(review.get("oracle_contract_hash")) != expected_oracle_contract_hash:
        reasons.append("mapping_review_oracle_hash_mismatch")
    if review.get("approved_case_count") != len(expected_cases):
        reasons.append("mapping_review_case_count_mismatch")
    if review.get("approved_class_count") != expected_class_count:
        reasons.append("mapping_review_class_count_mismatch")
    if approved_cases != expected_cases:
        reasons.append("mapping_review_case_ids_mismatch")
    if not expected_oos.issubset(observed_oos):
        reasons.append("mapping_review_out_of_scope_confirmation_missing")
    if not _REQUIRED_EXCLUSIONS.issubset(exclusions):
        reasons.append("mapping_review_explicit_exclusions_missing")
    if review.get("results_seen_by_reviewer") is not False:
        reasons.append("mapping_review_must_not_use_results")

    return {
        "valid": not reasons,
        "mapping_approved": not reasons,
        "full_p10_qualification_approved": False,
        "blocking_reasons": sorted(set(reasons)),
    }


__all__ = ["validate_mapping_review"]
