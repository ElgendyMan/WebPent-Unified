"""Differential reasoning adapter for ABHIP v5.

It consumes caller-supplied, already-recorded observations only.  It never
performs transport, infers a finding, or replaces the central oracle chain.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from webpent.models.evidence import canonical_json, redact_sensitive
from webpent.shared.differential_workflow import DifferentialResult

from .contracts import (
    DifferentialComparison,
    DifferentialDimension,
    DifferentialReasoningReport,
)

_SECRET_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "cookies",
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "otp",
        "headers",
        "body",
        "raw_body",
    }
)


def _has_secret_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(
            str(key).strip().lower().replace("-", "_") in _SECRET_KEYS
            or _has_secret_key(child)
            for key, child in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_has_secret_key(child) for child in value)
    return False


def _safe(value: Mapping[str, Any]) -> dict[str, Any]:
    if _has_secret_key(value):
        raise ValueError("differential_input_contains_secret")
    clean, _ = redact_sensitive(dict(value))
    if not isinstance(clean, Mapping):
        raise ValueError("differential_input_invalid")
    return dict(clean)


def _fingerprint(value: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()


class DifferentialReasoningEngine:
    """Explain differences between two recorded contexts without confirmation authority."""

    def compare(
        self,
        *,
        engagement_id: str,
        target_id: str,
        dimension: DifferentialDimension,
        left_context: str,
        right_context: str,
        left_observation: Mapping[str, Any],
        right_observation: Mapping[str, Any],
        observation_source: str,
        reasoning: str,
        possible_security_impact: str,
        validation_requirement: str,
        negative_control_complete: bool = False,
        replayable: bool = False,
    ) -> DifferentialReasoningReport:
        """Compare safe mappings; missing controls or replayability block the result."""
        blocked: list[str] = []
        if not negative_control_complete:
            blocked.append("negative_control_required")
        if not replayable:
            blocked.append("replayability_required")
        try:
            left = _safe(left_observation)
            right = _safe(right_observation)
        except (TypeError, ValueError) as exc:
            blocked.append(type(exc).__name__.lower())
            left = {}
            right = {}
        signal = bool(left and right and _fingerprint(left) != _fingerprint(right))
        comparison = DifferentialComparison(
            comparison_id=(
                "comparison:"
                + hashlib.sha256(
                    f"{engagement_id}|{target_id}|{dimension.value}|{left_context}|{right_context}".encode()
                ).hexdigest()[:24]
            ),
            dimension=dimension,
            left_context=left_context,
            right_context=right_context,
            observed_difference=(
                "recorded fingerprints differ" if signal else "recorded fingerprints match"
            ),
            observation_source=observation_source,
            reasoning=reasoning,
            possible_security_impact=possible_security_impact,
            validation_requirement=validation_requirement,
            differential_signal=signal and not blocked,
        )
        return DifferentialReasoningReport(
            engagement_id=engagement_id,
            target_id=target_id,
            comparisons=(comparison,),
            blocked_reasons=tuple(dict.fromkeys(blocked)),
            observation_count=(2 if left and right else 0),
        )

    def from_workflow_result(
        self,
        result: DifferentialResult,
        *,
        dimension: DifferentialDimension,
        reasoning: str,
        possible_security_impact: str,
        validation_requirement: str,
    ) -> DifferentialReasoningReport:
        """Project an existing workflow result into the v5 explanation contract."""
        blocked: tuple[str, ...] = ()
        if result.status == "blocked_by_precondition":
            blocked = (result.reason,)
        comparison = DifferentialComparison(
            comparison_id=result.comparison_fingerprint,
            dimension=dimension,
            left_context=(result.baseline.variant_label if result.baseline else "baseline"),
            right_context=(result.variant.variant_label if result.variant else "variant"),
            observed_difference=(
                "recorded fingerprints differ"
                if result.differential_signal
                else "no recorded differential signal"
            ),
            observation_source="DifferentialWorkflowRunner",
            reasoning=reasoning,
            possible_security_impact=possible_security_impact,
            validation_requirement=validation_requirement,
            differential_signal=result.differential_signal and not blocked,
        )
        return DifferentialReasoningReport(
            engagement_id=result.engagement_id,
            target_id=result.target_url,
            comparisons=(comparison,),
            blocked_reasons=blocked,
            observation_count=int(result.baseline is not None) + int(result.variant is not None),
        )


__all__ = ["DifferentialReasoningEngine"]
