"""Evidence-only novel behavior detection.

The detector compares bounded response signatures supplied by an authorized
caller. It never performs transport, interprets raw bodies, or creates a
finding. A causal signal is emitted only when both a control and a negative
control are explicitly complete.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import Any

from webpent.models.research import NovelBehaviorObservation

_ALLOWED_DIMENSIONS = {
    "status_code",
    "content_type",
    "body_length",
    "body_hash",
    "header_names",
    "location_present",
    "redirect_count",
    "workflow_state",
    "identity_context",
    "tenant_context",
}


def _safe_value(key: str, value: Any) -> Any:
    if key == "header_names":
        if not isinstance(value, (list, tuple, set)):
            return ()
        return tuple(sorted(str(item).strip().lower()[:80] for item in value if str(item).strip()))
    if key in {"status_code", "body_length", "redirect_count"}:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    if key == "location_present":
        return bool(value)
    if value is None:
        return None
    return str(value).strip()[:240]


def normalize_signature(signature: Mapping[str, Any] | None) -> dict[str, Any]:
    """Keep only bounded, non-raw dimensions from a response signature."""
    if not isinstance(signature, Mapping):
        return {}
    return {
        key: _safe_value(key, signature.get(key))
        for key in sorted(_ALLOWED_DIMENSIONS)
        if key in signature
    }


class NovelBehaviorDetector:
    """Compare two safe signatures and return a hypothesis seed, if any."""

    def detect(
        self,
        baseline: Mapping[str, Any] | None,
        current: Mapping[str, Any] | None,
        *,
        baseline_ref: str = "baseline",
        current_ref: str = "current",
        control_complete: bool = False,
        negative_control_complete: bool = False,
        evidence_refs: Iterable[str] = (),
    ) -> NovelBehaviorObservation | None:
        before = normalize_signature(baseline)
        after = normalize_signature(current)
        changed = [
            key
            for key in sorted(set(before) | set(after))
            if before.get(key) != after.get(key)
        ]
        if not changed:
            return None
        if negative_control_complete and "status_code" in changed:
            behavior_kind = "authorization_differential"
        elif "workflow_state" in changed:
            behavior_kind = "workflow_transition"
        elif "status_code" in changed:
            behavior_kind = "status_change"
        elif "body_hash" in changed or "body_length" in changed:
            behavior_kind = "response_shape_change"
        else:
            behavior_kind = "unknown"
        strength = min(1.0, len(changed) / max(1, len(set(before) | set(after))))
        fingerprint = hashlib.sha256(
            f"{baseline_ref}|{current_ref}|{'|'.join(changed)}".encode()
        ).hexdigest()[:24]
        causal_signal = bool(control_complete and negative_control_complete)
        return NovelBehaviorObservation(
            observation_id=f"novel:{fingerprint}",
            baseline_ref=str(baseline_ref)[:160],
            current_ref=str(current_ref)[:160],
            behavior_kind=behavior_kind,
            changed_dimensions=changed,
            signal_strength=round(strength, 6),
            causal_signal=causal_signal,
            negative_control_complete=bool(negative_control_complete),
            hypothesis_seed=(
                "Investigate differential behavior; require reproducible control, "
                "negative control, and proof validation before promotion."
            ),
            evidence_refs=[str(ref)[:160] for ref in evidence_refs if str(ref).strip()][:30],
        )


__all__ = ["NovelBehaviorDetector", "normalize_signature"]
