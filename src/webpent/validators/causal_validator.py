"""Fail-closed causal validation primitives."""

from __future__ import annotations

from typing import Any


def validate_causal_observation(observation: Any) -> bool:
    """Require both a causal signal and a completed negative control."""
    if not isinstance(observation, dict):
        return False
    evidence_refs = observation.get("evidence_refs")
    if not isinstance(evidence_refs, (list, tuple, set)) or not any(
        str(ref).strip() for ref in evidence_refs
    ):
        return False
    return (
        observation.get("causal_signal") is True
        and observation.get("negative_control_complete") is True
    )
