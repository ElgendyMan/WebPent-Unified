"""Compatibility facade for the canonical causal validator."""

from __future__ import annotations

from typing import Any

from webpent.validators.causal_validator import validate_causal_observation


def validate(observation: Any) -> bool:
    """Delegate to the existing fail-closed causal and negative-control gate."""
    return validate_causal_observation(observation)


__all__ = ["validate", "validate_causal_observation"]
