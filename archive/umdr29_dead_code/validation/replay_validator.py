"""Compatibility facade for the canonical replay validator."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from webpent.models.proof_bundle import ProofBundle
from webpent.validators.replay_validator import validate_replay as _validate_replay


def validate(
    value: ProofBundle | dict[str, Any],
    evidence_payloads: list[Any] | tuple[Any, ...],
    negative_control: Any = None,
    *,
    replay_context: Mapping[str, Any] | None = None,
) -> bool:
    """Delegate replay to the existing ProofBundle implementation."""
    return _validate_replay(
        value,
        evidence_payloads,
        negative_control,
        replay_context=replay_context,
    )


__all__ = ["validate", "_validate_replay"]
