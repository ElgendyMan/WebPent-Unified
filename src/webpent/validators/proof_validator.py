"""Structural validation for proof bundles."""

from __future__ import annotations

from typing import Any

from webpent.models.proof_bundle import ProofBundle, validate_proof_bundle


def validate_bundle_structure(
    value: ProofBundle | dict[str, Any], *, require_negative_control: bool = True
) -> bool:
    """Return True only for a sealed, referenced, structurally valid bundle."""
    return validate_proof_bundle(value, require_negative_control=require_negative_control)
