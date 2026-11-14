"""Canonical G-02 execution-plane metadata for transport adapters."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

G02_HTTP_ADAPTER_NAME = "smart_http"
G02_HTTP_CANONICAL_WRAPPER = "webpent.shared.http.make_safe_httpx_client"
G02_HTTP_SCOPE_POLICY = "same-origin"
G02_HTTP_INVENTORY_REF = "docs/direct_io_inventory.json#native-http"
G02_HTTP_PROOF_CONTRACT = "response-causal-negative-control-proof-bundle"
G02_HTTP_APPROVAL_EXPIRY = "2026-11-19"


def g02_http_metadata(extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return canonical request metadata, preserving caller-specific fields."""
    metadata = dict(extra or {})
    metadata["adapter_name"] = G02_HTTP_ADAPTER_NAME
    metadata["g02_inventory_ref"] = G02_HTTP_INVENTORY_REF
    metadata["g02_proof_contract"] = G02_HTTP_PROOF_CONTRACT
    return metadata


__all__ = [
    "G02_HTTP_ADAPTER_NAME",
    "G02_HTTP_APPROVAL_EXPIRY",
    "G02_HTTP_CANONICAL_WRAPPER",
    "G02_HTTP_INVENTORY_REF",
    "G02_HTTP_PROOF_CONTRACT",
    "G02_HTTP_SCOPE_POLICY",
    "g02_http_metadata",
]

