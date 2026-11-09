"""Append-only, engagement-scoped ProofBundle store.

The store is deliberately transport-free: persistence can be supplied by a
runtime-owned implementation later, while this deterministic implementation
provides the mandatory local contract without silently promoting or replacing
proof artifacts.
"""

from __future__ import annotations

from collections.abc import Mapping
from threading import RLock
from typing import Any

from webpent.models.proof_bundle import ProofBundle, validate_proof_bundle


class ProofBundleStoreError(ValueError):
    """Raised when a proof bundle cannot be safely stored."""


class ProofBundleStore:
    """Bounded append-only store for sealed, redaction-safe proof bundles.

    ``put`` is idempotent for the same bundle ID and seal digest. A different
    sealed payload using an existing bundle ID is rejected rather than
    overwritten. Reads are engagement-scoped by default to prevent accidental
    cross-campaign disclosure.
    """

    def __init__(self, *, max_bundles: int = 2048) -> None:
        if int(max_bundles) < 1:
            raise ValueError("max_bundles_must_be_positive")
        self._max_bundles = int(max_bundles)
        self._bundles: dict[str, ProofBundle] = {}
        self._lock = RLock()

    @staticmethod
    def _coerce(value: ProofBundle | Mapping[str, Any]) -> ProofBundle:
        if isinstance(value, ProofBundle):
            return value
        if isinstance(value, Mapping):
            return ProofBundle.model_validate(value)
        raise ProofBundleStoreError("proof_bundle_type_invalid")

    def put(self, value: ProofBundle | Mapping[str, Any]) -> str:
        """Store one sealed, structurally valid bundle and return its ID."""
        bundle = self._coerce(value)
        if not validate_proof_bundle(bundle):
            raise ProofBundleStoreError("proof_bundle_must_be_sealed_and_valid")
        with self._lock:
            existing = self._bundles.get(bundle.bundle_id)
            if existing is not None:
                if existing.seal_digest != bundle.seal_digest:
                    raise ProofBundleStoreError("proof_bundle_id_conflict")
                return existing.bundle_id
            if len(self._bundles) >= self._max_bundles:
                raise ProofBundleStoreError("proof_bundle_store_capacity_exhausted")
            self._bundles[bundle.bundle_id] = bundle
            return bundle.bundle_id

    def get(self, bundle_id: str, *, engagement_id: str | None = None) -> ProofBundle | None:
        """Return a bundle only when the optional engagement boundary matches."""
        with self._lock:
            bundle = self._bundles.get(str(bundle_id))
            if bundle is None:
                return None
            if engagement_id is not None and bundle.engagement_id != str(engagement_id):
                return None
            return bundle

    def list(self, *, engagement_id: str | None = None) -> tuple[ProofBundle, ...]:
        """Return deterministic insertion-order snapshots within an engagement."""
        with self._lock:
            values = tuple(self._bundles.values())
        if engagement_id is None:
            return values
        return tuple(item for item in values if item.engagement_id == str(engagement_id))

    def snapshot(self, *, engagement_id: str | None = None) -> tuple[dict[str, Any], ...]:
        """Return JSON-safe snapshots without exposing mutable model internals."""
        return tuple(
            item.model_dump(mode="json")
            for item in self.list(engagement_id=engagement_id)
        )

    def __len__(self) -> int:
        with self._lock:
            return len(self._bundles)


__all__ = ["ProofBundleStore", "ProofBundleStoreError"]
