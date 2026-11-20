from __future__ import annotations

import threading
from typing import Any

from .models import ScopePolicy
from .store import ScopeStoreUnavailable, SqliteScopeStore


class ScopeRegistry:
    """Process-local registry with an OPTIONAL durable shared backend.

    UM-DR-41 §6.3: the historical registry was an in-memory dict under a
    thread lock — authoritative only inside one process. A policy loaded
    through the API's ``/scope/load`` never reached Celery workers or
    other Uvicorn workers, and vanished on restart.

    Construction modes (both preserve the historical method signatures):

    * ``ScopeRegistry()`` — exact legacy behavior (in-memory only). All
      existing imports and tests are untouched.
    * ``ScopeRegistry(store=SqliteScopeStore(path))`` — every ``load``
      appends a versioned record to the shared store, every ``get``
      falls through to the store on an in-memory miss (another process
      may have loaded the policy), and ``clear`` tombstones both views.
      Store failures propagate as ``ScopeStoreUnavailable`` so callers
      fail closed instead of silently continuing permissive.

    The durable store is the AUTHORITY when present: the in-memory dict
    is a cache, and ``redacted()`` merges both views so the API listing
    reflects policies loaded by any process.
    """

    def __init__(self, *, store: SqliteScopeStore | None = None) -> None:
        self._lock = threading.RLock()
        self._policies: dict[str, ScopePolicy] = {}
        self._versions: dict[str, int] = {}
        self._store = store

    def attach_store(self, store: SqliteScopeStore) -> None:
        """Upgrade this registry with a durable store at runtime.

        Used by API startup when WEBPENT_SCOPE_STORE_* is configured.
        Existing cached policies are written through to the store so the
        upgrade never loses an already-loaded policy. Raises
        ``ScopeStoreUnavailable`` if the store rejects any write — the
        caller decides to fail startup (API) rather than downgrade.
        """
        with self._lock:
            self._store = store
            cached = dict(self._policies)
            self._versions.clear()
        for key, policy in cached.items():
            self.load(policy, engagement_id=key)

    def load(self, policy: ScopePolicy, *, engagement_id: str) -> ScopePolicy:
        key = str(engagement_id).strip()
        if not key or len(key) > 128:
            raise ValueError("engagement_id is required")
        # Durable write FIRST: if the store rejects the write, the
        # in-memory view must not pretend the load succeeded.
        version: int | None = None
        if self._store is not None:
            version = self._store.append(policy, engagement_id=key)
        with self._lock:
            self._policies[key] = policy
            if version is not None:
                self._versions[key] = version
        return policy

    def get(self, engagement_id: str) -> ScopePolicy | None:
        key = str(engagement_id).strip()
        if self._store is not None:
            # Durable store is the AUTHORITY: read it first (raises
            # ScopeStoreUnavailable on failure — fail closed). The
            # in-memory dict is only a write-through cache, so a record
            # another process changed, tombstoned or corrupted is always
            # observed here, never a stale local copy.
            return self._store.current(key)
        with self._lock:
            return self._policies.get(key)

    def current_version(self, engagement_id: str) -> int | None:
        """Policy version, when version tracking is active (else None)."""
        key = str(engagement_id).strip()
        with self._lock:
            if key in self._versions:
                return self._versions[key]
        if self._store is not None:
            return self._store.current_version(key)
        return None

    def clear(self, engagement_id: str) -> bool:
        key = str(engagement_id).strip()
        cleared_durable = False
        if self._store is not None:
            cleared_durable = self._store.clear(key)
        with self._lock:
            cleared_memory = self._policies.pop(key, None) is not None
            self._versions.pop(key, None)
        return cleared_memory or cleared_durable

    def redacted(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            merged: dict[str, dict[str, Any]] = {
                key: policy.as_dict()
                for key, policy in self._policies.items()
            }
        if self._store is not None:
            # Store view wins on conflicts: it may contain policies this
            # process has not cached (loaded by a peer process).
            merged.update(self._store.redacted())
        return merged


GLOBAL_SCOPE_REGISTRY = ScopeRegistry()
__all__ = ["GLOBAL_SCOPE_REGISTRY", "ScopeRegistry", "ScopeStoreUnavailable"]
