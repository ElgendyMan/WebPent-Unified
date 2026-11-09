from __future__ import annotations

import threading
from .models import ScopePolicy


class ScopeRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._policies: dict[str, ScopePolicy] = {}

    def load(self, policy: ScopePolicy, *, engagement_id: str) -> ScopePolicy:
        key = str(engagement_id).strip()
        if not key or len(key) > 128:
            raise ValueError("engagement_id is required")
        with self._lock:
            self._policies[key] = policy
        return policy

    def get(self, engagement_id: str) -> ScopePolicy | None:
        with self._lock:
            return self._policies.get(str(engagement_id).strip())

    def clear(self, engagement_id: str) -> bool:
        with self._lock:
            return self._policies.pop(str(engagement_id).strip(), None) is not None

    def redacted(self) -> dict[str, dict]:
        with self._lock:
            return {key: policy.as_dict() for key, policy in self._policies.items()}


GLOBAL_SCOPE_REGISTRY = ScopeRegistry()
__all__ = ["GLOBAL_SCOPE_REGISTRY", "ScopeRegistry"]
