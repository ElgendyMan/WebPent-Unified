"""Short-lived, engagement-bound secret references.

The vault is deliberately in-memory and non-persistent. Callers must keep the
returned reference, never the underlying value, in workflow state or evidence.
Production deployments should replace the storage backend with an encrypted,
least-privilege secret manager behind the same contract.
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SecretVaultError(RuntimeError):
    """Raised when a secret reference is invalid, expired, or mis-bound."""


class SecretRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    ref: str = Field(min_length=1, max_length=240)
    engagement_id: str = Field(min_length=1, max_length=160)
    secret_type: str = Field(min_length=1, max_length=80)
    created_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def _valid_window(self) -> SecretRef:
        if self.created_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("secret_ref_requires_timezone")
        if self.expires_at <= self.created_at:
            raise ValueError("secret_ref_expiry_invalid")
        return self


@dataclass(frozen=True)
class _StoredSecret:
    value: str | bytes
    ref: SecretRef


def _contains_nested_secret(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(_contains_nested_secret(child) for child in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_nested_secret(child) for child in value)
    return False


class SecretVault:
    """Thread-safe volatile vault with strict engagement isolation."""

    def __init__(self, *, max_ttl: timedelta = timedelta(minutes=15)) -> None:
        if max_ttl <= timedelta(0):
            raise ValueError("vault_max_ttl_invalid")
        self._max_ttl = max_ttl
        self._items: dict[str, _StoredSecret] = {}
        self._lock = RLock()

    def put(
        self,
        value: str | bytes,
        *,
        engagement_id: str,
        secret_type: str,
        ttl: timedelta = timedelta(minutes=5),
    ) -> SecretRef:
        if not engagement_id or not secret_type:
            raise ValueError("secret_ref_binding_required")
        if not isinstance(value, (str, bytes)) or not value:
            raise ValueError("secret_value_invalid")
        if isinstance(value, str) and "\x00" in value:
            raise ValueError("secret_value_invalid")
        if _contains_nested_secret(value):
            raise ValueError("nested_secret_not_supported")
        if ttl <= timedelta(0) or ttl > self._max_ttl:
            raise ValueError("secret_ttl_out_of_bounds")
        now = datetime.now(timezone.utc)
        ref = SecretRef(
            ref=f"vault://{secret_type}/{secrets.token_urlsafe(18)}",
            engagement_id=engagement_id,
            secret_type=secret_type,
            created_at=now,
            expires_at=now + ttl,
        )
        with self._lock:
            self._purge_locked(now)
            self._items[ref.ref] = _StoredSecret(value=value, ref=ref)
        return ref

    def get(self, ref: SecretRef | str, *, engagement_id: str) -> str | bytes:
        ref_value = ref.ref if isinstance(ref, SecretRef) else str(ref)
        with self._lock:
            item = self._items.get(ref_value)
            if item is None:
                raise SecretVaultError("secret_ref_not_found")
            now = datetime.now(timezone.utc)
            if item.ref.engagement_id != engagement_id:
                raise SecretVaultError("secret_engagement_mismatch")
            if item.ref.expires_at <= now:
                del self._items[ref_value]
                raise SecretVaultError("secret_ref_expired")
            return item.value

    def consume(self, ref: SecretRef | str, *, engagement_id: str) -> str | bytes:
        ref_value = ref.ref if isinstance(ref, SecretRef) else str(ref)
        value = self.get(ref, engagement_id=engagement_id)
        with self._lock:
            self._items.pop(ref_value, None)
        return value

    def revoke(self, ref: SecretRef | str, *, engagement_id: str) -> bool:
        ref_value = ref.ref if isinstance(ref, SecretRef) else str(ref)
        with self._lock:
            item = self._items.get(ref_value)
            if item is None:
                return False
            if item.ref.engagement_id != engagement_id:
                raise SecretVaultError("secret_engagement_mismatch")
            del self._items[ref_value]
            return True

    def purge_expired(self) -> int:
        with self._lock:
            return self._purge_locked(datetime.now(timezone.utc))

    def _purge_locked(self, now: datetime) -> int:
        expired = [key for key, item in self._items.items() if item.ref.expires_at <= now]
        for key in expired:
            del self._items[key]
        return len(expired)


__all__ = ["SecretRef", "SecretVault", "SecretVaultError"]
