# src/webpent/auth/reauth_vault.py
"""Worker-only runtime secret vault for authenticated engagements.

The vault keeps re-authentication material out of LangGraph checkpoints while
preserving the existing ``seal_reauth_secret``/``unseal_reauth_secret`` API.
Values are encrypted before being retained in worker memory, expire after a
bounded TTL, and are cleared when the engagement exits.  The vault is not a
replacement for a dedicated secret manager; missing or invalid key material is
fail-closed and produces no usable secret.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any

from cryptography.fernet import InvalidToken

logger = logging.getLogger(__name__)

_LOCK = threading.Lock()
_PASSWORD_VAULT: dict[str, tuple[str, float]] = {}
_COOKIE_VAULT: dict[str, tuple[str, float]] = {}
_IDENTITY_VAULT: dict[str, tuple[str, float]] = {}
_DEFAULT_TTL_SECONDS = 7_200
_MIN_TTL_SECONDS = 60
_MAX_TTL_SECONDS = 86_400
_DEFAULT_SWEEP_LIMIT = 256
_SHARED_STORE_ENV = "WEBPENT_REAUTH_VAULT_SHARED_STORE"
_SHARED_DB_ENV = "WEBPENT_REAUTH_VAULT_DATABASE_URL"
_SHARED_RECORD_TYPES = ("password", "cookies", "identity")
_SHARED_DATABASES: dict[str, Any] = {}


def identity_vault_key(client_id: str, engagement_id: str) -> str:
    """Return the engagement-scoped identity vault key.

    The exact key shape is ``client_id:engagement_id:identity``. Colons in
    caller-provided identifiers are normalized to avoid ambiguous addressing.
    Empty identifiers fall back to the legacy engagement key so old callers
    remain readable and cleanup stays backward-compatible.
    """
    client = str(client_id or "").strip().replace(":", "_")
    engagement = str(engagement_id or "").strip().replace(":", "_")
    if not client or not engagement:
        return engagement or client
    return f"{client}:{engagement}:identity"


def _shared_store_enabled() -> bool:
    """Return whether encrypted records should also survive worker restarts."""
    return os.getenv(_SHARED_STORE_ENV, "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _shared_database():
    """Return a cached DatabaseManager for the configured shared SQLite store."""
    if not _shared_store_enabled():
        return None
    try:
        from webpent.config.settings import get_settings
        from webpent.memory.db import DatabaseManager

        database_url = (
            os.getenv(_SHARED_DB_ENV)
            or os.getenv("WEBPENT_DATABASE_URL")
            or os.getenv("DATABASE_URL")
            or get_settings().database_url
        )
        if database_url == "sqlite://":
            logger.warning("Shared reauth vault disabled for in-memory SQLite")
            return None
        with _LOCK:
            manager = _SHARED_DATABASES.get(database_url)
            if manager is None:
                manager = DatabaseManager(database_url=database_url)
                _SHARED_DATABASES[database_url] = manager
            return manager
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("Shared reauth vault unavailable; using in-memory fallback: %s", exc)
        return None


def _shared_record(record_type: str, thread_id: str) -> tuple[str, float] | None:
    manager = _shared_database()
    if manager is None:
        return None
    try:
        return manager.get_reauth_vault_record(thread_id, record_type)
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("Shared reauth vault read failed; using in-memory fallback: %s", exc)
        return None


def _save_shared_record(thread_id: str, record_type: str, record: tuple[str, float]) -> None:
    manager = _shared_database()
    if manager is None:
        return
    try:
        manager.save_reauth_vault_record(thread_id, record_type, record[0], record[1])
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("Shared reauth vault write failed; retaining in-memory record: %s", exc)


def _delete_shared_records(thread_id: str, record_type: str | None = None) -> int:
    manager = _shared_database()
    if manager is None:
        return 0
    try:
        if record_type is not None:
            return manager.delete_reauth_vault_record(thread_id, record_type)
        return manager.delete_reauth_vault_records(thread_id)
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.warning("Shared reauth vault delete failed: %s", exc)
        return 0


def sweep_expired(max_items: int = _DEFAULT_SWEEP_LIMIT) -> int:
    """Remove at most ``max_items`` expired vault records and return the count."""
    if max_items <= 0:
        return 0
    now = time.time()
    removed = 0
    with _LOCK:
        for vault in (_PASSWORD_VAULT, _COOKIE_VAULT, _IDENTITY_VAULT):
            for thread_id, (_token, expires_at) in list(vault.items()):
                if expires_at <= now:
                    vault.pop(thread_id, None)
                    removed += 1
                    if removed >= max_items:
                        return removed
    remaining = max_items - removed
    if remaining > 0:
        manager = _shared_database()
        if manager is not None:
            try:
                removed += manager.sweep_reauth_vault_records(remaining)
            except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
                logger.warning("Shared reauth vault sweep failed: %s", exc)
    return removed


def vault_stats() -> dict[str, int]:
    """Return bounded, non-secret counts for operational health reporting."""
    with _LOCK:
        stats = {
            "password_records": len(_PASSWORD_VAULT),
            "cookie_records": len(_COOKIE_VAULT),
            "identity_records": len(_IDENTITY_VAULT),
        }
    manager = _shared_database()
    if manager is not None:
        try:
            shared = manager.reauth_vault_stats()
            for record_type, key in zip(_SHARED_RECORD_TYPES, stats, strict=True):
                stats[key] += shared.get(record_type, 0)
        except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
            logger.warning("Shared reauth vault stats failed: %s", exc)
    return stats


def _ttl_seconds() -> int:
    """Return a bounded runtime TTL; invalid configuration fails closed."""
    raw = os.getenv("WEBPENT_REAUTH_VAULT_TTL_SECONDS", str(_DEFAULT_TTL_SECONDS))
    try:
        ttl = int(raw)
    except (TypeError, ValueError):
        return 0
    if not _MIN_TTL_SECONDS <= ttl <= _MAX_TTL_SECONDS:
        return 0
    return ttl


def _encrypt(value: str) -> tuple[str, float] | None:
    """Encrypt a vault value with the current versioned KDF envelope."""
    ttl = _ttl_seconds()
    if ttl <= 0 or not value:
        return None
    try:
        from webpent.utils.task_crypto import _encrypt_value

        token = _encrypt_value(value)
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.error("Reauth vault encryption failed; secret was not retained: %s", exc)
        return None
    return token, time.time() + ttl


def _decrypt(record: tuple[str, float] | None) -> str | None:
    """Decrypt current envelopes and legacy raw Fernet vault records."""
    if not record:
        return None
    token, expires_at = record
    if time.time() >= expires_at:
        return None
    try:
        from cryptography.fernet import Fernet

        from webpent.utils.task_crypto import (
            _configured_secrets,
            _decrypt_value,
            _derive_fernet_key,
        )

        if token.startswith("enc:"):
            return _decrypt_value(token)
        for secret in _configured_secrets():
            try:
                return Fernet(_derive_fernet_key(secret)).decrypt(
                    token.encode("ascii")
                ).decode("utf-8")
            except (OSError, RuntimeError, TypeError, ValueError, UnicodeError, InvalidToken):
                continue
        raise ValueError("legacy vault decryption failed")
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        logger.error("Reauth vault decryption failed; secret was not released: %s", exc)
        return None


def seal_reauth_secret(thread_id: str, password: str) -> None:
    """Store an encrypted re-auth password for the bounded engagement TTL."""
    sweep_expired()
    if not thread_id or not password:
        return
    record = _encrypt(password)
    if record is None:
        return
    with _LOCK:
        _PASSWORD_VAULT[thread_id] = record
    _save_shared_record(thread_id, "password", record)
    logger.debug("Reauth vault: sealed password for thread_id=%s", thread_id)


def unseal_reauth_secret(thread_id: str) -> str | None:
    """Retrieve a password if present and unexpired; do not log its value."""
    sweep_expired()
    if not thread_id:
        return None
    with _LOCK:
        record = _PASSWORD_VAULT.get(thread_id)
        value = _decrypt(record)
        if record and value is None and time.time() >= record[1]:
            _PASSWORD_VAULT.pop(thread_id, None)
    if value is not None:
        return value
    record = _shared_record("password", thread_id)
    value = _decrypt(record)
    if record and value is None and time.time() >= record[1]:
        _delete_shared_records(thread_id, "password")
    return value


def seal_session_cookies(thread_id: str, cookies: dict[str, str] | None) -> None:
    """Store operator cookies encrypted and outside checkpoint state."""
    sweep_expired()
    if not thread_id or not cookies:
        return
    record = _encrypt(json.dumps(cookies, sort_keys=True, separators=(",", ":")))
    if record is None:
        return
    with _LOCK:
        _COOKIE_VAULT[thread_id] = record
    _save_shared_record(thread_id, "cookies", record)
    logger.debug("Reauth vault: sealed session cookies for thread_id=%s", thread_id)


def unseal_session_cookies(thread_id: str) -> dict[str, str]:
    """Return validated cookie material or an empty mapping on any failure."""
    sweep_expired()
    if not thread_id:
        return {}
    with _LOCK:
        record = _COOKIE_VAULT.get(thread_id)
        value = _decrypt(record)
        if record and value is None and time.time() >= record[1]:
            _COOKIE_VAULT.pop(thread_id, None)
    if value is None:
        record = _shared_record("cookies", thread_id)
        value = _decrypt(record)
        if record and value is None and time.time() >= record[1]:
            _delete_shared_records(thread_id, "cookies")
    if not value:
        return {}
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(decoded, dict):
        return {}
    return {str(key): str(item) for key, item in decoded.items() if item not in (None, "")}


def seal_identity_profiles(thread_id: str, profiles: dict[str, Any] | None) -> None:
    """Store identity profiles encrypted for runtime restoration after resume."""
    sweep_expired()
    if not thread_id or not profiles:
        return
    record = _encrypt(json.dumps(profiles, sort_keys=True, separators=(",", ":")))
    if record is None:
        return
    with _LOCK:
        _IDENTITY_VAULT[thread_id] = record
    _save_shared_record(thread_id, "identity", record)
    logger.debug("Reauth vault: sealed identity profiles for thread_id=%s", thread_id)


def unseal_identity_profiles(thread_id: str) -> dict[str, Any]:
    """Return identity profiles or an empty mapping when unavailable/expired."""
    sweep_expired()
    if not thread_id:
        return {}
    with _LOCK:
        record = _IDENTITY_VAULT.get(thread_id)
        value = _decrypt(record)
        if record and value is None and time.time() >= record[1]:
            _IDENTITY_VAULT.pop(thread_id, None)
    if value is None:
        record = _shared_record("identity", thread_id)
        value = _decrypt(record)
        if record and value is None and time.time() >= record[1]:
            _delete_shared_records(thread_id, "identity")
    if not value:
        return {}
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def clear_reauth_secret(thread_id: str) -> None:
    """Remove every runtime secret associated with an engagement."""
    if not thread_id:
        return
    with _LOCK:
        removed = (
            _PASSWORD_VAULT.pop(thread_id, None) is not None
            or _COOKIE_VAULT.pop(thread_id, None) is not None
            or _IDENTITY_VAULT.pop(thread_id, None) is not None
        )
    shared_removed = _delete_shared_records(thread_id)
    if removed or shared_removed:
        logger.debug("Reauth vault: cleared runtime secrets for thread_id=%s", thread_id)
