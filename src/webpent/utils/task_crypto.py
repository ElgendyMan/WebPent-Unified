# src/webpent/utils/task_crypto.py
"""webpent.utils.task_crypto

V10 HOSTILE-AUDIT FIX (CH-2): encrypt operator-supplied credentials
before they are placed on the Celery/Redis broker as task kwargs.

Problem
-------
``api/app.py``'s ``start_scan`` passes ``request.credentials``
(including the raw password) directly into
``run_pentest_task.delay(...)``. With ``task_serializer="json"`` and a
Redis broker (see ``workers/pentest_worker.py``'s ``_REDIS_URL``,
which defaults to plain ``redis://`` with no ``broker_use_ssl``
configured), the task message — including the plaintext password — is
JSON-serialized and written into Redis. It sits there in plaintext
for however long the task waits in queue, readable by anyone with
Redis access (a shared component, often with a wider trust boundary
than the API/worker processes themselves).

This is a DIFFERENT problem from the one ``auth.reauth_vault`` solves.
``reauth_vault`` keeps the password out of the LangGraph SqliteSaver
checkpoint (a different persistence layer, written to AFTER the graph
starts running). This module protects the password during the much
earlier API -> Celery -> Redis -> worker hop, before the graph has
even been built.

Fix
---
Symmetric encryption (Fernet — AES-128-CBC + HMAC-SHA256, authenticated)
of the ``credentials["password"]`` field only:

  * :func:`encrypt_credentials_for_task` is called in ``api/app.py``
    immediately before ``run_pentest_task.delay(...)``.
  * :func:`decrypt_credentials_from_task` is called at the very top of
    ``workers/pentest_worker.run_pentest_task``, before the
    ``credentials`` kwarg is used for anything else (sealing the
    reauth vault, building ``initial_state``).

``username`` is left in plaintext — it is not a secret, and keeping it
readable lets operators debug task payloads in Celery monitoring
tools (e.g. Flower) without decrypting anything.

The current Fernet key is derived from ``Settings.celery_payload_key`` via
versioned PBKDF2-HMAC-SHA256 with a per-message random salt. Operators still
configure a passphrase, while each broker envelope carries only its salt and
ciphertext. Legacy ``enc:v1:`` envelopes (the former SHA-256 derivation) remain
readable during rotation, and an optional previous key can be configured with
``CELERY_PAYLOAD_KEY_PREVIOUS`` or ``WEBPENT_CELERY_PAYLOAD_KEY_PREVIOUS``.
New dispatches always use ``enc:v2:``.

Both functions are idempotent / defensive by design:
  * :func:`decrypt_credentials_from_task` only attempts decryption when
    the password carries a recognized ``enc:v2:`` or legacy ``enc:v1:`` marker —
    a plaintext password (e.g. from a test harness, the CLI, or a task
    dispatched before this fix shipped) passes through unchanged.
  * Both functions fail CLOSED on error: if encryption fails, the
    password is dropped (empty string) rather than sent in plaintext;
    if decryption fails (wrong/rotated key, corrupted payload), the
    password is dropped rather than risk using a mis-decrypted value.
    Either failure degrades the engagement to unauthenticated rather
    than silently leaking or silently corrupting credentials — see the
    module docstring convention used throughout ``auth/reauth_vault.py``
    for the same fail-loud philosophy.

Residual risk (documented, not solved by this module)
-------------------------------------------------------
The key itself must be distributed to both the API and worker
processes, e.g. via the same ``.env`` / secret manager already used
for ``jwt_secret_key``. This moves the trust boundary from "Redis" to
"wherever ``WEBPENT_CELERY_PAYLOAD_KEY`` is stored" — the same
boundary already accepted for the JWT and audit secrets. This module
does not encrypt ``session_cookies`` (operator-supplied cookies are
already engagement-scoped and short-lived by nature, and are not the
credential CH-2 was raised against) nor does it add TLS to the Redis
connection itself; ``WEBPENT_REDIS_URL`` should still be set to
``rediss://`` in production for transport-level protection of the
rest of the task payload (target URL, thread_id, etc.).
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets

logger = logging.getLogger(__name__)

# Marker prefixed onto an encrypted password so decrypt_credentials_from_task
# can tell an encrypted payload apart from a plaintext one (idempotency —
# see module docstring). Chosen to be exceedingly unlikely to collide with
# a real plaintext password.
_LEGACY_ENCRYPTED_MARKER = "enc:v1:"
_ENCRYPTED_MARKER = "enc:v2:"
_KDF_VERSION = 2
_KDF_SALT_BYTES = 16
_KDF_ITERATIONS = 600_000
_PREVIOUS_KEY_ENV_NAMES = (
    "CELERY_PAYLOAD_KEY_PREVIOUS",
    "WEBPENT_CELERY_PAYLOAD_KEY_PREVIOUS",
    "CELERY_PAYLOAD_KEY_OLD",
    "WEBPENT_CELERY_PAYLOAD_KEY_OLD",
)


def _derive_fernet_key(secret: str) -> bytes:
    """Derive the legacy SHA-256 Fernet key for v1 migration reads only."""
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def derive_v2_fernet_key(secret: str, salt: bytes) -> bytes:
    """Derive a Fernet key with the versioned PBKDF2-HMAC-SHA256 policy."""
    if not secret or not isinstance(salt, bytes) or len(salt) < _KDF_SALT_BYTES:
        raise ValueError("PBKDF2 key derivation requires a secret and a 16-byte salt")
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode("utf-8"),
        salt,
        _KDF_ITERATIONS,
        dklen=32,
    )
    return base64.urlsafe_b64encode(digest)


def _configured_secrets() -> tuple[str, ...]:
    """Return current and explicitly configured previous secrets, deduplicated."""
    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        current = str(settings.celery_payload_key or "")
        previous = str(getattr(settings, "celery_payload_key_previous", "") or "")
    except Exception:
        current = ""
        previous = ""
    values = [current, previous]
    for env_name in _PREVIOUS_KEY_ENV_NAMES:
        value = os.getenv(env_name, "").strip()
        if value:
            values.append(value)
    return tuple(dict.fromkeys(value for value in values if value))


def _encrypt_value(value: str, *, marker: str = _ENCRYPTED_MARKER) -> str:
    """Encrypt one value using the current versioned KDF envelope."""
    from cryptography.fernet import Fernet

    secrets_for_use = _configured_secrets()
    if not secrets_for_use:
        raise RuntimeError("celery payload key is not configured")
    salt = secrets.token_bytes(_KDF_SALT_BYTES)
    token = Fernet(derive_v2_fernet_key(secrets_for_use[0], salt)).encrypt(
        value.encode("utf-8")
    ).decode("ascii")
    salt_text = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    return f"enc:v2:{salt_text}:{token}"


def _decode_v2_envelope(payload: str) -> tuple[bytes, str]:
    """Decode ``enc:v2:<salt>:<token>`` without accepting ambiguous fields."""
    prefix = _ENCRYPTED_MARKER
    if not payload.startswith(prefix):
        raise ValueError("not a v2 envelope")
    remainder = payload[len(prefix) :]
    salt_text, separator, token = remainder.partition(":")
    if not separator or not salt_text or not token:
        raise ValueError("malformed v2 envelope")
    padded = salt_text + "=" * (-len(salt_text) % 4)
    salt = base64.urlsafe_b64decode(padded.encode("ascii"))
    if len(salt) != _KDF_SALT_BYTES:
        raise ValueError("invalid v2 salt length")
    return salt, token


def _decrypt_value(payload: str) -> str:
    """Decrypt v2 or legacy v1; caller handles the fail-closed exception."""
    from cryptography.fernet import Fernet

    candidates = _configured_secrets()
    if payload.startswith(_ENCRYPTED_MARKER):
        salt, token = _decode_v2_envelope(payload)
        for secret in candidates:
            try:
                return Fernet(derive_v2_fernet_key(secret, salt)).decrypt(
                    token.encode("ascii")
                ).decode("utf-8")
            except Exception:
                continue
        raise ValueError("v2 decryption failed")
    if payload.startswith(_LEGACY_ENCRYPTED_MARKER):
        token = payload[len(_LEGACY_ENCRYPTED_MARKER) :]
        if not token:
            raise ValueError("empty legacy envelope")
        for secret in candidates:
            try:
                return Fernet(_derive_fernet_key(secret)).decrypt(
                    token.encode("ascii")
                ).decode("utf-8")
            except Exception:
                continue
        raise ValueError("legacy decryption failed")
    if payload.startswith("enc:"):
        raise ValueError("unsupported encrypted envelope version")
    return payload


def encrypt_credentials_for_task(
    credentials: dict[str, str] | None,
) -> dict[str, str]:
    """Return a copy of ``credentials`` with the password encrypted.

    Call this in ``api/app.py`` immediately before
    ``run_pentest_task.delay(...)``. Safe to call with ``None`` or an
    empty/password-less dict — returns ``{}`` or the dict unchanged
    (nothing sensitive to protect).

    Fails CLOSED: if encryption raises for any reason (misconfigured
    key, missing ``cryptography`` package), the password is dropped
    rather than sent to the broker in plaintext. The engagement will
    run unauthenticated rather than risk a CH-2 regression.
    """
    if not credentials:
        return {}
    password = credentials.get("password", "")
    if not password:
        return dict(credentials)
    try:
        out = dict(credentials)
        out["password"] = _encrypt_value(password)
        return out
    except Exception as exc:
        logger.error(
            "CH-2 mitigation: failed to encrypt credentials for Celery "
            "task dispatch (%s) — refusing to send a plaintext password "
            "to the broker. This scan will proceed unauthenticated; "
            "check WEBPENT_CELERY_PAYLOAD_KEY and that the "
            "'cryptography' package is installed.",
            exc,
        )
        out = dict(credentials)
        out["password"] = ""
        return out


def decrypt_credentials_from_task(
    credentials: dict[str, str] | None,
) -> dict[str, str]:
    """Return a copy of ``credentials`` with the password decrypted.

    Call this as the FIRST thing ``workers/pentest_worker.run_pentest_task``
    does with its ``credentials`` kwarg — before sealing the reauth
    vault and before building ``initial_state`` — so every downstream
    consumer (auth_node, the reauth vault, ``initial_state["credentials"]``)
    sees a plaintext password exactly as before this fix.

    Idempotent: a password without the ``enc:v1:`` marker (plaintext —
    e.g. from the CLI, a test harness, or a task dispatched before this
    fix shipped) is returned unchanged, so redelivered/in-flight tasks
    from before a deploy of this fix do not break.

    Fails CLOSED: if decryption raises (wrong/rotated key, corrupted
    payload), the password is dropped rather than risk passing a
    mis-decrypted value to Playwright/the reauth vault.
    """
    if not credentials:
        return {}
    password = credentials.get("password", "")
    if not password.startswith("enc:"):
        return dict(credentials)
    try:
        out = dict(credentials)
        out["password"] = _decrypt_value(password)
        return out
    except Exception as exc:
        logger.error(
            "CH-2 mitigation: failed to decrypt task credentials (%s) — "
            "wrong/rotated celery_payload_key, or corrupted payload. "
            "Proceeding with an EMPTY password (fail-closed): this "
            "engagement will run unauthenticated rather than risk "
            "using a mis-decrypted credential.",
            exc,
        )
        out = dict(credentials)
        out["password"] = ""
        return out


def encrypt_secret_map_for_task(
    values: dict[str, str] | None,
) -> dict[str, str]:
    """Encrypt values in a bounded operator-supplied secret map."""
    if not values:
        return {}
    try:
        out: dict[str, str] = {}
        for name, value in values.items():
            text = str(value)
            if not text or text.startswith("enc:"):
                out[str(name)] = text
                continue
            out[str(name)] = _encrypt_value(text)
        return out
    except Exception as exc:
        logger.error(
            "Failed to encrypt secret map for Celery dispatch (%s); "
            "dropping secret values fail-closed.",
            exc,
        )
        return {str(name): "" for name in values}


def decrypt_secret_map_from_task(
    values: dict[str, str] | None,
) -> dict[str, str]:
    """Decrypt a secret map at the worker boundary; corrupt values become empty."""
    if not values:
        return {}
    try:
        out: dict[str, str] = {}
        for name, value in values.items():
            text = str(value)
            out[str(name)] = _decrypt_value(text) if text.startswith("enc:") else text
        return out
    except Exception as exc:
        logger.error(
            "Failed to decrypt secret map at worker boundary (%s); "
            "dropping secret values fail-closed.",
            exc,
        )
        return {str(name): "" for name in values}


def encrypt_identity_profiles_for_task(
    profiles: dict[str, dict[str, object]] | None,
) -> dict[str, dict[str, object]]:
    """Encrypt credentials nested in bounded identity profiles before Celery dispatch."""
    if not profiles:
        return {}
    out: dict[str, dict[str, object]] = {}
    for name, profile in profiles.items():
        safe_profile = dict(profile)
        raw_credentials = safe_profile.get("credentials")
        if isinstance(raw_credentials, dict):
            safe_profile["credentials"] = encrypt_credentials_for_task(
                {str(k): str(v) for k, v in raw_credentials.items()}
            )
        out[str(name)] = safe_profile
    return out


def decrypt_identity_profiles_from_task(
    profiles: dict[str, dict[str, object]] | None,
) -> dict[str, dict[str, object]]:
    """Decrypt nested identity credentials at the worker boundary."""
    if not profiles:
        return {}
    out: dict[str, dict[str, object]] = {}
    for name, profile in profiles.items():
        safe_profile = dict(profile)
        raw_credentials = safe_profile.get("credentials")
        if isinstance(raw_credentials, dict):
            safe_profile["credentials"] = decrypt_credentials_from_task(
                {str(k): str(v) for k, v in raw_credentials.items()}
            )
        out[str(name)] = safe_profile
    return out
