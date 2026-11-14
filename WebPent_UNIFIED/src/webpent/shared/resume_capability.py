"""Short-lived, signed capability for HITL engagement resumption.

The API authorizes the human approval first, then issues this capability to
Celery. The worker verifies the signature and binds every claim to the
persisted scan-registry record before invoking LangGraph. The capability is
never written to graph state or SQLite checkpoints.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from typing import Any

from webpent.config.settings import get_settings

_VERSION = "v1"
_ALGORITHM = "sha256"
_MAX_TOKEN_BYTES = 2048


def _key() -> bytes:
    secret = get_settings().jwt_secret_key
    if not secret or len(secret) < 32:
        raise ValueError("resume capability signing key is not configured securely")
    return secret.encode("utf-8")


def _encode(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).rstrip(b"=")
    signature = hmac.new(_key(), body, hashlib.sha256).digest()
    sig = base64.urlsafe_b64encode(signature).rstrip(b"=")
    token = f"{_VERSION}.{body.decode('ascii')}.{sig.decode('ascii')}"
    if len(token.encode("ascii")) > _MAX_TOKEN_BYTES:
        raise ValueError("resume capability is unexpectedly large")
    return token


def _decode(token: str) -> dict[str, Any]:
    if not isinstance(token, str) or len(token.encode("utf-8")) > _MAX_TOKEN_BYTES:
        raise ValueError("invalid resume capability")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != _VERSION:
        raise ValueError("invalid resume capability format")
    _, body_text, signature_text = parts
    body = body_text.encode("ascii")
    supplied = base64.urlsafe_b64decode(signature_text + "=" * (-len(signature_text) % 4))
    expected = hmac.new(_key(), body, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied, expected):
        raise ValueError("invalid resume capability signature")
    raw = base64.urlsafe_b64decode(body_text + "=" * (-len(body_text) % 4))
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("invalid resume capability payload")
    return payload


def issue_resume_capability(
    *,
    thread_id: str,
    owner_username: str,
    client_id: str,
    engagement_id: str,
    ttl_seconds: int = 120,
) -> str:
    """Issue a short-lived capability after API authorization succeeds."""
    if not all((thread_id, owner_username, engagement_id)):
        raise ValueError("resume capability requires stable engagement identity")
    if ttl_seconds <= 0 or ttl_seconds > 900:
        raise ValueError("resume capability TTL must be between 1 and 900 seconds")
    now = int(time.time())
    return _encode(
        {
            "aud": "webpent-resume",
            "thread_id": thread_id,
            "owner_username": owner_username,
            "client_id": client_id,
            "engagement_id": engagement_id,
            "iat": now,
            "exp": now + ttl_seconds,
        }
    )


def verify_resume_capability_detailed(
    token: str,
    *,
    thread_id: str,
    record: dict[str, Any],
) -> tuple[bool, str]:
    """Verify a capability and return a safe, non-secret denial reason."""
    try:
        payload = _decode(token)
    except (
        TypeError,
        ValueError,
        KeyError,
        UnicodeError,
        binascii.Error,
        json.JSONDecodeError,
    ):
        return False, "invalid_signature_or_format"

    now = int(time.time())
    if payload.get("aud") != "webpent-resume":
        return False, "invalid_audience"
    try:
        expires_at = int(payload.get("exp", 0))
        issued_at = int(payload.get("iat", 0))
    except (TypeError, ValueError):
        return False, "invalid_timestamps"
    if expires_at < now:
        return False, "expired_capability"
    if issued_at > now + 30:
        return False, "future_issued_capability"

    expected = {
        "thread_id": thread_id,
        "owner_username": str(record.get("owner_username") or ""),
        "client_id": str(record.get("client_id") or ""),
        "engagement_id": str(record.get("engagement_id") or thread_id),
    }
    for key, value in expected.items():
        if key == "client_id" and not value:
            continue
        if payload.get(key) != value:
            return False, f"binding_mismatch_{key}"
    return True, "valid"


def verify_resume_capability(
    token: str,
    *,
    thread_id: str,
    record: dict[str, Any],
) -> bool:
    """Verify signature, freshness, thread binding, and registry identity."""
    valid, _reason = verify_resume_capability_detailed(
        token,
        thread_id=thread_id,
        record=record,
    )
    return valid


__all__ = [
    "issue_resume_capability",
    "verify_resume_capability",
    "verify_resume_capability_detailed",
]
