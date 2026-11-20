"""Mandatory engagement authorization for real hunts.

A hunt that sends requests must run under a written authorization the
operator supplies as a JSON file. This module is the release gate: it
parses, validates and verifies that authorization against the target,
and refuses with a specific reason on every failure mode.

The gate is HARD, not advisory: the CLI blocks before any request is
built. Only ``--dry-run`` is exempt, because a dry run never touches the
network. Matching is at origin level (scheme + host[:port], userinfo
stripped, exactly like the remediation locator), so a scope entry can
never authorize a different host by path trickery.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from webpent.autonomous.hunt_contracts import redact

_DEFAULT_PORTS = {"http": "80", "https": "443"}


def origin_of(url: str) -> str:
    """Origin of a URL: scheme://host[:port], credentials stripped.

    Host case is normalized to lowercase (RFC 3986 section 3.2.2: host is
    case-insensitive) and the scheme's default port (http 80, https 443) is
    dropped, so ``https://LAB.Example:443`` and ``https://lab.example`` are
    the same origin.
    """
    parts = urlsplit(str(url))
    if not parts.scheme or not parts.netloc:
        return ""
    netloc = parts.netloc.rpartition("@")[2].lower()
    if not netloc:
        return ""
    host, sep, port = netloc.partition(":")
    if sep and port == _DEFAULT_PORTS.get(parts.scheme.lower(), ""):
        netloc = host
    return f"{parts.scheme.lower()}://{netloc}"


@dataclass(frozen=True)
class EngagementAuthorization:
    """A written authorization record for one engagement."""

    target_origin: str
    scope: tuple[str, ...]
    operator: str
    authorization_reference: str
    expires_at: datetime | None = None
    notes: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "target_origin": self.target_origin,
            "scope": list(self.scope),
            "operator": redact(self.operator, 160),
            "authorization_reference": redact(self.authorization_reference, 160),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "notes": redact(self.notes, 400),
        }


class AuthorizationError(ValueError):
    """Raised with a specific, operator-readable refusal reason."""


def _parse_datetime(value: object, field_name: str) -> datetime | None:
    if value is None or value == "":
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise AuthorizationError(
            f"authorization field {field_name!r} is not an ISO datetime: {value!r}"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _parse_scope(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        entries = (value,)
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        entries = tuple(value)
    else:
        raise AuthorizationError(
            "authorization field 'scope' must be a URL string or a list of URL strings"
        )
    scope = tuple(origin_of(entry) for entry in entries if origin_of(entry))
    return scope


def load_authorization(path: Path | str) -> EngagementAuthorization:
    """Parse an authorization JSON file with readable refusals."""
    file_path = Path(path)
    if not file_path.is_file():
        raise AuthorizationError(f"authorization file not found: {file_path}")
    try:
        document = json.loads(file_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AuthorizationError(
            f"authorization file is not valid JSON: {file_path} ({exc})"
        ) from exc
    if not isinstance(document, dict):
        raise AuthorizationError("authorization file must contain a JSON object")
    required = ("target_origin", "scope", "operator", "authorization_reference")
    missing = [name for name in required if not str(document.get(name) or "").strip()]
    if missing:
        raise AuthorizationError(
            "authorization file is missing required field(s): " + ", ".join(missing)
        )
    target_origin = origin_of(str(document["target_origin"]))
    if not target_origin:
        raise AuthorizationError(
            "authorization field 'target_origin' is not a usable URL origin"
        )
    scope = _parse_scope(document.get("scope"))
    if not scope:
        raise AuthorizationError(
            "authorization field 'scope' resolved to no usable origins; "
            "an empty scope authorizes nothing"
        )
    return EngagementAuthorization(
        target_origin=target_origin,
        scope=scope,
        operator=str(document["operator"]),
        authorization_reference=str(document["authorization_reference"]),
        expires_at=_parse_datetime(document.get("expires_at"), "expires_at"),
        notes=str(document.get("notes") or ""),
    )


def verify_authorization(
    target_url: str,
    authorization: EngagementAuthorization,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Verify the authorization covers ``target_url`` right now.

    Returns ``(ok, reason)``; ``reason`` states the exact failure mode on
    refusal and "authorized" on success. ``now`` is injectable for tests
    and defaults to the current UTC time.
    """
    target_origin = origin_of(target_url)
    if not target_origin:
        return False, f"target URL has no usable origin: {redact(str(target_url), 200)}"
    if target_origin != authorization.target_origin and target_origin not in authorization.scope:
        entries_word = "entry" if len(authorization.scope) == 1 else "entries"
        return (
            False,
            f"target origin {target_origin} is outside the authorized scope "
            f"({authorization.target_origin} + "
            f"{len(authorization.scope)} scope {entries_word})",
        )
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    if authorization.expires_at is not None and current >= authorization.expires_at:
        return (
            False,
            f"authorization {authorization.authorization_reference} expired at "
            f"{authorization.expires_at.isoformat()}",
        )
    return True, "authorized"


def require_authorization(
    target_url: str, path: Path | str, now: datetime | None = None
) -> EngagementAuthorization:
    """Load, verify and return the authorization, or raise with the reason.

    The single entry point the CLI uses: one call, every failure mode
    raises :class:`AuthorizationError` with a readable reason.
    """
    authorization = load_authorization(path)
    ok, reason = verify_authorization(target_url, authorization, now=now)
    if not ok:
        raise AuthorizationError(reason)
    return authorization


__all__ = [
    "AuthorizationError",
    "EngagementAuthorization",
    "load_authorization",
    "origin_of",
    "require_authorization",
    "verify_authorization",
]
