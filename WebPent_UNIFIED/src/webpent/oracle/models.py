"""The Oracle — shared types and safety primitives (v88).

Everything the Oracle stores passes through two gates before it lands in
a report or a ledger: `sanitize_secret` (ORACLE-L-3 — a secret is reduced
to a SHA-256 hash plus a 4-character prefix, never the value itself) and
`redact_pii` (ORACLE-L-4 — emails, phone numbers and government-id-like
numbers are replaced with a typed placeholder before storage).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

SECRET_KEY_HINTS = ("secret", "token", "password", "api_key", "apikey", "credential")


class ZeroTouchViolationError(RuntimeError):
    """Raised when any code path attempts a request to the target
    (ORACLE-L-1/L-2). A law breach is never an isolatable per-source
    failure: it aborts the whole gather loudly."""


ZeroTouchViolation = ZeroTouchViolationError
class OracleLawError(ValueError):
    """A configuration or action would violate an Oracle law."""


@dataclass
class Target:
    """An in-scope target the operator has authorized intelligence work on."""

    host: str
    allowed_scopes: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """A candidate weakness the Oracle reasons about (input to chains,
    perspectives and impact escalation)."""

    finding_id: str
    vuln_class: str
    endpoint: str
    severity: str  # info | low | medium | high | critical
    confidence: float
    detail: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sanitize_secret(value: str) -> dict[str, str]:
    """ORACLE-L-3: reduce a secret to its hash and, for values long
    enough that a prefix is not itself the whole secret, a 4-char
    prefix. The full value must never be persisted anywhere downstream."""
    return {
        "sha256": sha256_text(value),
        # a prefix of a short secret IS the secret (RT-02): only values
        # longer than 8 chars may carry one.
        "partial": (value[:4] + "…") if len(value) > 8 else "",
        "length": str(len(value)),
    }


def sanitize_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """ORACLE-L-3/L-4 applied at every nesting depth: secret-valued keys
    at any level are reduced to hash+length (RT-03), personal-data keys
    are replaced outright, and any remaining string is PII-redacted."""
    dropped = ("email", "phone", "full_name", "firstname", "lastname", "ssn")

    def _walk(value: Any) -> Any:
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for key, item in value.items():
                lowered = str(key).lower()
                if looks_like_secret_key(key) and isinstance(item, str):
                    out[key] = sanitize_secret(item)
                elif any(d in lowered for d in dropped):
                    out[key] = "[pii-redacted:key]"
                else:
                    out[key] = _walk(item)
            return out
        if isinstance(value, list):
            return [_walk(item) for item in value]
        if isinstance(value, str):
            return redact_pii(value)
        return value

    return _walk(raw)


def looks_like_secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(hint in lowered for hint in SECRET_KEY_HINTS)


PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone": re.compile(r"(?:\+?\d[\d\s().-]{7,}\d)"),
    "national_id": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}


def redact_pii(value: Any) -> Any:
    """ORACLE-L-4: replace personal data inside any string with a typed
    placeholder; recurse through dicts and lists. Numbers that are plain
    counts (short, no separators) are left alone."""
    if isinstance(value, str):
        redacted = value
        for pii_type, pattern in PII_PATTERNS.items():
            if pii_type == "phone":
                redacted = pattern.sub(
                    lambda m: "[pii-redacted:phone]"
                    if sum(ch.isdigit() for ch in m.group(0)) >= 9
                    else m.group(0),
                    redacted,
                )
            else:
                redacted = pattern.sub(f"[pii-redacted:{pii_type}]", redacted)
        return redacted
    if isinstance(value, dict):
        return {k: redact_pii(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_pii(v) for v in value]
    return value


def strip_pii_keys(raw: dict[str, Any]) -> dict[str, Any]:
    """Drop dict entries whose key names denote personal data outright
    (email, phone, name fields), redact the rest."""
    dropped = ("email", "phone", "full_name", "firstname", "lastname", "ssn")
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if any(d in key.lower() for d in dropped):
            out[key] = "[pii-redacted:key]"
        else:
            out[key] = redact_pii(value)
    return out


def canonical_hash(payload: Any) -> str:
    return sha256_text(json.dumps(payload, sort_keys=True, default=str))
