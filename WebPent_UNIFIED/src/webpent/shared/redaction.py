"""Central redaction helpers for diagnostics and persisted error metadata."""

from __future__ import annotations

import re
from typing import Any

_REPLACEMENT = "[REDACTED]"

_PATTERNS = (
    (
        re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"),
        rf"\1{_REPLACEMENT}",
    ),
    (
        re.compile(r"(?i)(\bbearer\s+)[^\s,;]+"),
        rf"\1{_REPLACEMENT}",
    ),
    (
        re.compile(r"(?i)(\b(?:cookie|set-cookie)\s*:\s*)[^\r\n]+"),
        rf"\1{_REPLACEMENT}",
    ),
    (
        re.compile(
            r"(?i)(\b(?:password|passwd|token|secret|api[_-]?key|session"
            r"|sessionid|phpsessid|jsessionid|sid)\s*[=:]\s*)"
            r"(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
        ),
        rf"\1{_REPLACEMENT}",
    ),
)

# UM-DR-34 §6.4 — key-aware structured redaction.  When a dictionary KEY
# is itself a recognized sensitive/credential field name, the VALUE is
# redacted regardless of its shape (an opaque session-cookie value under
# ``PHPSESSID`` never matches the string patterns above, but must not
# survive into diagnostics).  Mirrors the LLM-boundary cookie-name
# families (shared/untrusted_content.py) without importing them (this
# module is imported early and must stay dependency-free).
_SENSITIVE_KEY_RE = re.compile(
    r"(?:^|[_-])(authorization|cookie|cookies|set-cookie|password|passwd|"
    r"secret|token|api[-_]?key|access[-_]?key|session|"
    r"sessionid|session[-_]?id|phpsessid|jsessionid|asp[-_]?net[-_]?session[-_]?id|"
    r"connect[-_]?sid|sessid|sid|csrftoken|csrf[-_]?token|xsrf[-_]?token|"
    r"refresh[-_]?token|id[-_]?token|auth[-_]?token|"
    r"private[-_]?key|client[-_]?secret)",
    re.IGNORECASE,
)


def _is_sensitive_key(key: Any) -> bool:
    normalized = str(key).replace(" ", "_").replace(".", "_")
    return bool(_SENSITIVE_KEY_RE.search(normalized))


def redact_text(value: str) -> str:
    """Redact common credential and session-token forms from text."""
    redacted = value
    for pattern, replacement in _PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_value(value: Any) -> Any:
    """Recursively redact strings in JSON-like diagnostic values.

    UM-DR-34 §6.4: key-aware — a value stored under a sensitive
    dictionary key is redacted WHOLE, even when the value itself does
    not match any embedded-form pattern (e.g. an opaque session-cookie
    value under ``PHPSESSID``).  The checkpoint-specific redaction in
    ``graph/checkpoints.py`` (its own key-aware ``_redact_value``) is
    unchanged and remains authoritative for persisted channels.
    """
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            if _is_sensitive_key(key):
                redacted[redact_value(key)] = _REPLACEMENT
            else:
                redacted[redact_value(key)] = redact_value(item)
        return redacted
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    return value
