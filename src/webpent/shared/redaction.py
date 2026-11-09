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
            r"(?i)(\b(?:password|passwd|token|secret|api[_-]?key|session)\s*[=:]\s*)"
            r"(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
        ),
        rf"\1{_REPLACEMENT}",
    ),
)


def redact_text(value: str) -> str:
    """Redact common credential and session-token forms from text."""
    redacted = value
    for pattern, replacement in _PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_value(value: Any) -> Any:
    """Recursively redact strings in JSON-like diagnostic values."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {redact_value(key): redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    return value
