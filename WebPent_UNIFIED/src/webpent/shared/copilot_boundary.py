"""Fail-closed boundary for optional LLM research assistance."""

from __future__ import annotations

from typing import Any

from webpent.models.evidence import redact_sensitive

_FORBIDDEN_KEYS = frozenset(
    {"finding", "findings", "proof", "proof_bundle", "execute", "payload"}
)
_ALLOWED_KEYS = frozenset(
    {"action_class", "target_ref", "reason", "expected_information_gain", "evidence_refs"}
)
_ALLOWED_ACTION_CLASSES = frozenset(
    {"information_gathering", "passive_discovery", "research"}
)


def sanitize_copilot_suggestion(value: Any) -> dict[str, Any] | None:
    """Return a bounded research-only suggestion or None.

    The function deliberately rejects forbidden authority-bearing keys instead
    of silently dropping them, so callers can record a policy-denied decision.
    """
    if not isinstance(value, dict):
        return None
    keys = {str(key).strip().lower() for key in value}
    if keys & _FORBIDDEN_KEYS:
        return None
    if not {"action_class", "target_ref"}.issubset(keys):
        return None
    if str(value.get("action_class", "")).strip() not in _ALLOWED_ACTION_CLASSES:
        return None
    clean: dict[str, Any] = {}
    for key in _ALLOWED_KEYS:
        if key not in value:
            continue
        redacted, _ = redact_sensitive(value[key])
        if key == "evidence_refs":
            if not isinstance(redacted, (list, tuple, set)):
                return None
            clean[key] = [str(item)[:200] for item in redacted if str(item).strip()][:20]
        elif key == "expected_information_gain":
            try:
                clean[key] = max(0.0, min(1.0, float(redacted)))
            except (TypeError, ValueError):
                return None
        else:
            clean[key] = str(redacted)[:240]
    return clean


__all__ = ["sanitize_copilot_suggestion"]
