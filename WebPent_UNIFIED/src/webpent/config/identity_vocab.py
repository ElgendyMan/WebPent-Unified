# src/webpent/config/identity_vocab.py
"""Loader for the generic identity-resolution vocabularies (data-driven).

The identity strategy ladder must stay general and autonomous: every
extensible list (probe paths, self actions, claim keys, id-suffix shapes,
transport-variant names, bounds) lives in ``identity_vocab.json`` next to
this module so a new target needs NO code edits.  The loader is fail-soft:
if the data file is missing or malformed the safe built-in defaults below
are used and a ``source`` marker records which path was taken.  Values are
bounded on load; oversized or wrong-typed entries are rejected, never
silently truncated.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

_DATA_FILE = Path(__file__).resolve().parent / "identity_vocab.json"
_OVERRIDE_ENV = "WEBPENT_IDENTITY_VOCAB_PATH"

_MAX_LIST_ITEMS = 64
_MAX_STRING_LENGTH = 512

_LIST_FIELDS = (
    "probe_paths",
    "self_actions",
    "user_identity_keys",
    "id_key_suffixes",
    "id_key_short_forms",
    "negative_id_keys",
    "identity_claim_keys",
    "email_claim_keys",
    "query_token_names",
    "cookie_token_names",
)
_INT_FIELDS = {
    "max_probe_paths": (1, 32),
    "max_transport_retries_per_path": (0, 16),
    "max_anonymous_shape_retries": (0, 8),
    "max_crawl_self_paths": (0, 64),
    "max_login_artifact_depth": (1, 8),
    "max_login_artifact_nodes": (16, 4096),
}

_BUILTIN_DEFAULTS: dict[str, Any] = {
    "probe_paths": [
        "/identity/api/v2/user/me",
        "/identity/api/v2/user/current",
        "/identity/api/me",
        "/identity/api/v2/user/dashboard",
    ],
    "self_actions": ["dashboard", "me", "current", "profile", "details", "self", "account", "whoami"],
    "user_identity_keys": ["userid", "user_id", "user-id", "subject_id", "subjectid"],
    "id_key_suffixes": ["id", "uid", "no", "number", "num"],
    "id_key_short_forms": ["id", "bid", "uid", "no", "num"],
    "negative_id_keys": ["valid", "void", "solid", "rapid", "fluid", "humid"],
    "identity_claim_keys": ["sub", "userId", "user_id", "userid", "id", "uid"],
    "email_claim_keys": ["email", "mail", "user_email", "userEmail"],
    "query_token_names": ["token", "access_token", "jwt", "auth_token"],
    "cookie_token_names": ["token", "jwt", "auth", "session"],
    "max_probe_paths": 10,
    "max_transport_retries_per_path": 8,
    "max_anonymous_shape_retries": 3,
    "max_crawl_self_paths": 8,
    "max_login_artifact_depth": 4,
    "max_login_artifact_nodes": 256,
}


def _clean_string_list(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    values: list[str] = []
    for item in raw[:_MAX_LIST_ITEMS]:
        if not isinstance(item, str):
            continue
        text = item.strip()
        if text and len(text) <= _MAX_STRING_LENGTH and text not in values:
            values.append(text)
    return values


def _clean_int(raw: Any, bounds: tuple[int, int]) -> int | None:
    if isinstance(raw, bool) or not isinstance(raw, int):
        return None
    low, high = bounds
    return raw if low <= raw <= high else None


def _load_payload(path: Path) -> Mapping[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, Mapping) else None


@lru_cache(maxsize=1)
def _load_cached() -> Mapping[str, Any]:
    merged: dict[str, Any] = {key: value for key, value in _BUILTIN_DEFAULTS.items() if key in _LIST_FIELDS}
    merged.update({key: value for key, value in _BUILTIN_DEFAULTS.items() if key in _INT_FIELDS})
    source = "builtin_defaults"
    candidates = [_DATA_FILE]
    override = str(os.environ.get(_OVERRIDE_ENV, "") or "").strip()
    if override:
        candidates.insert(0, Path(override))
    for path in candidates:
        data = _load_payload(path)
        if data is None:
            continue
        for field_name in _LIST_FIELDS:
            cleaned = _clean_string_list(data.get(field_name))
            if cleaned:
                merged[field_name] = cleaned
        for field_name, bounds in _INT_FIELDS.items():
            cleaned = _clean_int(data.get(field_name), bounds)
            if cleaned is not None:
                merged[field_name] = cleaned
        source = f"data_file:{path.name}"
        break
    merged["source"] = source
    return merged


def load_identity_vocab() -> Mapping[str, Any]:
    """Return the bounded, merged identity vocabularies (cached)."""
    return _load_cached()


def reload_identity_vocab() -> Mapping[str, Any]:
    """Drop the cache and reload (used by tests and operators)."""
    _load_cached.cache_clear()
    return _load_cached()


__all__ = ["load_identity_vocab", "reload_identity_vocab"]
