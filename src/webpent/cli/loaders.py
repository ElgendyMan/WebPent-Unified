"""Safe, bounded loaders for operator-supplied scan input files.

The loaders are deliberately independent of Typer so they can be exercised by
unit tests and reused by non-CLI entry points. They never log secret values.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 2_000_000
MAX_PAYLOADS = 10_000
MAX_PROFILES = 32
MAX_COOKIES = 500
MAX_VALUE_CHARS = 16_384
MAX_OWNERSHIP_ITEMS = 256
MAX_HEADERS = 64
_ALLOWED_PROFILE_FIELDS = {
    "name",
    "role",
    "credentials",
    "username",
    "password",
    "email",
    "token",
    "cookies",
    "session_cookies",
    "headers",
    "owned_object_ids",
    "owned_ids",
    "owned_urls",
    "auth_type",
    "login_url",
    "protected_url",
    "validation_url",
    "login_fields",
    "surface_paths",
    "identity_paths",
    "register_if_unauthorized",
    "registration_url",
    "registration_fields",
    "registration_extra",
}


def _read_bounded(path: Path | str, *, label: str) -> str:
    """Read a UTF-8 file only when it is within the bounded input policy."""
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        raise ValueError(f"{label} file does not exist or is not a regular file")
    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise ValueError(f"cannot stat {label} file: {exc}") from exc
    if size > MAX_FILE_BYTES:
        raise ValueError(f"{label} file exceeds {MAX_FILE_BYTES} bytes")
    try:
        return resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"cannot read {label} file: {exc}") from exc


def _validate_secret_mapping(value: Any, *, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    result: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key).strip()
        if not key or len(key) > 128 or not isinstance(raw_value, str):
            raise ValueError(f"{label} contains an invalid key or non-string value")
        if len(raw_value) > MAX_VALUE_CHARS:
            raise ValueError(f"{label} contains a value exceeding {MAX_VALUE_CHARS} characters")
        result[key] = raw_value
    return result


def _validate_string_list(value: Any, *, label: str, max_items: int) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise ValueError(f"{label} must be an array of strings")
    if len(value) > max_items:
        raise ValueError(f"{label} exceeds {max_items} items")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{label} must contain only strings")
        item = item.strip()
        if not item or len(item) > MAX_VALUE_CHARS or item in seen:
            if not item or len(item) > MAX_VALUE_CHARS:
                raise ValueError(f"{label} contains an invalid item")
            continue
        seen.add(item)
        result.append(item)
    return result


def _validate_profile(raw_profile: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(raw_profile, dict):
        raise ValueError(f"{label} must be a JSON object")
    unknown = set(raw_profile) - _ALLOWED_PROFILE_FIELDS
    if unknown:
        fields = ", ".join(sorted(map(str, unknown)))
        raise ValueError(f"{label} contains unsupported fields: {fields}")

    profile: dict[str, Any] = {}
    nested = raw_profile.get("credentials")
    if nested is not None:
        profile["credentials"] = _validate_secret_mapping(nested, label=f"{label}.credentials")
    direct_secret = {
        key: raw_profile[key]
        for key in ("username", "password", "email", "token")
        if key in raw_profile
    }
    if direct_secret:
        profile.update(_validate_secret_mapping(direct_secret, label=label))
    has_cookie_session = any(
        isinstance(raw_profile.get(key), dict) and raw_profile[key]
        for key in ("cookies", "session_cookies", "headers")
    )
    has_direct_credentials = {"username", "password"}.issubset(profile)
    if not profile.get("credentials") and not has_direct_credentials and not has_cookie_session:
        raise ValueError(f"{label} must include credentials or a non-empty session")

    for key in ("name", "role"):
        if key in raw_profile:
            value = raw_profile[key]
            if not isinstance(value, str) or not value.strip() or len(value) > 128:
                raise ValueError(f"{label}.{key} must be a short non-empty string")
            profile[key] = value.strip()
    for key in (
        "auth_type",
        "login_url",
        "protected_url",
        "validation_url",
        "registration_url",
    ):
        if key in raw_profile:
            value = raw_profile[key]
            if not isinstance(value, str) or not value.strip() or len(value) > MAX_VALUE_CHARS:
                raise ValueError(f"{label}.{key} must be a bounded non-empty string")
            profile[key] = value.strip()
    if "login_fields" in raw_profile:
        profile["login_fields"] = _validate_secret_mapping(raw_profile["login_fields"], label=f"{label}.login_fields")
    if "register_if_unauthorized" in raw_profile:
        value = raw_profile["register_if_unauthorized"]
        if not isinstance(value, bool):
            raise ValueError(f"{label}.register_if_unauthorized must be a boolean")
        profile["register_if_unauthorized"] = value
    if "registration_fields" in raw_profile:
        profile["registration_fields"] = _validate_secret_mapping(
            raw_profile["registration_fields"], label=f"{label}.registration_fields"
        )
    if "registration_extra" in raw_profile:
        raw_extra = raw_profile["registration_extra"]
        if not isinstance(raw_extra, dict) or len(raw_extra) > 16:
            raise ValueError(f"{label}.registration_extra must be a JSON object with at most 16 fields")
        extra: dict[str, str | int | float | bool] = {}
        for raw_key, raw_value in raw_extra.items():
            key = str(raw_key).strip()
            if not key or len(key) > 128 or not isinstance(raw_value, (str, int, float, bool)):
                raise ValueError(f"{label}.registration_extra contains an invalid key or scalar value")
            if isinstance(raw_value, str) and len(raw_value) > MAX_VALUE_CHARS:
                raise ValueError(f"{label}.registration_extra contains an oversized string value")
            extra[key] = raw_value
        profile["registration_extra"] = extra
    for key in ("cookies", "session_cookies", "headers"):
        if key not in raw_profile:
            continue
        mapping = _validate_secret_mapping(raw_profile[key], label=f"{label}.{key}")
        if key == "headers" and len(mapping) > MAX_HEADERS:
            raise ValueError(f"{label}.headers exceeds {MAX_HEADERS} entries")
        if key != "headers" and len(mapping) > MAX_COOKIES:
            raise ValueError(f"{label}.{key} exceeds {MAX_COOKIES} entries")
        profile[key] = mapping
    for key in ("owned_object_ids", "owned_ids", "owned_urls"):
        if key in raw_profile:
            profile[key] = _validate_string_list(
                raw_profile[key], label=f"{label}.{key}", max_items=MAX_OWNERSHIP_ITEMS
            )
    if "surface_paths" in raw_profile:
        profile["surface_paths"] = _validate_string_list(
            raw_profile["surface_paths"], label=f"{label}.surface_paths", max_items=128
        )
    if "identity_paths" in raw_profile:
        profile["identity_paths"] = _validate_string_list(
            raw_profile["identity_paths"], label=f"{label}.identity_paths", max_items=8
        )
    return profile


def load_creds_file(path: Path | str) -> dict[str, Any]:
    """Load one credential mapping or a bounded set of named identity profiles.

    In addition to credentials, named profiles may carry session material and
    non-secret ownership provenance. Secret values are returned to the caller
    but are never printed here.
    """
    raw = _read_bounded(path, label="credentials")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"credentials file is not valid JSON: {exc.msg}") from exc

    if not isinstance(payload, dict):
        raise ValueError("credentials file must contain a JSON object")
    if "profiles" in payload:
        payload = payload["profiles"]
    if not isinstance(payload, dict) or not payload:
        raise ValueError("credentials file must contain at least one profile")
    if {"username", "password"}.issubset(payload) or "credentials" in payload:
        return _validate_profile(payload, label="credentials")
    if len(payload) > MAX_PROFILES:
        raise ValueError(f"credentials file exceeds {MAX_PROFILES} profiles")
    profiles: dict[str, dict[str, Any]] = {}
    for raw_name, raw_profile in payload.items():
        name = str(raw_name).strip()
        if not name or len(name) > 128:
            raise ValueError("credentials profile names must be non-empty and short")
        profile = _validate_profile(raw_profile, label=f"profile '{name}'")
        profile.setdefault("name", name)
        profiles[name] = profile
    return profiles


def load_cookie_file(path: Path | str) -> dict[str, str]:
    """Load cookies from a JSON object or Netscape cookie-jar text file."""
    raw = _read_bounded(path, label="cookie")
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"cookie file is not valid JSON: {exc.msg}") from exc
        cookies = _validate_secret_mapping(payload, label="cookies")
    else:
        cookies = {}
        for line_number, line in enumerate(raw.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 7:
                raise ValueError(f"invalid Netscape cookie row at line {line_number}")
            name, value = parts[5].strip(), parts[6].strip()
            if not name or len(name) > 256 or len(value) > MAX_VALUE_CHARS:
                raise ValueError(f"invalid cookie at Netscape line {line_number}")
            cookies[name] = value
    if len(cookies) > MAX_COOKIES:
        raise ValueError(f"cookie file exceeds {MAX_COOKIES} cookies")
    return cookies


def load_payload_file(path: Path | str) -> list[str]:
    """Load bounded, non-empty, de-duplicated payload lines from a text file."""
    raw = _read_bounded(path, label="payload")
    payloads: list[str] = []
    seen: set[str] = set()
    for line_number, line in enumerate(raw.splitlines(), 1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if len(value) > MAX_VALUE_CHARS:
            raise ValueError(f"payload at line {line_number} exceeds {MAX_VALUE_CHARS} characters")
        if value not in seen:
            seen.add(value)
            payloads.append(value)
        if len(payloads) > MAX_PAYLOADS:
            raise ValueError(f"payload file exceeds {MAX_PAYLOADS} entries")
    return payloads


__all__ = ["load_creds_file", "load_cookie_file", "load_payload_file"]
