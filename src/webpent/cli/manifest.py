"""Local, versioned engagement manifests used by additive CLI commands.

The manifest is an operator-controlled coordination file. It deliberately
stores identifiers, scope, findings metadata, and evidence references only;
credentials, cookies, raw response bodies, and payloads are rejected or
redacted before persistence.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MANIFEST_FILENAME = "webpent-engagement.json"
SCHEMA_VERSION = 1
_SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|session)"
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def manifest_path(value: str | Path | None = None) -> Path:
    path = Path(value or MANIFEST_FILENAME).expanduser()
    if path.exists() and path.is_dir():
        return path / MANIFEST_FILENAME
    if str(path).endswith(("/", "\\")):
        return path / MANIFEST_FILENAME
    return path


def default_manifest(name: str) -> dict[str, Any]:
    clean_name = str(name).strip()
    if not clean_name or len(clean_name) > 96:
        raise ValueError("engagement name must be 1-96 characters")
    return {
        "schema_version": SCHEMA_VERSION,
        "engagement": {
            "name": clean_name,
            "created_at": now_iso(),
            "updated_at": now_iso(),
        },
        "scope": [],
        "findings": [],
        "evidence_refs": [],
        "investigations": [],
        "graph": {"mental_model": {}, "attack_graph": {}},
        "runs": [],
    }


def _redact_value(value: Any, *, key: str = "") -> Any:
    if _SECRET_KEY_RE.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact_value(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(item, key=key) for item in value]
    if isinstance(value, str) and len(value) > 4096:
        return value[:4096] + "...[TRUNCATED]"
    return value


def load_manifest(value: str | Path | None = None) -> tuple[Path, dict[str, Any]]:
    path = manifest_path(value)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"manifest not found: {path}") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read manifest {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("manifest root must be a JSON object")
    version = payload.get("schema_version")
    if version != SCHEMA_VERSION:
        raise ValueError(f"unsupported manifest schema_version: {version!r}")
    for key, default in (
        ("scope", []),
        ("findings", []),
        ("evidence_refs", []),
        ("investigations", []),
        ("runs", []),
    ):
        if not isinstance(payload.get(key, default), list):
            raise ValueError(f"manifest field {key!r} must be a JSON array")
    return path, _redact_value(payload)


def save_manifest(
    path_or_payload: str | Path | dict[str, Any], payload: dict[str, Any] | None = None
) -> Path:
    if payload is None:
        if not isinstance(path_or_payload, dict):
            raise TypeError("save_manifest(payload) requires a dict")
        path = manifest_path(None)
        document = path_or_payload
    else:
        path = manifest_path(path_or_payload)  # type: ignore[arg-type]
        document = payload
    if not isinstance(document, dict):
        raise ValueError("manifest payload must be a JSON object")
    document = _redact_value(document)
    document.setdefault("schema_version", SCHEMA_VERSION)
    document.setdefault("scope", [])
    document.setdefault("findings", [])
    document.setdefault("evidence_refs", [])
    document.setdefault("investigations", [])
    document.setdefault("runs", [])
    document.setdefault("graph", {"mental_model": {}, "attack_graph": {}})
    document.setdefault("engagement", {})
    document["engagement"]["updated_at"] = now_iso()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)
    return path


def normalize_scope_url(value: str) -> dict[str, str]:
    raw = str(value).strip()
    if not raw.startswith(("http://", "https://")):
        raise ValueError("scope value must start with http:// or https://")
    parsed = urlsplit(raw)
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("scope URL must include a host and no embedded credentials")
    if parsed.fragment:
        raise ValueError("scope URL must not include a fragment")
    query = [
        (key, "[REDACTED]" if _SECRET_KEY_RE.search(key) else val)
        for key, val in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    normalized = urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            urlencode(query, safe="[]"),
            "",
        )
    )
    return {"url": normalized, "host": parsed.hostname.lower(), "scheme": parsed.scheme.lower()}


def add_scope_entry(document: dict[str, Any], value: str) -> dict[str, str]:
    entry = normalize_scope_url(value)
    scope = document.setdefault("scope", [])
    if any(isinstance(item, dict) and item.get("url") == entry["url"] for item in scope):
        return entry
    scope.append(entry)
    return entry


def remove_scope_entry(document: dict[str, Any], value: str) -> bool:
    target = normalize_scope_url(value)["url"]
    scope = document.setdefault("scope", [])
    before = len(scope)
    document["scope"] = [
        item for item in scope if not (isinstance(item, dict) and item.get("url") == target)
    ]
    return len(document["scope"]) != before


def redacted_evidence_refs(document: dict[str, Any]) -> list[dict[str, Any]]:
    refs = document.get("evidence_refs", [])
    return [item for item in refs if isinstance(item, dict)]
