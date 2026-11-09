from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

import yaml

from .models import ScopeLimits, ScopePolicy, ScopeRule


class ScopeParseError(ValueError):
    """Invalid, ambiguous, or empty operator scope."""


def _boolean(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "yes", "1", "on"}:
        return True
    if text in {"false", "no", "0", "off"}:
        return False
    raise ScopeParseError("boolean scope option must be true or false")


def _port(value: Any) -> int | tuple[int, int] | None:
    if value is None or value == "":
        return None
    if isinstance(value, (list, tuple)) and len(value) == 2:
        low, high = int(value[0]), int(value[1])
        if not (1 <= low <= high <= 65535):
            raise ScopeParseError("invalid port range")
        return low, high
    text = str(value).strip()
    if "-" in text:
        parts = text.split("-", 1)
        return _port([parts[0], parts[1]])
    number = int(text)
    if not 1 <= number <= 65535:
        raise ScopeParseError("invalid port")
    return number


def _path(value: Any) -> str | None:
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()
    if not text.startswith("/") or any(ord(ch) > 127 for ch in text):
        raise ScopeParseError("path must be an absolute ASCII path")
    return text.rstrip("/") or "/"


def _rule_from_item(item: Any, *, allow_default: bool, source: str) -> ScopeRule:
    if isinstance(item, str):
        text = item.strip()
        if not text:
            raise ScopeParseError("empty scope rule")
        parsed = urlsplit(text if "://" in text else f"//{text}")
        value = text
        kind = "wildcard" if "*" in (parsed.hostname or text) else "url" if "://" in text else "domain"
        return ScopeRule(value=value, kind=kind, allow=allow_default, port=parsed.port, source=source)
    if not isinstance(item, dict):
        raise ScopeParseError("scope rule must be a string or object")
    raw = item.get("value") or item.get("url") or item.get("domain") or item.get("host") or item.get("asset_identifier") or item.get("target")
    if not raw:
        raise ScopeParseError("scope rule is missing value")
    raw = str(raw).strip()
    kind = str(item.get("kind") or item.get("asset_type") or ("domain" if any(key in item for key in ("domain", "host")) else "wildcard" if "*" in raw else "url")).lower()
    if kind in {"host", "hostname", "domain"}:
        kind = "wildcard" if "*" in raw else "domain"
    if kind in {"cidr", "ip_range", "ip"}:
        kind = "cidr"
    methods = item.get("allowed_methods") if "allowed_methods" in item else item.get("methods") or ()
    if isinstance(methods, str):
        methods = (methods,)
    allow_value = item.get("allow", allow_default)
    return ScopeRule(
        value=raw,
        kind=kind,
        allow=_boolean(allow_value, default=allow_default),
        protocol=str(item.get("protocol") or item.get("scheme") or "").lower() or None,
        port=_port(item["port"] if "port" in item else item.get("ports")),
        path=_path(item.get("path") or item.get("path_prefix")),
        source=str(item.get("source") or source)[:120],
        instruction=str(item.get("instruction") or item.get("instructions") or "")[:500],
        max_severity=str(item.get("max_severity") or item.get("severity") or "").lower() or None,
        allowed_methods=frozenset(str(m).upper() for m in methods),
    )


def _walk_structured(document: Any, *, source: str) -> tuple[list[ScopeRule], list[ScopeRule], list[str], dict[str, Any]]:
    """Extract common HackerOne/Bugcrowd/manual shapes without target-specific execution."""
    if not isinstance(document, dict):
        raise ScopeParseError("structured scope document must be an object")
    allows: list[ScopeRule] = []
    denies: list[ScopeRule] = []
    instructions: list[str] = []
    options: dict[str, Any] = {}
    for key in ("instruction", "instructions", "notes", "description"):
        value = document.get(key)
        if isinstance(value, str) and value.strip():
            instructions.append(value.strip()[:500])
        elif isinstance(value, list):
            instructions.extend(str(x).strip()[:500] for x in value if str(x).strip())
    for key in ("rules", "scope", "targets", "structured_scopes", "assets"):
        value = document.get(key)
        if isinstance(value, dict):
            nested_allow, nested_deny, nested_i, nested_o = _walk_structured(value, source=source)
            allows.extend(nested_allow); denies.extend(nested_deny); instructions.extend(nested_i); options.update(nested_o)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and any(k in item for k in ("out_of_scope", "excluded", "exclude")):
                    for denied in item.get("out_of_scope") or item.get("excluded") or item.get("exclude") or ():
                        denies.append(_rule_from_item(denied, allow_default=False, source=source))
                    continue
                rule = _rule_from_item(item, allow_default=True, source=source)
                (allows if rule.allow else denies).append(rule)
    for key in ("in_scope", "in-scope", "included", "allow", "allowed"):
        value = document.get(key)
        if isinstance(value, (str, dict)):
            value = [value]
        if isinstance(value, list):
            allows.extend(_rule_from_item(item, allow_default=True, source=source) for item in value)
    for key in ("out_of_scope", "out-of-scope", "excluded", "exclude", "blacklisted"):
        value = document.get(key)
        if isinstance(value, (str, dict)):
            value = [value]
        if isinstance(value, list):
            denies.extend(_rule_from_item(item, allow_default=False, source=source) for item in value)
    options.update(document.get("limits") or {})
    for key in ("max_requests_per_second", "max_concurrent_requests", "max_violations", "no_destructive", "blacklisted_payloads"):
        if key in document:
            options[key] = document[key]
    return allows, denies, instructions, options


def _parse_plain(text: str, *, source: str) -> tuple[list[ScopeRule], list[ScopeRule], list[str], dict[str, Any]]:
    allows: list[ScopeRule] = []
    denies: list[ScopeRule] = []
    instructions: list[str] = []
    options: dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lowered = line.lower()
        if lowered.startswith(("instruction:", "note:")):
            instructions.append(line.split(":", 1)[1].strip()[:500]); continue
        if lowered.startswith(("max_requests_per_second:", "max-concurrent:", "max_concurrent_requests:")):
            options["max_requests_per_second" if "second" in lowered else "max_concurrent_requests"] = line.split(":", 1)[1].strip(); continue
        if lowered.startswith(("exclude:", "out-of-scope:", "out_of_scope:", "deny:")):
            value = line.split(":", 1)[1].strip()
            denies.append(_rule_from_item(value, allow_default=False, source=source)); continue
        if lowered.startswith(("include-path:", "exclude-path:")):
            raise ScopeParseError("path-only rules require a structured YAML/JSON rule")
        allows.append(_rule_from_item(line, allow_default=True, source=source))
    return allows, denies, instructions, options


def parse_scope_text(text: str, *, source: str = "operator") -> ScopePolicy:
    raw = str(text or "")
    if not raw.strip():
        raise ScopeParseError("scope document is empty")
    document: Any = None
    structured = False
    try:
        document = json.loads(raw)
        structured = isinstance(document, (dict, list))
    except json.JSONDecodeError:
        try:
            document = yaml.safe_load(raw)
            structured = isinstance(document, (dict, list))
        except yaml.YAMLError:
            structured = False
    if structured and isinstance(document, list):
        document = {"in_scope": document}
    if structured and isinstance(document, dict):
        allows, denies, instructions, options = _walk_structured(document, source=source)
    else:
        allows, denies, instructions, options = _parse_plain(raw, source=source)
    if not allows:
        raise ScopeParseError("scope document must contain at least one in-scope rule")
    try:
        limits = ScopeLimits(
            max_requests_per_second=float(options.get("max_requests_per_second", 1.0)),
            max_concurrent_requests=int(options.get("max_concurrent_requests", 1)),
            max_violations=int(options.get("max_violations", 5)),
            no_destructive=_boolean(options.get("no_destructive"), default=True),
        )
    except (TypeError, ValueError, OverflowError) as exc:
        raise ScopeParseError(f"invalid scope limits: {exc}") from exc
    blacklisted = tuple(str(x)[:200] for x in (options.get("blacklisted_payloads") or ()))
    normalized = [r.as_dict() for r in (*allows, *denies)]
    fingerprint = "sha256:" + hashlib.sha256(json.dumps({"rules": normalized, "limits": limits.as_dict(), "blacklisted": blacklisted}, sort_keys=True).encode()).hexdigest()
    return ScopePolicy(tuple(allows + denies), limits, blacklisted, source, tuple(dict.fromkeys(instructions)), fingerprint)


def parse_scope_file(path: str | Path) -> ScopePolicy:
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise ScopeParseError("scope file not found")
    if file_path.stat().st_size > 1_000_000:
        raise ScopeParseError("scope file exceeds 1 MiB")
    return parse_scope_text(file_path.read_text(encoding="utf-8"), source=str(file_path.name))


__all__ = ["ScopeParseError", "parse_scope_file", "parse_scope_text"]
