"""Deterministic scope-drift detection for discovered resources."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit


def _origin(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    port = parsed.port
    suffix = "" if port in {None, 80 if parsed.scheme == "http" else 443} else f":{port}"
    return f"{parsed.scheme}://{parsed.hostname.lower()}{suffix}"


def detect_scope_drift(
    discovered_urls: Iterable[str], declared_target: str
) -> dict[str, Any]:
    """Return a redacted, auditable drift event; never authorizes execution."""
    declared = _origin(declared_target)
    out_of_scope = sorted(
        {
            str(url)
            for url in discovered_urls
            if _origin(str(url)) and _origin(str(url)) != declared
        }
    )
    return {
        "detected": bool(out_of_scope),
        "requires_human_approval": bool(out_of_scope),
        "declared_origin": declared,
        "out_of_scope_origins": sorted({_origin(url) for url in out_of_scope}),
        "resource_count": len(out_of_scope),
    }


__all__ = ["detect_scope_drift"]
