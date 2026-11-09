# src/webpent/remediation/locator.py
"""webpent.remediation.locator

Turn a finding into a precise, redaction-safe location description.

ADVISORY-ONLY: this module only reads fields of the finding it is given
(url, method, parameter name) and never invents a location that the
finding does not carry; missing pieces come back as ``None``. Redaction
contract: query VALUES are dropped and never reach the output, only
parameter NAMES do. Raw bodies, payloads, and credentials are not read.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from webpent.autonomous.hunt_contracts import redact


def _clean(value: Any, limit: int = 500) -> str | None:
    text = str(value).strip() if value is not None else ""
    if not text:
        return None
    return redact(text[:limit])


def locate(finding: dict[str, Any]) -> dict[str, str | None]:
    """Origin, path, method, and parameter name(s) of a finding.

    Every field is taken from the finding itself; a missing field is
    ``None``, never a guess. Query values are dropped: ``q=blood`` keeps
    the name ``q`` and loses the value.
    """
    url = _clean(finding.get("url"))
    origin: str | None = None
    path: str | None = None
    param_names: list[str] = []
    if url:
        parts = urlsplit(url)
        if parts.scheme and parts.netloc:
            # Redaction contract: userinfo (user:pass@) never reaches the
            # output, only the host[:port] does.
            host = parts.netloc.rpartition("@")[2]
            if host:
                origin = f"{parts.scheme}://{host}"
        if parts.path and parts.path != "/":
            path = parts.path
        for raw in parts.query.split("&"):
            name = raw.split("=", 1)[0].strip()
            if name:
                param_names.append(name)
    named = _clean(finding.get("target_param"))
    if named and named not in param_names:
        param_names.insert(0, named)
    method = _clean(finding.get("request_method"), limit=10)
    return {
        "origin": origin,
        "path": path,
        "method": method.upper() if method else None,
        "param": param_names[0] if param_names else None,
        "params": param_names[:20],
    }
