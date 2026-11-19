"""Historical endpoint tracker (v82, Layer 1 / Task 3).

Parses CDX-style lines (``url originated ts`` or raw URLs) that the
operator's injected fetcher returns, extracts endpoints that existed
historically, and marks them as advisory discovery candidates for the
hunt's discovery merge. Old endpoints are *leads*: they still obey every
scope/authorization gate downstream, and nothing here executes anything.

A fetcher failure, empty body, or garbage line degrades to fewer
candidates, never an exception.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from webpent.autonomous.hunt_contracts import redact

MAX_LINES = 500
MAX_ENDPOINTS = 64

FetchText = Callable[[str], str]


def _origin_of(url: str) -> str:
    parts = urlsplit(str(url or "").strip())
    if not parts.scheme or not parts.hostname:
        return ""
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def parse_cdx(body: str, *, target_origin: str) -> list[str]:
    """Extract unique in-origin endpoint paths from CDX-ish text."""
    origin = _origin_of(target_origin)
    if not origin:
        return []
    paths: list[str] = []
    for line in str(body or "").splitlines()[:MAX_LINES]:
        text = redact(line.strip())
        if not text or text.startswith(" "):
            continue
        url = text.split()[0] if " " in text else text
        parts = urlsplit(url)
        if not parts.scheme or not parts.hostname:
            continue
        if f"{parts.scheme.lower()}://{parts.netloc.lower()}" != origin:
            continue
        path = parts.path.split("?", 1)[0].split("#", 1)[0]
        if not path.startswith("/") or len(path) > 256:
            continue
        if path not in paths:
            paths.append(path)
    return paths[:MAX_ENDPOINTS]


def historical_endpoints(
    target_url: str, *, fetch_text: FetchText, cdx_url: str = "cdx://wayback"
) -> dict[str, Any]:
    """Fetch (via the injected fetcher) and parse historical endpoints.

    The injected fetcher owns all network; this function stays pure with
    respect to transport and never raises past a ``fetch_failed`` reason.
    """
    try:
        body = fetch_text(cdx_url)
    except Exception as exc:
        return {"candidates": [], "reason": f"fetch_failed:{type(exc).__name__}", "advisory": True}
    if not isinstance(body, str):
        return {"candidates": [], "reason": "bad_body_type", "advisory": True}
    paths = parse_cdx(body, target_origin=target_url)
    return {
        "candidates": [
            {"path": path, "source": "wayback", "advisory": True} for path in paths
        ],
        "count": len(paths),
        "advisory": True,
    }
