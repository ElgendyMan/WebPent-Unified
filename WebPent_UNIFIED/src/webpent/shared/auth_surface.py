"""Two-layer recon primitives: pre-auth anonymous snapshot + surface diff.

SCENARIO CONTRACT (operator workflow step 5 + step 12):

* **Pre-auth snapshot** — before any login is attempted the tool fetches the
  target URL anonymously ONCE and records a bounded, redaction-safe baseline
  (status, safe header subset, page title, links, forms). This is the
  reference the authenticated surface is later compared against; it is also
  the honest "what could an anonymous visitor see" record in the report.
* **Surface diff** — after the authenticated crawl, every crawled endpoint is
  classified ``both`` (visible anonymously too), ``auth_only`` (appeared only
  once a session existed — priority fuel for BAC/IDOR hypotheses), or the
  reverse ``anonymous_only`` note. Classification is string-level on the
  URL path, deterministic, bounded, and carries NO secret material.

Both operations are best-effort by design: a failed snapshot degrades to a
declared gap (``status: "error"``) and never blocks the engagement.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit

logger = logging.getLogger(__name__)

__all__ = [
    "AUTH_SURFACE_SCHEMA_VERSION",
    "MAX_SNAPSHOT_LINKS",
    "capture_anonymous_snapshot",
    "diff_auth_surface",
]

AUTH_SURFACE_SCHEMA_VERSION = "auth-surface-v1"
MAX_SNAPSHOT_LINKS = 50
MAX_SNAPSHOT_FORMS = 20
MAX_BODY_SAMPLE = 20_000
_SNAPSHOT_TIMEOUT = 8.0

# Header allowlist: structural metadata only. Set-Cookie is deliberately
# excluded — the snapshot must never become a secret-bearing artifact.
_SNAPSHOT_SAFE_HEADERS = (
    "content-type",
    "server",
    "x-powered-by",
    "www-authenticate",
    "content-security-policy",
    "allow",
)

_HREF_RE = re.compile(
    r"""(?:href|src|action)\s*=\s*["']([^"'#\s]+)["']""",
    re.IGNORECASE,
)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_FORM_RE = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_FORM_METHOD_RE = re.compile(r"""method\s*=\s*["']([^"']*)["']""", re.IGNORECASE)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _same_origin(url: str, base: str) -> bool:
    try:
        candidate = urlsplit(url)
        origin = urlsplit(base)
    except ValueError:
        return False
    return (
        candidate.scheme.lower() == origin.scheme.lower()
        and (candidate.hostname or "") == (origin.hostname or "")
    )


def capture_anonymous_snapshot(target_url: str) -> dict[str, Any]:
    """One bounded anonymous GET of the target — the pre-login baseline.

    Never raises. On any failure returns a record with ``status: "error"``
    so the run keeps an honest declared gap instead of a silent one.
    """
    record: dict[str, Any] = {
        "schema_version": AUTH_SURFACE_SCHEMA_VERSION,
        "status": "ok",
        "url": str(target_url),
        "captured_at": _now_iso(),
        "authenticated": False,
    }
    try:

        from webpent.shared.http import make_safe_httpx_client

        with make_safe_httpx_client(
            follow_redirects=True,
            timeout=_SNAPSHOT_TIMEOUT,
        ) as client:
            response = client.get(str(target_url))
        record["status_code"] = int(response.status_code)
        record["headers"] = {
            name: value[:200]
            for name, value in response.headers.items()
            if name.lower() in _SNAPSHOT_SAFE_HEADERS
        }
        body = response.text or ""
        record["body_sha256"] = f"sha256:{hashlib.sha256(body.encode('utf-8', 'replace')).hexdigest()}"
        record["body_bytes"] = len(body.encode("utf-8", "replace"))
        title_match = _TITLE_RE.search(body[:MAX_BODY_SAMPLE])
        record["title"] = title_match.group(1).strip()[:200] if title_match else ""

        links: list[str] = []
        seen: set[str] = set()
        base = str(response.url)
        for match in _HREF_RE.finditer(body[:MAX_BODY_SAMPLE]):
            raw = match.group(1).strip()
            if raw.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            absolute = urljoin(base, raw)
            if not _same_origin(absolute, base):
                continue
            path = urlsplit(absolute).path or "/"
            if path in seen:
                continue
            seen.add(path)
            links.append(path)
            if len(links) >= MAX_SNAPSHOT_LINKS:
                break
        record["links"] = links

        forms: list[dict[str, str]] = []
        for form_tag in _FORM_RE.finditer(body[:MAX_BODY_SAMPLE]):
            tag = form_tag.group(0)
            action = _FORM_ACTION_RE.search(tag)
            method = _FORM_METHOD_RE.search(tag)
            forms.append(
                {
                    "action": (action.group(1) if action else "")[:200],
                    "method": (method.group(1) if method else "get").lower()[:10],
                }
            )
            if len(forms) >= MAX_SNAPSHOT_FORMS:
                break
        record["forms"] = forms
        record["link_count"] = len(links)
        record["form_count"] = len(forms)
    except Exception as exc:  # noqa: BLE001 — snapshot is best-effort by contract
        logger.warning(
            "Pre-auth anonymous snapshot failed (declared gap): %s",
            type(exc).__name__,
        )
        record["status"] = "error"
        record["error"] = type(exc).__name__
    return record


def _canonical_path(url: str) -> str:
    try:
        return urlsplit(str(url or "")).path or "/"
    except ValueError:
        return "/"


def diff_auth_surface(
    snapshot: dict[str, Any] | None,
    endpoints: list[Any],
    *,
    max_records: int = 200,
) -> dict[str, Any]:
    """Classify crawled endpoints against the pre-auth anonymous snapshot.

    Returns a redaction-safe projection:
      ``records``: bounded list of {path, url, auth_visibility},
      ``counts``: {both, auth_only, anonymous_only},
      ``auth_only_endpoints``: bounded URL list for hypothesis generation.
    A missing/errored snapshot yields ``status: "unavailable"`` — the diff
    is then honestly absent rather than fabricated.
    """
    projection: dict[str, Any] = {
        "schema_version": AUTH_SURFACE_SCHEMA_VERSION,
        "status": "unavailable",
        "counts": {"both": 0, "auth_only": 0, "anonymous_only": 0},
        "records": [],
        "auth_only_endpoints": [],
    }
    if not isinstance(snapshot, dict) or snapshot.get("status") != "ok":
        return projection

    anonymous_paths = {
        _canonical_path(link) for link in (snapshot.get("links") or [])
    }
    projection["status"] = "ok"
    projection["anonymous_link_count"] = len(anonymous_paths)

    records: list[dict[str, Any]] = []
    auth_only: list[str] = []
    counts = projection["counts"]
    seen_paths: set[str] = set()
    for endpoint in endpoints or []:
        if isinstance(endpoint, str):
            url = endpoint
        elif isinstance(endpoint, dict):
            url = str(endpoint.get("url") or endpoint.get("endpoint") or "")
        else:
            continue
        if not url:
            continue
        path = _canonical_path(url)
        if path in seen_paths:
            continue
        seen_paths.add(path)
        if path in anonymous_paths:
            visibility = "both"
            counts["both"] += 1
        else:
            visibility = "auth_only"
            counts["auth_only"] += 1
            if len(auth_only) < 25:
                auth_only.append(url)
        if len(records) < max_records:
            records.append({"path": path, "url": url, "auth_visibility": visibility})

    anonymous_only = sorted(
        path for path in anonymous_paths if path not in seen_paths
    )
    counts["anonymous_only"] = len(anonymous_only)

    projection["records"] = records
    projection["auth_only_endpoints"] = auth_only
    projection["anonymous_only_paths"] = anonymous_only[:25]
    return projection
