"""V7 Phase 2 — Live Reference Lookup with allowlist + bounded lookups."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus, urlsplit

logger = logging.getLogger(__name__)
MAX_LOOKUPS_PER_FINDING = 3
MAX_REFERENCE_CHARS = 4000
_MANIFEST_PATH = Path(__file__).resolve().parents[3] / "knowledge_sources.yaml"
_lookup_count: dict[str, int] = {}


def _load_allowlist() -> list[dict[str, Any]]:
    try:
        import yaml

        if not _MANIFEST_PATH.is_file():
            return []
        with open(_MANIFEST_PATH) as f:
            return yaml.safe_load(f).get("live_references", [])
    except Exception:
        return []


def _path_is_boundary_match(path: str, prefix: str) -> bool:
    """Match path prefixes only on segment boundaries (``/api`` != ``/apix``)."""
    normalized_path = path or "/"
    normalized_prefix = str(prefix or "/").strip() or "/"
    if not normalized_prefix.startswith("/"):
        normalized_prefix = f"/{normalized_prefix}"
    normalized_prefix = normalized_prefix.rstrip("/") or "/"
    return normalized_prefix == "/" or normalized_path in {
        normalized_prefix,
        f"{normalized_prefix}/",
    } or normalized_path.startswith(f"{normalized_prefix}/")


def _is_url_allowed(url: str, allowlist: list[dict[str, Any]]) -> bool:
    """Require exact canonical origin plus an optional segment-boundary path."""
    try:
        parsed = urlsplit(url)
        if parsed.username is not None or parsed.password is not None:
            return False
        from webpent.shared.engagement_scope import OriginPolicy
    except (TypeError, ValueError):
        return False

    for entry in allowlist:
        base = str(entry.get("base_url", "") or "").strip()
        if not base:
            continue
        try:
            base_policy = OriginPolicy.from_url(base)
        except (TypeError, ValueError):
            continue
        if not base_policy.allows(url):
            continue
        allowed_paths = entry.get("allowed_paths", [])
        if not allowed_paths:
            return True
        if any(_path_is_boundary_match(parsed.path or "/", str(path)) for path in allowed_paths):
            return True
    return False


def reference_lookup(
    query: str, finding_id: str, *, source: str = "hacktricks"
) -> str:
    count = _lookup_count.get(finding_id, 0)
    if count >= MAX_LOOKUPS_PER_FINDING:
        logger.info(
            "reference_lookup: budget exceeded for %s (%d/%d)",
            finding_id,
            count,
            MAX_LOOKUPS_PER_FINDING,
        )
        return ""
    _lookup_count[finding_id] = count + 1
    allowlist = _load_allowlist()
    if not allowlist:
        return ""
    entry = next((e for e in allowlist if e.get("name") == source), None)
    if not entry:
        return ""
    base_url = entry.get("base_url", "")
    # V7 Ready-For-Kali P0 FIX: query.replace(' ', '+') is not proper
    # URL encoding. `query` is typically derived from a skill name or
    # finding title/description -- content that can itself be
    # influenced by the scanned target's responses. An unescaped `&`,
    # `#`, or `%` in `query` could inject extra query parameters or
    # break the URL structure. Fixed with quote_plus (proper encoding,
    # including spaces -> '+').
    search_url = f"{base_url}/search?q={quote_plus(query)}" if source == "hacktricks" else base_url
    if not _is_url_allowed(search_url, allowlist):
        return ""
    try:
        from webpent.shared.http import make_safe_httpx_client

        # V7 Ready-For-Kali P0 FIX: removed verify=True. This request
        # goes to a FIXED, supposedly-trusted reference site (from
        # knowledge_sources.yaml), not an arbitrary pentest target —
        # there is no legitimate reason to accept an invalid TLS cert
        # here. Disabling cert verification for a "trusted reference"
        # lookup opens exactly the kind of MITM-spoofed-content risk
        # this whole knowledge-source system is supposed to guard
        # against (feeding the LLM fake "trusted" reference material).
        with make_safe_httpx_client(timeout=15.0, follow_redirects=True) as c:
            resp = c.get(search_url)
        # The transport may follow redirects, so authorize the final URL too.
        # Rejecting an off-allowlist final origin is fail-closed even when the
        # initial search URL was canonical.
        if resp.status_code != 200 or not _is_url_allowed(str(resp.url), allowlist):
            return ""
        content = resp.text[:MAX_REFERENCE_CHARS]
    except Exception as e:
        logger.debug("reference_lookup: %s", e)
        return ""
    # V7 Ready-For-Kali P0 FIX: use safe_prompt_format (the same
    # sanitization every other untrusted-content path in this codebase
    # goes through — structural cleanup + injection-defense framing),
    # not the raw _UNTRUSTED_WRAPPER.format() which skips it.
    from webpent.shared.llm import safe_prompt_format

    framed = safe_prompt_format("{content}", content=content)
    logger.info(
        "reference_lookup: %d chars from %s for %s (%d/%d)",
        len(content),
        source,
        finding_id,
        count + 1,
        MAX_LOOKUPS_PER_FINDING,
    )
    return framed


def reset_lookup_budget(finding_id: str | None = None) -> None:
    if finding_id:
        _lookup_count.pop(finding_id, None)
    else:
        _lookup_count.clear()
