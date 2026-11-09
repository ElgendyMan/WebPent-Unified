"""Deep JavaScript file analyzer (v82, Layer 1 / Task 4).

Static, regex-based analysis of JS source text supplied by the operator
(no fetching here). Extracts advisory leads only:

* hardcoded API-key *candidates* (shape matches, values are redacted and
  never echoed back),
* commented-out auth/permission checks,
* dev/staging/internal URLs,
* feature-flag assignments,
* internal API versions (v0/v1/v2).

Candidates are leads for the operator and for advisory seed merging; they
are never findings and never promoted. Everything is redacted and
bounded.
"""

from __future__ import annotations

import re
from typing import Any

from webpent.autonomous.hunt_contracts import redact

MAX_SOURCE = 200_000
MAX_LEADS_PER_KIND = 12

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,64})['\"]",
        r"\b(?:secret|token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,64})['\"]",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bsk_live_[0-9a-zA-Z]{16,48}\b",
    )
)

_COMMENTED_AUTH = re.compile(
    r"//[^\n]*(?:if\s*\(\s*!?is[A-Z]\w*|verify(?:Token|Jwt|Session)|check(?:Auth|Permission)|requireAdmin)[^\n]*",
    re.IGNORECASE,
)
_DEV_URL = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|[\w.-]+\.local|[\w.-]+\.(?:dev|staging|internal|test))\b[^\s'\"<>]*",
    re.IGNORECASE,
)
_FEATURE_FLAG = re.compile(
    r"(?:flags?\[|flags?\.|FEATURES\[|hasFeature\()['\"]?([\w.\-]+)['\"]?",
    re.IGNORECASE,
)
_API_VERSION = re.compile(r"/api/v(?:0|1|2)\b[\w/\-]*")


def _clip(items: list[str]) -> list[str]:
    return items[:MAX_LEADS_PER_KIND]


def analyze_javascript(source: str) -> dict[str, Any]:
    """Static advisory analysis of one JS source text; never raises.

    Secret *detection* runs on the raw source (redaction would destroy
    the key shapes), but only a fingerprint (first 4 chars + length) is
    ever stored; every other lead kind is extracted from the redacted
    text.
    """
    raw = str(source or "")[:MAX_SOURCE]
    if not raw:
        return {"leads": {}, "scanned": False, "advisory": True}
    text = redact(raw)

    api_keys: list[str] = []
    for pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(raw):
            value = match.group(1) if match.groups() else match.group(0)
            # Store only a fingerprint, never the value itself.
            api_keys.append(f"{value[:4]}...len{len(value)}")
    api_keys = sorted(set(api_keys))

    commented_auth = _clip(
        [redact(m.group(0).strip())[:160] for m in _COMMENTED_AUTH.finditer(text)]
    )
    dev_urls = _clip(sorted({m.group(0)[:200] for m in _DEV_URL.finditer(text)}))
    flags = _clip(sorted({m.group(1)[:60] for m in _FEATURE_FLAG.finditer(text) if m.group(1)}))
    versions = _clip(sorted({m.group(0)[:120] for m in _API_VERSION.finditer(text)}))

    leads = {
        "api_key_candidates": api_keys,
        "commented_auth_checks": commented_auth,
        "dev_staging_urls": dev_urls,
        "feature_flags": flags,
        "internal_api_versions": versions,
    }
    leads = {kind: items for kind, items in leads.items() if items}
    return {"leads": leads, "scanned": True, "advisory": True}
