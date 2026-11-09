"""Certificate Transparency mining (v82, Layer 1 / Task 5).

Parses the operator-supplied CT log JSON (crt.sh ``name_value`` shape or
a plain name list) returned through an injected fetcher, extracts
subdomains of the target, and returns them as advisory scope-checked
candidates. The module never opens a socket and never invents hosts:
garbage in, zero candidates out.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from webpent.autonomous.hunt_contracts import redact

MAX_NAMES = 200
MAX_CANDIDATES = 64

FetchText = Callable[[str], str]


def _domain_of(value: str) -> str:
    parts = urlsplit(str(value or "").strip())
    host = (parts.hostname or parts.path).lower()
    host = redact(host)[:253]
    # Structural check only: a registrable domain has a dot and no spaces.
    if not host or " " in host or "." not in host:
        return ""
    return host


def _in_scope(candidate: str, registrable: str) -> bool:
    if not candidate or candidate == registrable:
        return False
    return candidate.endswith("." + registrable)


def _names_from_document(document: Any) -> list[str]:
    names: list[str] = []
    if isinstance(document, list):
        for entry in document[:MAX_NAMES]:
            if isinstance(entry, dict):
                raw = entry.get("name_value") or entry.get("common_name") or ""
                names.extend(str(raw).split("\n"))
    elif isinstance(document, dict):
        raw = document.get("name_value") or document.get("names") or []
        if isinstance(raw, str):
            names.extend(raw.split("\n"))
        elif isinstance(raw, list):
            names.extend(str(item) for item in raw[:MAX_NAMES])
    return names


def mine_ct_logs(
    target_url: str, *, fetch_text: FetchText, ct_url: str = "ct://crt.sh"
) -> dict[str, Any]:
    """Extract in-scope subdomains from fetched CT data; advisory only."""
    registrable = _domain_of(target_url)
    if not registrable:
        return {"candidates": [], "reason": "bad_target", "advisory": True}
    try:
        body = fetch_text(ct_url)
    except Exception as exc:
        return {"candidates": [], "reason": f"fetch_failed:{type(exc).__name__}", "advisory": True}
    try:
        document = json.loads(body) if isinstance(body, str) else None
    except ValueError:
        return {"candidates": [], "reason": "bad_json", "advisory": True}

    candidates: list[str] = []
    for raw in _names_from_document(document)[:MAX_NAMES]:
        candidate = _domain_of(raw)
        if _in_scope(candidate, registrable) and candidate not in candidates:
            candidates.append(candidate)
    return {
        "candidates": [
            {"subdomain": name, "source": "ct_logs", "advisory": True}
            for name in sorted(candidates)[:MAX_CANDIDATES]
        ],
        "advisory": True,
    }
