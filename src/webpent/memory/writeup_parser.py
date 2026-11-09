"""Safe structural parsing for writeups and CVE descriptions.

The parser extracts bounded methodology metadata. It does not preserve raw
writeup text as a lesson and it never treats an external statement as proof.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable

from webpent.shared.untrusted_content import wrap_target_content

_FAMILY_PATTERNS = {
    "IDOR": re.compile(r"\b(?:idor|insecure direct object reference)\b", re.I),
    "BOLA": re.compile(r"\b(?:bola|broken object level authorization)\b", re.I),
    "SSRF": re.compile(r"\b(?:ssrf|server[- ]side request forgery)\b", re.I),
    "OPEN_REDIRECT": re.compile(r"\b(?:open redirect|unvalidated redirect)\b", re.I),
    "INFO_DISCLOSURE": re.compile(r"\b(?:information disclosure|info(?:rmation)? leak|sensitive data exposure)\b", re.I),
    "XSS": re.compile(r"\b(?:xss|cross[- ]site scripting)\b", re.I),
    "SQLI": re.compile(r"\b(?:sql(?:i| injection)|structured query language injection)\b", re.I),
}
_ROUTE_RE = re.compile(r"(?<![A-Za-z0-9])/(?:[A-Za-z0-9_.~-]+/)*(?:[A-Za-z0-9_.*{}:$?-]+)?(?:\?[A-Za-z0-9_.=&${}:-]+)?")
_PARAMETER_RE = re.compile(r"\b(?:parameter|param|field|input|argument|query)\s*(?:named|called|`|:)?\s*[`'\"]?([A-Za-z_][A-Za-z0-9_.-]{0,63})", re.I)
_TECHNIQUES = {
    "authorization bypass": re.compile(r"authorization bypass|access control bypass", re.I),
    "parameter tampering": re.compile(r"parameter tampering|tamper(?:ed|ing)", re.I),
    "error-based injection": re.compile(r"error[- ]based|database error", re.I),
    "boolean-based injection": re.compile(r"boolean[- ]based|true and false", re.I),
    "reflected input": re.compile(r"reflected|reflection", re.I),
    "external URL manipulation": re.compile(r"external url|redirect parameter|next=", re.I),
    "metadata probing": re.compile(r"metadata endpoint|169\.254\.169\.254", re.I),
}


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:24]


def _routes(text: str) -> list[str]:
    seen: list[str] = []
    for value in _ROUTE_RE.findall(text[:200_000]):
        route = value.rstrip(".,;:)]\"'")
        if route and route not in seen:
            seen.append(route[:240])
    return seen[:30]


def parse_writeup_text(
    text: str, *, source: str = "writeup", source_id: str | None = None,
    use_llm: bool = False, llm_enhancer: Callable[[str], dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Parse Markdown/text into bounded structural knowledge entries."""
    raw = str(text or "")
    if not raw.strip():
        return []
    wrapper = wrap_target_content(raw, source="writeup", content_id=source_id or _digest(raw))
    lower = raw.lower()
    families = [family for family, pattern in _FAMILY_PATTERNS.items() if pattern.search(raw)] or ["UNKNOWN"]
    routes = _routes(raw) or ["/*"]
    params = list(dict.fromkeys(match.group(1)[:64] for match in _PARAMETER_RE.finditer(raw)))[:20]
    techniques = [name for name, pattern in _TECHNIQUES.items() if pattern.search(raw)][:12]
    if use_llm and llm_enhancer is not None:
        # Only the wrapper's structural summary may cross this seam. The
        # enhancer is advisory and its result is merged only as bounded hints.
        enhanced = llm_enhancer(wrapper.to_prompt_fragment()) or {}
        families.extend(str(item).upper()[:40] for item in enhanced.get("families", [])[:5])
        routes.extend(str(item)[:240] for item in enhanced.get("route_patterns", [])[:10])
        params.extend(str(item)[:64] for item in enhanced.get("parameter_hints", [])[:10])
        techniques.extend(str(item)[:80] for item in enhanced.get("techniques", [])[:10])
    families = list(dict.fromkeys(families))[:10]
    routes = list(dict.fromkeys(routes))[:30]
    params = list(dict.fromkeys(params))[:20]
    techniques = list(dict.fromkeys(techniques))[:12]
    digest = _digest(raw)
    entries: list[dict[str, Any]] = []
    for family in families:
        for route in routes[:10]:
            entries.append({
                "family": family,
                "route_pattern": route,
                "parameter_hint": params[0] if params else None,
                "technique": techniques[0] if techniques else "structural pattern extraction",
                "source": source[:80],
                "source_id": (source_id or digest)[:160],
                "digest": digest,
                "type": "writeup",
                "target_type": "generic_web",
                "content": f"{family} methodology pattern at {route}; technique={techniques[0] if techniques else 'structural pattern extraction'}; parameter={params[0] if params else 'unknown'}.",
            })
    return entries[:100]


def parse_cve_json(value: str | bytes | dict[str, Any], *, source: str = "cve", source_id: str | None = None) -> list[dict[str, Any]]:
    """Parse a CVE JSON document into structural advisory knowledge."""
    if isinstance(value, dict):
        payload = value
        raw = json.dumps(value, sort_keys=True, default=str)
    else:
        raw = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value or "")
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            return []
    description = json.dumps(payload, sort_keys=True, default=str)
    entries = parse_writeup_text(description, source=source, source_id=source_id or _digest(raw))
    for entry in entries:
        entry["type"] = "cve"
        entry["source"] = source[:80]
    return entries[:100]


def parse_file(path: str | Path, *, doc_type: str = "writeup", use_llm: bool = False, llm_enhancer: Callable[[str], dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    file_path = Path(path)
    raw = file_path.read_bytes()
    source_id = f"{file_path.name}:{_digest(raw.decode('utf-8', 'replace'))}"
    if doc_type == "cve":
        return parse_cve_json(raw, source="cve", source_id=source_id)
    return parse_writeup_text(raw, source="writeup", source_id=source_id, use_llm=use_llm, llm_enhancer=llm_enhancer)


__all__ = ["parse_writeup_text", "parse_cve_json", "parse_file"]
