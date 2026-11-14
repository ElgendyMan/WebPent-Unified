"""Optional, local-only disclosed-report intelligence.

The component accepts operator-supplied report text or exported JSON records. It
never scrapes HackerOne/Bugcrowd, never treats a report as proof, and never
creates a vulnerability finding. Its output is advisory coverage guidance with
stable source fingerprints and redacted excerpts.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

_CLASS_PATTERNS: dict[str, tuple[str, ...]] = {
    "broken_access_control": (
        "idor",
        "bola",
        "broken access control",
        "authorization bypass",
        "access control",
    ),
    "business_logic": (
        "race condition",
        "workflow",
        "business logic",
        "checkout",
        "coupon",
        "negative quantity",
    ),
    "jwt": ("jwt", "json web token", "alg=none", "key confusion", "weak secret"),
    "xss": ("cross-site scripting", "xss", "dom xss", "stored xss", "reflected xss"),
    "ssrf": ("ssrf", "server-side request forgery", "metadata endpoint"),
    "subdomain_takeover": ("subdomain takeover", "dangling cname", "dangling dns"),
    "cloud_storage": ("s3 bucket", "cloud storage", "public bucket", "blob storage", "gcs bucket"),
    "api": ("graphql", "rest api", "mass assignment", "api endpoint"),
}

_ENDPOINT_RE = re.compile(
    r"(?<![A-Za-z0-9])/(?:[A-Za-z0-9_.~-]+/){0,5}[A-Za-z0-9_.~-]+(?:\?[A-Za-z0-9_=&.%~-]+)?"
)
_SECRET_RE = re.compile(
    r"(?i)(authorization\s*:\s*bearer\s+\S+|cookie\s*:\s*\S+|"
    r"(?:api[_ -]?key|secret|token)\s*[=:]\s*\S+)"
)


def _redact(text: str) -> str:
    text = _SECRET_RE.sub("[REDACTED]", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:280]


def _fingerprint(source: str, text: str) -> str:
    return hashlib.sha256(f"{source}\n{text}".encode()).hexdigest()[:16]


def _classify(text: str) -> list[str]:
    lowered = text.lower()
    return sorted(
        name
        for name, patterns in _CLASS_PATTERNS.items()
        if any(pattern in lowered for pattern in patterns)
    )


def ingest_disclosed_reports(
    documents: Iterable[str | dict[str, Any]], *, max_documents: int = 200
) -> list[dict[str, Any]]:
    """Normalize local report text into safe, searchable advisory records."""
    records: list[dict[str, Any]] = []
    for index, document in enumerate(documents):
        if index >= max_documents:
            break
        if isinstance(document, str):
            source = f"operator_text_{index + 1}"
            title = "Operator-supplied disclosed report"
            text = document
        elif isinstance(document, dict):
            source = str(
                document.get("source") or document.get("url") or f"operator_record_{index + 1}"
            )
            title = str(document.get("title") or "Disclosed report")[:160]
            text = str(
                document.get("text") or document.get("body") or document.get("description") or ""
            )
        else:
            continue
        text = text.strip()
        if not text:
            continue
        endpoints = sorted(set(_ENDPOINT_RE.findall(text)))[:30]
        tags = _classify(text)
        records.append(
            {
                "report_id": _fingerprint(source, text),
                "source_label": _redact(source)[:160],
                "title": _redact(title),
                "tags": tags,
                "endpoint_shapes": endpoints,
                "excerpt": _redact(text),
            }
        )
    return records


def search_disclosed_reports(
    records: Iterable[dict[str, Any]], query: str, *, limit: int = 20
) -> list[dict[str, Any]]:
    """Search normalized records by terms without external retrieval."""
    terms = {term for term in re.findall(r"[a-z0-9_-]+", query.lower()) if term}
    scored: list[tuple[int, dict[str, Any]]] = []
    for record in records:
        haystack = " ".join(
            [
                str(record.get("title", "")),
                str(record.get("excerpt", "")),
                " ".join(str(tag) for tag in record.get("tags", [])),
            ]
        ).lower()
        score = sum(1 for term in terms if term in haystack)
        if score:
            scored.append((score, record))
    scored.sort(key=lambda pair: (-pair[0], str(pair[1].get("report_id", ""))))
    return [record for _, record in scored[: max(0, limit)]]


def build_advisories(
    target_url: str,
    discovered_endpoints: Iterable[str] | None,
    records: Iterable[dict[str, Any]],
    *,
    max_advisories: int = 30,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Create target-specific hypotheses and explicit coverage gaps.

    Similarity is intentionally weak and transparent: matching path shapes or
    report tags raises an advisory priority, but never changes a Finding or
    confidence level.
    """
    host = urlparse(target_url).hostname or "target"
    endpoint_values = [str(endpoint) for endpoint in (discovered_endpoints or []) if endpoint]
    endpoint_tokens = {
        token.lower()
        for endpoint in endpoint_values
        for token in re.findall(r"[a-z0-9_-]+", endpoint.lower())
    }
    advisories: list[dict[str, Any]] = []
    for record in records:
        tags = [str(tag) for tag in record.get("tags", [])]
        shapes = [str(shape) for shape in record.get("endpoint_shapes", [])]
        shape_tokens = {
            token.lower() for shape in shapes for token in re.findall(r"[a-z0-9_-]+", shape.lower())
        }
        overlap = sorted(endpoint_tokens & shape_tokens)
        if not tags and not overlap:
            continue
        priority = min(100, 30 + 10 * len(tags) + 15 * len(overlap))
        advisories.append(
            {
                "advisory_id": f"{record.get('report_id', 'unknown')}:{host}",
                "target_host": host,
                "source_report_id": record.get("report_id"),
                "suggested_classes": tags,
                "matched_endpoint_tokens": overlap[:20],
                "priority": priority,
                "rationale": (
                    "Historical pattern is a lead only; validate with target-specific "
                    "evidence before reporting."
                ),
            }
        )
        if len(advisories) >= max_advisories:
            break

    gaps: list[dict[str, Any]] = []
    if not records:
        gaps.append(
            {
                "type": "disclosed_report_corpus_missing",
                "reason": (
                    "No operator-supplied local report corpus was provided; advisory "
                    "intelligence was skipped."
                ),
            }
        )
    if not endpoint_values:
        gaps.append(
            {
                "type": "advisory_endpoint_context_missing",
                "reason": (
                    "No discovered endpoint shapes were available for target-specific "
                    "matching."
                ),
            }
        )
    return advisories, gaps
