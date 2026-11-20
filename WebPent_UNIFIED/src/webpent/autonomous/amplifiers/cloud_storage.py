"""Cloud storage misconfiguration detective (v82, Layer 1 / Task 2).

Two halves, both pure:

* permutation generation: company name -> candidate bucket names
  (backup, prod, dev, staging, releases, ...) across provider suffixes.
* response classification: given a bucket URL and the response text the
  operator's fetcher returns, classify open / protected / missing from
  the provider's own body signatures. Anything unrecognized is honestly
  ``unknown``.

Advisory only: a classified-open bucket is a candidate for the operator
to verify manually, never an automatic finding. Tests inject doubles;
no network here.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from webpent.autonomous.hunt_contracts import redact

MAX_PERMUTATIONS = 64
MAX_BUCKETS = 64

BUCKET_WORDS: tuple[str, ...] = (
    "backup", "backups", "prod", "production", "dev", "development",
    "staging", "stage", "test", "qa", "releases", "assets", "static",
    "data", "logs", "media", "uploads", "internal", "private", "tmp",
)

PROVIDER_SUFFIXES: tuple[str, ...] = (
    "s3.amazonaws.com",
    "storage.googleapis.com",
    "blob.core.windows.net",
)

# (provider, marker, verdict). Markers are matched case-insensitively.
RESPONSE_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("s3", "listbucketresult", "open_list"),
    ("s3", "accessdenied", "protected"),
    ("s3", "nosuchbucket", "missing"),
    ("gcs", "nosuchbucket", "missing"),
    ("gcs", "bucket is empty", "open_list"),
    ("gcs", "denied", "protected"),
    ("azure", "blobnotfound", "missing"),
    ("azure", "public access is not permitted", "protected"),
    ("azure", "authorizationfailure", "protected"),
)

FetchBody = Callable[[str], str]


def bucket_permutations(company: str, *, extra_words: list[str] | None = None) -> list[str]:
    """Company name -> candidate bucket labels (pure, bounded)."""
    base = redact(str(company or "").strip().lower())
    base = "".join(ch for ch in base if ch.isalnum() or ch == "-")
    if not base:
        return []
    words = list(BUCKET_WORDS) + [
        redact(str(w).strip().lower())[:40] for w in (extra_words or [])
    ]
    labels: list[str] = []
    for word in words:
        if not word:
            continue
        for candidate in (f"{base}-{word}", f"{base}{word}", f"{word}-{base}"):
            if candidate not in labels:
                labels.append(candidate)
    return labels[:MAX_PERMUTATIONS]


def bucket_urls(labels: list[str]) -> list[str]:
    """Labels -> provider URLs (bounded, deterministic order)."""
    urls: list[str] = []
    for label in labels[:MAX_BUCKETS]:
        for suffix in PROVIDER_SUFFIXES:
            if suffix == "s3.amazonaws.com":
                urls.append(f"https://{label}.{suffix}")
            else:
                urls.append(f"https://{suffix}/{label}/")
    return urls[: MAX_BUCKETS * len(PROVIDER_SUFFIXES)]


def classify_bucket(url: str, fetch_body: FetchBody) -> dict[str, Any]:
    """Classify one bucket URL from its fetched body; never raises."""
    host = urlsplit(url).hostname or ""
    provider = "s3" if "s3.amazonaws.com" in host else (
        "gcs" if "googleapis.com" in host else "azure"
    )
    try:
        body = redact(str(fetch_body(url) or ""))[:4000]
    except Exception as exc:
        return {
            "url": url,
            "verdict": "unknown",
            "reason": f"fetch_failed:{type(exc).__name__}",
            "advisory": True,
        }
    for prov, marker, verdict in RESPONSE_SIGNATURES:
        if prov == provider and marker in body.lower():
            return {"url": url, "provider": provider, "verdict": verdict, "advisory": True}
    return {"url": url, "provider": provider, "verdict": "unknown", "advisory": True}


def scan_buckets(
    urls: list[str], *, fetch_body: FetchBody, max_checks: int = MAX_BUCKETS
) -> dict[str, Any]:
    """Classify up to ``max_checks`` buckets; advisory report only."""
    open_buckets: list[dict[str, Any]] = []
    verdicts: dict[str, int] = {}
    for url in list(urls)[:max_checks]:
        item = classify_bucket(url, fetch_body)
        verdicts[item["verdict"]] = verdicts.get(item["verdict"], 0) + 1
        if item["verdict"] == "open_list":
            open_buckets.append(item)
    return {
        "open_candidates": open_buckets[:MAX_BUCKETS],
        "verdicts": verdicts,
        "advisory": True,
    }
