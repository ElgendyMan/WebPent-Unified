"""Read-only cloud storage exposure checks.

This module only sends unauthenticated GET/HEAD requests to URLs already
identified by the engagement.  A bucket is reported only when the response
contains provider-specific public-listing evidence; a 200 response alone is
never treated as proof of exposure.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from webpent.models.findings import Finding, Severity
from webpent.models.targets import Target
from webpent.shared.http import make_safe_httpx_client

logger = logging.getLogger(__name__)

# TEAM-1 (2026-10): added DigitalOcean Spaces, Cloudflare R2, Backblaze B2,
# and Alibaba OSS. All four are documented by their vendors as S3-API-
# compatible for object listing (ListObjects/ListBucketResult), so the same
# "<listbucketresult>"+"<key>" evidence check already used for AWS S3 below
# applies to them without inventing new markers. Hostnames were picked to hit
# the actual listing API endpoint, not a CDN/public-serving alias that never
# returns a listing even when the bucket is public:
#   - Cloudflare R2: the API endpoint is *.r2.cloudflarestorage.com. The
#     public dev alias *.r2.dev serves individual objects, not a listing —
#     deliberately not matched here, since it can never produce the
#     provider-specific listing evidence this detector requires.
#   - Backblaze B2: the S3-compatible listing endpoint is
#     s3.<region>.backblazeb2.com (docs: backblaze.com/apidocs/s3-compatible-api).
#   - Alibaba OSS: *.aliyuncs.com (docs: GetBucket/ListObjects XML response
#     uses <ListBucketResult>/<Contents>/<Key>, same shape as S3).
#   - DigitalOcean Spaces: *.digitaloceanspaces.com, documented as using the
#     same REST API as S3.
_BUCKET_HOST_RE = re.compile(
    r"(?:^|\.)((?:s3[.-][a-z0-9-]+"
    r"|storage\.googleapis\.com"
    r"|blob\.core\.windows\.net"
    r"|storage\.cloud\.google\.com"
    r"|digitaloceanspaces\.com"
    r"|r2\.cloudflarestorage\.com"
    r"|backblazeb2\.com"
    r"|aliyuncs\.com))$",
    re.I,
)


def _candidate_urls(state: dict[str, Any]) -> list[str]:
    target: Target | None = state.get("target")
    values: list[Any] = []
    if target:
        values.append(target.url)
    values.extend([state.get("discovered_urls"), state.get("urls"), state.get("crawled_data")])
    urls: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for item in value.values():
                visit(item)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                visit(item)
        elif isinstance(value, str) and value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            if parsed.hostname and (target is None or target.is_in_scope(value)):
                urls.add(value.rstrip("/") or value)

    for value in values:
        visit(value)
    return sorted(urls)


def _safe_headers(response: Any) -> dict[str, str]:
    blocked = {"set-cookie", "authorization", "proxy-authorization", "cookie"}
    return {str(k): str(v) for k, v in response.headers.items() if str(k).lower() not in blocked}


def _provider_hint(host: str) -> str | None:
    lower = host.lower()
    # These four checks MUST run before the aws-s3 check below: aws-s3's own
    # condition (`lower.startswith("s3.")`) is broad enough to misfire on
    # hosts like "s3.us-west-002.backblazeb2.com" (a real Backblaze B2
    # S3-compatible-API hostname that happens to start with "s3." but is not
    # AWS). Verified empirically — this ordering was not just reasoned about;
    # flipping it was caught by a test that sent exactly that hostname
    # through and got "aws-s3" back instead of "backblaze-b2".
    if "digitaloceanspaces.com" in lower:
        return "digitalocean-spaces"
    if "r2.cloudflarestorage.com" in lower:
        return "cloudflare-r2"
    if "backblazeb2.com" in lower:
        return "backblaze-b2"
    if "aliyuncs.com" in lower:
        return "alibaba-oss"
    if "amazonaws.com" in lower or lower.startswith("s3.") or ".s3." in lower:
        return "aws-s3"
    if "storage.googleapis.com" in lower or "storage.cloud.google.com" in lower:
        return "gcs"
    if "blob.core.windows.net" in lower:
        return "azure-blob"
    return None


# Providers documented by their vendors as S3-API-compatible for object
# listing (see the _BUCKET_HOST_RE comment above for per-provider sourcing).
# They return the same <ListBucketResult>/<Key> XML shape as AWS S3, so the
# same evidence check applies — this set exists only to avoid duplicating
# that check four times below.
_S3_COMPATIBLE_PROVIDERS = frozenset(
    {"digitalocean-spaces", "cloudflare-r2", "backblaze-b2", "alibaba-oss"}
)


def _listing_evidence(provider: str | None, response: Any, body: str) -> list[str]:
    lower = body.lower()
    header_names = {str(k).lower(): str(v) for k, v in response.headers.items()}
    evidence: list[str] = []
    if provider == "aws-s3" and "<listbucketresult" in lower and "<key>" in lower:
        evidence.append("aws_listbucketresult_with_key")
    if (
        provider in _S3_COMPATIBLE_PROVIDERS
        and "<listbucketresult" in lower
        and "<key>" in lower
    ):
        evidence.append(f"{provider.replace('-', '_')}_listbucketresult_with_key")
    if provider == "gcs" and (
        "<listbucketresult" in lower or "<bucket" in lower and "<name" in lower
    ):
        evidence.append("gcs_xml_listing")
    if provider == "azure-blob" and "<enumerationresults" in lower and "<blob" in lower:
        evidence.append("azure_blob_listing")
    if "x-amz-bucket-region" in header_names and "<key>" in lower:
        evidence.append("s3_region_header_and_object_key")
    return evidence


def verify_cloud_storage(
    target: Target,
    urls: list[str] | None = None,
    *,
    timeout: float = 8.0,
) -> tuple[list[Finding], list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[Finding] = []
    observations: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    for url in urls or [target.url]:
        if not target.is_in_scope(url):
            continue
        host = urlparse(url).hostname or ""
        provider = _provider_hint(host)
        if provider is None and not _BUCKET_HOST_RE.search(host):
            observations.append({"url": url, "status": "not_cloud_storage_candidate"})
            continue
        row: dict[str, Any] = {
            "url": url,
            "provider": provider or "unknown",
            "status": "inconclusive",
        }
        try:
            with make_safe_httpx_client(
                timeout=timeout, follow_redirects=False, verify=True
            ) as client:
                response = client.get(url, headers={"User-Agent": "WebPent/readonly-cloud-check"})
            body = response.text[:40000]
            matched = _listing_evidence(provider, response, body)
            row.update(
                {
                    "status_code": response.status_code,
                    "matched_evidence": matched,
                    "headers": _safe_headers(response),
                }
            )
            if response.status_code == 200 and matched:
                row["status"] = "public_listing_confirmed"
                findings.append(
                    Finding(
                        title=f"Public cloud storage listing exposed at {host}",
                        severity=Severity.HIGH,
                        description=(
                            f"An unauthenticated read-only request to {url} returned "
                            "provider-specific object-listing evidence. The response demonstrates "
                            "public enumeration of storage contents; no write or destructive "
                            "operation was attempted."
                        ),
                        tool_name="cloud_storage_agent",
                        payload=None,
                        url=url,
                        confidence_level="Needs Human Review",
                        vuln_class="cloud_storage_exposure",
                        reasoning=(
                            "HTTP 200 plus provider-specific listing markers were observed "
                            "without authentication."
                        ),
                        evidence_bundle={
                            "url": url,
                            "provider": provider,
                            "status_code": response.status_code,
                            "matched_evidence": matched,
                            "headers": _safe_headers(response),
                            "causal_signal": False,
                            "negative_control_complete": False,
                            "promotion_guard": "blocked_missing_negative_control",
                        },
                        references=["https://owasp.org/www-project-api-security/"],
                        business_impact=(
                            "Public object enumeration can disclose sensitive files, identifiers, "
                            "and application metadata to unauthenticated users."
                        ),
                    )
                )
        except Exception as exc:
            row["status"] = "probe_failed"
            row["error_type"] = type(exc).__name__
            gaps.append(
                {
                    "url": url,
                    "reason": "Cloud storage probe failed",
                    "error_type": type(exc).__name__,
                }
            )
        observations.append(row)
    return findings, observations, gaps


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def cloud_storage_node(state: dict[str, Any]) -> dict[str, Any]:
    target: Target | None = state.get("target")
    if target is None:
        return {
            "current_phase": "cloud_storage",
            "errors": ["No target configured for cloud storage check."],
        }
    findings, observations, gaps = verify_cloud_storage(target, _candidate_urls(state))
    return {
        "findings": findings,
        "cloud_storage_observations": observations,
        "cloud_storage_coverage_gaps": gaps,
        "current_phase": "cloud_storage",
    }


__all__ = ["verify_cloud_storage", "cloud_storage_node", "_candidate_urls", "_listing_evidence"]
