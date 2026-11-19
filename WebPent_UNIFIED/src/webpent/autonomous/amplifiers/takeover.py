"""Subdomain takeover scanner (v82, Layer 1 / Task 1).

Analyzes CNAME records the operator supplies through an injected fetcher
(``name -> list[str]`` of chain targets). A takeover *fingerprint* fires
only when a CNAME points at a known service's host pattern AND the probe
response for that host shows the service's dangling-resource marker
(404/NXDOMAIN with the service's body signature). That combination is the
classic takeover precondition; anything else is reported as
``not_dangling`` honestly.

Output is advisory: an entry in the returned report, never a finding,
never a promotion. No DNS resolution happens here — the fetcher owns all
network, and tests inject doubles.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from webpent.autonomous.hunt_contracts import redact

MAX_HOSTS = 128
MAX_CHAIN = 6

# (service, cname_suffix, response_marker). The marker must appear in the
# response text of the pointed-at host for the pair to count as dangling.
SERVICE_FINGERPRINTS: tuple[tuple[str, str, str], ...] = (
    ("github-pages", "github.io", "There isn't a GitHub Pages site here"),
    ("heroku", "herokuapp.com", "No such app"),
    ("s3", "s3.amazonaws.com", "The specified bucket does not exist"),
    ("azure-cdn", "azureedge.net", "404 Not Found"),
    ("cloudfront", "cloudfront.net", "The request could not be satisfied"),
    ("fastly", "fastly.net", "Fastly error: unknown domain"),
    ("zendesk", "zendesk.com", "Help Center Closed"),
    ("shopify", "myshopify.com", "Sorry, this shop is currently unavailable"),
    ("surge", "surge.sh", "project not found"),
    ("bitbucket", "bitbucket.io", "Repository not found"),
)

FetchDns = Callable[[str], list[str]]


def _host_of(value: str) -> str:
    parts = urlsplit(str(value or "").strip())
    if parts.hostname:
        return parts.hostname.lower()
    text = redact(str(value or "").strip().lower())
    return text.split("/")[0][:253] if text else ""


def _dangling_probe(value: str, fetch_response: FetchDns) -> str:
    """Return the response text for a pointed-at host via the injected
    fetcher; failures degrade to an empty body (never raises)."""
    try:
        body = fetch_response(value)
    except Exception:
        return ""
    if isinstance(body, str):
        return redact(body)[:2000]
    if isinstance(body, list) and body:
        return redact(str(body[0]))[:2000]
    return ""


def scan_takeover(
    hosts: list[str],
    *,
    fetch_dns: FetchDns,
    fetch_response: FetchDns | None = None,
) -> dict[str, Any]:
    """Scan hosts for dangling CNAME fingerprints; advisory report only.

    ``fetch_dns(host)`` returns the CNAME chain (list of target names);
    ``fetch_response(name)`` returns that host's body text (defaults to
    the same fetcher). Never raises; failures degrade to no signal.
    """
    response = fetch_response or fetch_dns
    report: dict[str, Any] = {"candidates": [], "scanned": 0, "errors": 0}
    for raw in list(hosts)[:MAX_HOSTS]:
        host = _host_of(raw)
        if not host:
            continue
        report["scanned"] += 1
        try:
            chain = [str(item) for item in (fetch_dns(host) or [])][:MAX_CHAIN]
        except Exception:
            report["errors"] += 1
            continue
        for target in chain:
            target_host = _host_of(target)
            for service, suffix, marker in SERVICE_FINGERPRINTS:
                if not target_host.endswith(suffix):
                    continue
                body = _dangling_probe(target_host, response)
                if marker.lower() in body.lower():
                    report["candidates"].append(
                        {
                            "host": host,
                            "cname_target": target_host[:253],
                            "service": service,
                            "verdict": "dangling_fingerprint",
                            "advisory": True,
                        }
                    )
                    break
            else:
                continue
            break
    report["candidates"] = report["candidates"][:MAX_HOSTS]
    return report
