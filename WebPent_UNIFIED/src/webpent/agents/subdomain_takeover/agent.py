"""Read-only subdomain takeover verification.

The detector is deliberately evidence-first.  It never claims takeover from a
CNAME alone: it requires an in-scope hostname, a provider signature, and an
HTTP response fingerprint consistent with an unclaimed resource.  DNS and HTTP
failures are retained as observations rather than promoted to findings.
"""

from __future__ import annotations

import hashlib
import logging
import re
import socket
from typing import Any
from urllib.parse import urlparse

from webpent.models.findings import Finding, Severity
from webpent.models.targets import Target
from webpent.shared.http import make_safe_httpx_client
from webpent.shared.research_intelligence import NegativeEvidence

logger = logging.getLogger(__name__)

#   TEAM-1 (2026-10): expanded from 6 to 21 providers. Every entry below was
#   cross-checked against the community-maintained fingerprint database at
#   github.com/EdOverflow/can-i-take-over-xyz (fingerprints.json, cloned and
#   read directly rather than taken from training-data memory) — each CNAME
#   marker and body marker is copied from an entry with "vulnerable": true.
#
#   Deliberately NOT added, despite appearing in the team's planning notes,
#   because the upstream source lists them as "vulnerable": false (adding
#   them would manufacture false positives, not close a gap):
#     - Fastly        -> fingerprint is an error page, not an unclaimed state
#     - Zendesk        -> "Help Center Closed" is a disabled-not-claimable state
#     - Unbounce       -> generic 404, service is not vulnerable
#     - CloudFront     -> ViewerCertificateException is a TLS config error
#   Also deliberately skipped (named in planning notes but no documented CNAME
#   in the upstream source — adding a guessed CNAME would be fabrication):
#     - Shopify, Tumblr, Cargo Collective
#   Also skipped: Ngrok and the upstream Wordpress/HTTP_STATUS-only entries
#   where the only documented fingerprint is a bare HTTP status code (e.g.
#   "HTTP_STATUS=301") rather than response-body text this detector matches
#   against, or where the only body text is too short/generic to be a safe
#   substring marker on its own (e.g. Ngrok's fingerprint is a regex,
#   "Tunnel .*.ngrok.io not found", whose only fixed substrings are "Tunnel "
#   and " not found" — both too generic to use alone).
_PROVIDER_SIGNATURES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "github-pages": (
        ("github.io",),
        (
            "There isn't a GitHub Pages site here.",
            "For root URLs",
        ),
    ),
    "heroku": (("herokuapp.com",), ("No such app", "no-such-app")),
    "azure": (
        ("azurewebsites.net", "cloudapp.azure.com"),
        ("404 Web Site not found", "ResourceNotFound"),
    ),
    "aws-s3-website": (
        ("s3-website", "amazonaws.com"),
        ("NoSuchBucket", "The specified bucket does not exist"),
    ),
    "netlify": (("netlify.app", "netlify.com"), ("Not found - Request ID", "NETLIFY_NOT_FOUND")),
    "vercel": (("vercel.app",), ("DEPLOYMENT_NOT_FOUND", "The deployment could not be found")),
    "wordpress-com": (
        ("wordpress.com",),
        ("Do you want to register",),
    ),
    "bitbucket": (("bitbucket.io",), ("Repository not found",)),
    "ghost-io": (("ghost.io",), ("Failed to resolve DNS path for this host",)),
    "help-scout": (
        ("helpscoutdocs.com",),
        ("No settings were found for this company:",),
    ),
    "help-juice": (("helpjuice.com",), ("We could not find what you're looking for.",)),
    "readme-io": (
        ("readme.io",),
        ("The creators of this project are still working on making everything perfect!",),
    ),
    "surge-sh": (("surge.sh",), ("project not found",)),
    "uberflip": (
        ("uberflip.com",),
        ("The URL you've accessed does not provide a hub.",),
    ),
    "jetbrains-youtrack": (
        ("youtrack.cloud",),
        ("is not a registered InCloud YouTrack",),
    ),
    "strikingly": (("strikinglydns.com",), ("PAGE NOT FOUND.",)),
    "hatenablog": (("hatenablog.com",), ("404 Blog is not found",)),
    "anima": (
        ("animaapp.io",),
        ("The page you were looking for does not exist.",),
    ),
    "agile-crm": (
        ("agilecrm.com",),
        ("Sorry, this page is no longer available.",),
    ),
    "gemfury": (("furyns.com",), ("404: This page could not be found.",)),
    "surveysparrow": (("surveysparrow.com",), ("Account not found.",)),
}


def _candidate_hosts(state: dict[str, Any]) -> list[str]:
    """Collect hosts already discovered by the engagement; never enumerate out of scope."""
    target: Target | None = state.get("target")
    values: list[Any] = []
    if target:
        values.extend([target.domain, urlparse(target.url).hostname])
    for key in ("subdomains", "hosts", "live_hosts", "recon_results"):
        values.append(state.get(key))
    crawled = state.get("crawled_data") or {}
    values.append(crawled)

    hosts: set[str] = set()
    host_re = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for item in value.values():
                visit(item)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                visit(item)
        elif isinstance(value, str):
            candidate = value.strip().lower()
            parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
            host = parsed.hostname or candidate.split("/")[0].split(":")[0]
            if host and host_re.fullmatch(host):
                hosts.add(host.rstrip("."))

    for value in values:
        visit(value)
    return sorted(hosts)


def _resolve_cname(host: str) -> str | None:
    """Resolve a CNAME without failing the scan when optional dnspython is absent."""
    try:
        import dns.resolver  # type: ignore

        answers = dns.resolver.resolve(host, "CNAME", lifetime=3.0)
        for answer in answers:
            return str(answer.target).rstrip(".").lower()
    except Exception as exc:
        logger.debug("CNAME resolve failed for %s: %s", host, exc, exc_info=True)
        # K-2 (RA-3): narrowed from bare except: pass — reviewed 2026-09-03, updated 2026-10-13
    try:
        _name, aliases, _addresses = socket.gethostbyname_ex(host)
        for alias in aliases:
            if alias and alias.lower() != host.lower():
                return alias.rstrip(".").lower()
    except Exception:
        return None
    return None


def _provider_for_cname(cname: str | None) -> tuple[str, tuple[str, ...]] | None:
    if not cname:
        return None
    lower = cname.lower().rstrip(".")
    for provider, (cname_markers, body_markers) in _PROVIDER_SIGNATURES.items():
        if any(marker in lower for marker in cname_markers):
            return provider, body_markers
    return None


def _safe_headers(response: Any) -> dict[str, str]:
    blocked = {"set-cookie", "authorization", "proxy-authorization", "cookie"}
    return {str(k): str(v) for k, v in response.headers.items() if str(k).lower() not in blocked}


def verify_subdomain_takeover(
    target: Target,
    hosts: list[str] | None = None,
    *,
    timeout: float = 8.0,
) -> tuple[list[Finding], list[dict[str, Any]], list[dict[str, Any]]]:
    """Return confirmed findings, observations, and coverage gaps."""
    findings: list[Finding] = []
    observations: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    candidates = hosts or _candidate_hosts({"target": target})

    for host in candidates:
        url = f"https://{host}/"
        if not target.is_in_scope(url):
            observations.append({"host": host, "status": "out_of_scope", "evidence": {}})
            continue
        cname = _resolve_cname(host)
        provider = _provider_for_cname(cname)
        row: dict[str, Any] = {"host": host, "cname": cname, "status": "inconclusive"}
        if not provider:
            row["status"] = "no_provider_signature"
            observations.append(row)
            continue
        provider_name, body_markers = provider
        row["provider"] = provider_name
        try:
            with make_safe_httpx_client(
                timeout=timeout, follow_redirects=False, verify=True
            ) as client:
                response = client.get(
                    url, headers={"User-Agent": "WebPent/readonly-takeover-check"}
                )
            body = response.text[:20000]
            matched = [marker for marker in body_markers if marker.lower() in body.lower()]
            row.update(
                {
                    "status_code": response.status_code,
                    "matched_markers": matched,
                    "headers": _safe_headers(response),
                }
            )
            if matched:
                row["status"] = "provider_fingerprint_match"
                finding = Finding(
                    title=f"Potential {provider_name} subdomain takeover at {host}",
                    severity=Severity.HIGH,
                    description=(
                        f"The in-scope hostname {host} resolves to a {provider_name} service "
                        "and returned a provider-specific unclaimed-resource fingerprint. "
                        "This is a read-only confirmation candidate; ownership must be "
                        "verified before remediation."
                    ),
                    tool_name="subdomain_takeover_agent",
                    payload=None,
                    url=url,
                    confidence_level="Needs Human Review",
                    vuln_class="subdomain_takeover",
                    reasoning=(
                        "CNAME provider signature and provider-specific HTTP fingerprint matched."
                    ),
                    evidence_bundle={
                        "hostname": host,
                        "cname": cname,
                        "provider": provider_name,
                        "status_code": response.status_code,
                        "matched_markers": matched,
                        "headers": _safe_headers(response),
                        "causal_signal": False,
                        "negative_control_complete": False,
                        "promotion_guard": "blocked_missing_negative_control_and_ownership_proof",
                    },
                    references=[
                        "https://owasp.org/www-community/attacks/Hostile_subdomain_takeover"
                    ],
                    business_impact=(
                        "An abandoned DNS alias can allow an attacker to claim the delegated "
                        "service and serve content under the organization’s hostname."
                    ),
                )
                findings.append(finding)
            else:
                row["status"] = "provider_responded_without_takeover_fingerprint"
        except Exception as exc:
            row["status"] = "probe_failed"
            row["error_type"] = type(exc).__name__
            gaps.append(
                {
                    "host": host,
                    "reason": "HTTP verification failed",
                    "error_type": type(exc).__name__,
                }
            )
        observations.append(row)
    return findings, observations, gaps


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def subdomain_takeover_node(state: dict[str, Any]) -> dict[str, Any]:
    target: Target | None = state.get("target")
    if target is None:
        return {
            "current_phase": "subdomain_takeover",
            "errors": ["No target configured for takeover check."],
        }
    candidates = _candidate_hosts(state)
    in_scope_hosts: list[str] = []
    out_of_scope_evidence: list[dict[str, Any]] = []
    scope_runtime_handle = getattr(
        state.get("runtime_context"), "scope_runtime_handle", None
    )
    compiled_scope = (
        scope_runtime_handle.as_dict()
        if scope_runtime_handle is not None
        else state.get("compiled_scope") or {}
    )
    scope_regex = tuple(str(item) for item in compiled_scope.get("compiled_regex", []))
    client_id = str(state.get("client_id") or "").strip()
    engagement_id = str(state.get("engagement_id") or "").strip()
    for host in candidates:
        host_in_scope = (
            scope_runtime_handle.permits_host(host)
            if scope_runtime_handle is not None
            else target.is_in_scope(f"https://{host}")
        )
        if host_in_scope:
            in_scope_hosts.append(host)
            continue
        if not client_id:
            continue
        action_fingerprint = hashlib.sha256(
            f"subdomain-scope|{host}|{compiled_scope.get('fingerprint', '')}".encode()
        ).hexdigest()[:32]
        out_of_scope_evidence.append(
            NegativeEvidence(
                evidence_id=f"scope:{action_fingerprint}",
                hypothesis_id=f"subdomain_scope:{host}",
                action_fingerprint=action_fingerprint,
                identity_context="none",
                tenant_context=client_id,
                method="scope_filter",
                workflow_state="subdomain_takeover",
                reason="discovered_host_out_of_scope",
                confidence=1.0,
                client_id=client_id,
                engagement_id=engagement_id,
                scope=scope_regex,
            ).as_dict()
        )
    findings, observations, gaps = verify_subdomain_takeover(target, in_scope_hosts)
    return {
        "findings": findings,
        "subdomain_takeover_observations": observations,
        "subdomain_takeover_coverage_gaps": gaps,
        "negative_evidence_ledger": out_of_scope_evidence,
        **(
            {"scope_runtime_fingerprint": scope_runtime_handle.fingerprint}
            if scope_runtime_handle is not None
            else {}
        ),
        "current_phase": "subdomain_takeover",
    }


__all__ = [
    "verify_subdomain_takeover",
    "subdomain_takeover_node",
    "_resolve_cname",
    "_candidate_hosts",
]
