# src/webpent/tools/recon/httpx.py
"""webpent.tools.recon.httpx

Wrapper around ProjectDiscovery's ``httpx`` CLI for live-host probing.

V4.5: Custom timeout (120s) with partial-output recovery on timeout.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urlparse

from webpent.config.settings import get_settings
from webpent.shared.exceptions import ToolExecutionError
from webpent.tools.registry import register_tool
from webpent.tools.utils.subprocess import run_command

logger = logging.getLogger(__name__)


def _safe_local_probe(domains: list[str]) -> list[dict[str, Any]]:
    """Probe declared local Docker/reserved targets when httpx emits nothing.

    ProjectDiscovery httpx v1.9 rejects single-label Docker service names such
    as ``app`` even though the same URL is reachable by the hardened WebPent
    HTTP client. This fallback is deliberately narrow: it only handles
    single-label or reserved-suffix hostnames that are already present in the
    engagement target allowlist. It never probes a newly discovered host and
    never bypasses the OriginPolicy/SSRF-pinning transport.
    """
    from webpent.shared.engagement_scope import is_engagement_target_host
    from webpent.shared.http import make_safe_httpx_client

    local_domains: list[str] = []
    for value in domains:
        if not value:
            continue
        candidate = value.strip()
        parsed = urlparse(candidate if "://" in candidate else f"http://{candidate}")
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not hostname or not is_engagement_target_host(hostname):
            continue
        if "." in hostname and not hostname.endswith(
            (".localhost", ".local", ".internal", ".test", ".invalid", ".example")
        ):
            continue
        local_domains.append(candidate)

    if not local_domains:
        return []

    records: list[dict[str, Any]] = []
    try:
        with make_safe_httpx_client(
            timeout=10.0,
            follow_redirects=False,
            headers={"Accept-Encoding": "identity"},
        ) as client:
            for target in local_domains:
                try:
                    response = client.get(target)
                except Exception as exc:  # noqa: BLE001 - probe is best-effort
                    logger.warning("safe local http probe failed for %s: %s", target, exc)
                    continue
                body = response.text or ""
                parsed = urlparse(target)
                records.append(
                    {
                        "url": target,
                        "input": target,
                        "scheme": parsed.scheme,
                        "host": parsed.hostname or "",
                        "port": parsed.port,
                        "path": parsed.path or "/",
                        "status_code": response.status_code,
                        "content_type": response.headers.get("content-type", ""),
                        "content_length": len(response.content),
                        "method": "GET",
                        "words": len(body.split()),
                        "lines": body.count("\\n") + (1 if body else 0),
                        "failed": False,
                        "webpent_probe_fallback": "safe_local_http",
                    }
                )
    except Exception as exc:  # noqa: BLE001 - fallback must not abort recon
        logger.warning("safe local http fallback unavailable: %s", exc)

    return records


@register_tool(name="httpx", category="recon", description="HTTP toolkit for live-host probing")
def run_httpx(
    domains: list[str],
    stealth_mode: bool = False,
    cookies: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Probe a list of hosts with httpx and return parsed JSON results.

    Args:
        domains: List of hostnames or URLs to probe.
        stealth_mode: V5 Sprint 6/8 — when True, insert randomized
            jitter and enforce minimum inter-request spacing before
            launching httpx. Recon tools generate the highest traffic
            volume, so stealth is most impactful here.
        cookies: POST-P0 Phase 3 — optional operator session cookies
            forwarded as a single ``Cookie`` header so authenticated
            surfaces answer honestly during recon. Values are never
            logged; only the header name count is reported.

    Returns:
        A list of dictionaries, one per valid JSONL record emitted by
        httpx. Lines that fail JSON parsing are silently skipped.

    Raises:
        ToolNotFoundError: If ``httpx`` is not installed.
        ToolExecutionError: If httpx exits non-zero (non-timeout).
    """
    # V5 Sprint 8: pre-tool stealth delay. httpx probes many hosts in
    # a burst — pacing matters for WAF/IDS evasion.
    if stealth_mode:
        from webpent.shared.stealth import (
            apply_jitter,
            enforce_min_interval,
            extract_host,
        )
        apply_jitter(stealth_mode, label="httpx")
        # Rate-limit per first domain (httpx probes many at once; we
        # use the first as a proxy for the batch).
        if domains:
            enforce_min_interval(stealth_mode, extract_host(domains[0]))

    settings = get_settings()
    cmd = [
        settings.httpx_path,
        "-silent",
        "-json",
    ]

    # POST-P0 Phase 3: forward operator session cookies as one header so
    # authenticated engagements probe their real (authenticated) surface.
    scoped_cookies = {
        str(k).strip(): str(v)
        for k, v in (cookies or {}).items()
        if str(k).strip()
    }
    if scoped_cookies:
        try:
            from webpent.shared.http import build_cookie_header

            cookie_header = build_cookie_header(scoped_cookies)
        except Exception:
            cookie_header = "; ".join(
                f"{k}={v}" for k, v in scoped_cookies.items()
            )
        if cookie_header:
            cmd += ["-H", f"Cookie: {cookie_header}"]
            logger.info(
                "httpx: forwarding %d session cookie name(s) (values not logged).",
                len(scoped_cookies),
            )

    # V10 HOSTILE P2-1 FIX: scope gate — filter the input domains through
    # the engagement_scope allowlist before probing. httpx runs as a
    # subprocess and is NOT wrapped by make_safe_httpx_client, so the
    # SSRF guard does not cover it. A subfinder-discovered subdomain
    # that resolves to an internal IP (e.g. internal.corp.example.com
    # → 10.0.0.5) would be probed by httpx, exfiltrating internal
    # service banners into the recon data. Gate: only probe domains
    # whose hostname matches the engagement's declared target host.
    from urllib.parse import urlparse

    from webpent.shared.engagement_scope import is_engagement_target_host
    _scoped_domains: list[str] = []
    _dropped_count = 0
    for d in domains:
        d_stripped = d.strip() if d else ""
        if not d_stripped:
            continue
        # Normalize to a hostname for the scope check.
        _host = d_stripped
        if "://" not in _host:
            _host = "http://" + _host
        _hostname = (urlparse(_host).hostname or "").lower()
        if _hostname and is_engagement_target_host(_hostname):
            _scoped_domains.append(d_stripped)
        else:
            _dropped_count += 1
            logger.debug(
                "httpx scope gate: dropping %s (host %s not in engagement target)",
                d_stripped, _hostname,
            )
    if _dropped_count:
        logger.info(
            "httpx scope gate: dropped %d/%d domain(s) not in engagement "
            "target scope (SSRF safety).",
            _dropped_count, len(domains),
        )
    domains = _scoped_domains

    if not _scoped_domains:
        # IMPL P0-F: every input domain was dropped by the scope gate.
        # Do not spawn a no-op subprocess with empty stdin — fail closed
        # with an empty result, consistent with the other recon tools'
        # out-of-scope behavior.
        logger.info(
            "httpx scope gate: no in-scope domains remain; skipping subprocess."
        )
        return []

    input_data = "\n".join(d.strip() for d in domains if d and d.strip())

    # V4.5: Custom timeout + partial-output recovery.
    try:
        raw_output = run_command(cmd, input_data=input_data, timeout=120)
    except ToolExecutionError as exc:
        if "timed out" in (exc.stderr or "").lower() and exc.stdout:
            logger.warning(
                "httpx timed out after 120s — processing partial output (%d bytes)",
                len(exc.stdout),
            )
            raw_output = exc.stdout
        else:
            logger.error(
                "httpx FAILED (exit=%d, error_reason=%s)",
                exc.returncode, (exc.stderr or "")[:200],
            )
            raise

    results: list[dict[str, Any]] = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            results.append(record)

    # V7 Phase 6: Classify tool failure mode. For Docker/local aliases,
    # httpx v1.9 can exit successfully while emitting no records because its
    # parser expects a dotted DNS name. Recover only with the hardened local
    # probe; public/FQDN empty output remains an honest empty result.
    if not raw_output.strip() or not results:
        fallback_results = _safe_local_probe(domains)
        if fallback_results:
            logger.info(
                "httpx emitted no usable records; safe local fallback recovered %d probe(s).",
                len(fallback_results),
            )
            results.extend(fallback_results)
        else:
            logger.warning("TOOL_INFRA_FAILURE: httpx produced no output.")

    return results
