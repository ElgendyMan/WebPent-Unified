# src/webpent/tools/recon/katana.py
"""webpent.tools.recon.katana

Wrapper around ProjectDiscovery's ``katana`` CLI for deep crawling.

Katana is a high-performance crawler that recursively discovers
endpoints, links, and JavaScript-rendered routes. Unlike the previous
BeautifulSoup-based single-page crawler, katana follows links to a
configurable depth and emits structured JSONL output.

The wrapper executes::

    katana -u <url> -jc -silent -d 3

where:
  * ``-u <url>``     — target URL
  * ``-jc``          — JSON output with crawl data (request + response meta)
  * ``-silent``      — suppress banner / progress output
  * ``-d 3``         — maximum crawl depth of 3 hops

Each JSONL line represents a discovered endpoint. The wrapper extracts
the endpoint URL from either ``request.endpoint`` (preferred) or the
top-level ``url`` field, and returns a de-duplicated list.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from webpent.config.settings import get_settings
from webpent.shared.exceptions import ToolExecutionError
from webpent.tools.registry import register_tool
from webpent.tools.utils.subprocess import run_command

logger = logging.getLogger(__name__)

# Default crawl depth. Three hops balances coverage against runtime —
# deeper crawls quickly explode in scope on large applications.
_DEFAULT_DEPTH = 3


def _extract_url(record: dict[str, Any]) -> str | None:
    """Extract the endpoint URL from a katana JSONL record.

    Katana's ``-jc`` mode emits records with a ``request`` object whose
    ``endpoint`` field holds the absolute URL. Older katana versions (or
    non-``-jc`` output) may instead emit a top-level ``url`` field. We
    prefer ``request.endpoint`` and fall back to ``url`` for
    compatibility.
    """
    request = record.get("request")
    if isinstance(request, dict):
        endpoint = request.get("endpoint")
        if isinstance(endpoint, str) and endpoint.strip():
            return endpoint.strip()

    url = record.get("url")
    if isinstance(url, str) and url.strip():
        return url.strip()

    return None


@register_tool(name="katana", category="recon", description="Deep crawling framework")
def run_katana(
    url: str,
    depth: int = _DEFAULT_DEPTH,
    stealth_mode: bool = False,
    session_cookies: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> list[str]:
    """Crawl ``url`` with katana and return a de-duplicated list of endpoints.

    Args:
        url: Absolute URL to crawl.
        depth: Maximum crawl depth (hops). Defaults to 3.
        stealth_mode: V5 Sprint 6/8 — when True, insert randomized
            jitter and enforce minimum inter-request spacing before
            launching katana. Recon tools generate the highest traffic
            volume, so stealth is most impactful here.

    Returns:
        A de-duplicated list of discovered endpoint URLs in discovery
        order. Empty list if katana finds nothing or fails.

    Raises:
        ToolNotFoundError: If ``katana`` is not installed.
        ToolExecutionError: If katana exits non-zero or times out.
    """
    # V5 Sprint 8: pre-tool stealth delay. Recon tools generate the
    # highest traffic volume — jitter here has the biggest WAF/IDS
    # evasion impact.
    if stealth_mode:
        from webpent.shared.stealth import (
            apply_jitter,
            enforce_min_interval,
            extract_host,
        )
        apply_jitter(stealth_mode, label="katana")
        enforce_min_interval(stealth_mode, extract_host(url))

    settings = get_settings()
    # V10 AUDIT FIX (C4): SSRF protection for katana.
    # katana runs as a subprocess and is NOT wrapped by
    # make_safe_httpx_client. It crawls discovered links to arbitrary
    # hosts — a malicious target can include <a href="http://169.254.169.254/">
    # and katana will crawl it. Mitigation: use -nc (no crawl config)
    # and -known-files (don't append /robots.txt etc.) to reduce
    # off-target crawling, AND post-filter discovered endpoints to
    # drop any whose host is NOT the engagement's own target.
    from urllib.parse import urlparse

    from webpent.shared.engagement_scope import is_engagement_target_host
    _seed_host = (urlparse(url).hostname or "").lower()

    # V10 P3-11 FIX: pre-flight scope check. If the engagement allowlist
    # is set up correctly, the seed host (the engagement's own declared
    # target URL's host) MUST be in the allowlist — otherwise the
    # post-filter below would drop every discovered endpoint (since none
    # of them would be in the empty allowlist, and equality with
    # _seed_host wouldn't help if the allowlist is genuinely empty).
    # Worse, katana would still crawl the seed host itself before we
    # get a chance to filter, violating the engagement scope. Fail
    # closed: if the seed host is non-empty AND NOT in the engagement
    # allowlist, log WARNING and return [] without invoking katana.
    if _seed_host and not is_engagement_target_host(_seed_host):
        logger.warning(
            "katana SSRF guard: seed host %s is NOT in the engagement "
            "target allowlist — refusing to crawl (engagement scope "
            "may not have been set up by the worker). Returning empty "
            "endpoint list.",
            _seed_host,
        )
        return []

    cmd = [
        settings.katana_path,
        "-u", url,
        # M1-A (M-2): pin the crawl field-scope explicitly to the seed's
        # FQDN instead of relying on katana's *default* (``-fs rdn`` —
        # the whole registrable domain).  Reasons:
        #   (a) a katana default change across versions must never be
        #       able to silently widen crawl scope;
        #   (b) with ``rdn`` an engagement scoped to app.example.com
        #       would still let katana *contact* sibling hosts
        #       (blog.example.com) before our post-filter drops the
        #       results — connections outside the engagement allowlist.
        # Subdomain discovery is subfinder's pipeline (allowlist-gated),
        # not katana's.  The seed-host allowlist gate above and the
        # post-invocation result filter below both stay.
        "-fs", "fqdn",
        # `-jc` enables JavaScript crawling; `-j` is the separate JSONL
        # output switch.  The previous wrapper used only `-jc`, so Katana
        # could complete successfully while emitting plain/empty output that
        # the JSON parser could not consume.  Keep both switches explicit.
        "-jc",
        "-j",
        # Preserve form and XHR observations for downstream endpoint and
        # hypothesis generation.  These are observations only; validators
        # still require target-backed proof before confirmation.
        "-fx",
        "-xhr",
        "-silent",
        "-d", str(depth),
        # V10 AUDIT FIX (C4): -nc disables katana's built-in crawl
        # config (which appends /robots.txt, /.git/HEAD, etc. — these
        # are off-target for a scoped engagement).
        "-nc",
    ]

    from webpent.shared.http import sanitize_request_headers
    for header_name, header_value in sanitize_request_headers(extra_headers).items():
        if header_name.lower() != "user-agent":
            cmd.extend(["-H", f"{header_name}: {header_value}"])

    # V7 Phase 4.3: Inject session cookies.
    if session_cookies:
        from webpent.shared.http import build_cookie_header
        cookie_str = build_cookie_header(session_cookies)
        if cookie_str:
            cmd.extend(["-H", f"Cookie: {cookie_str}"])
            logger.info(
                "katana: injected %d session cookie(s) (names: %s)",
                len(session_cookies), sorted(session_cookies.keys()),
            )
        else:
            logger.warning(
                "katana: session_cookies provided but all values empty "
                "after CRLF sanitization — crawling UNAUTHENTICATED.",
            )

    # V4.5: Handle timeout with partial result processing.
    try:
        raw_output = run_command(cmd, timeout=120)
    except ToolExecutionError as exc:
        if "timed out" in (exc.stderr or "").lower() and exc.stdout:
            logger.warning(
                "katana timed out after 120s — processing partial output (%d bytes)",
                len(exc.stdout),
            )
            raw_output = exc.stdout
        else:
            logger.error(
                "katana FAILED for %s (exit=%d, error_reason=%s)",
                url, exc.returncode, (exc.stderr or "")[:200],
            )
            raise

    endpoints: list[str] = []
    seen: set[str] = set()
    dropped_offscope = 0

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # katana occasionally interleaves non-JSON status lines —
            # skip them silently.
            continue
        if not isinstance(record, dict):
            continue

        endpoint = _extract_url(record)
        if endpoint and endpoint not in seen:
            seen.add(endpoint)
            # V10 AUDIT FIX (C4): post-filter — drop any discovered
            # endpoint whose host is NOT the engagement's own declared
            # target. This prevents katana from exfiltrating internal
            # hosts (169.254.169.254, redis, etc.) into the endpoint
            # list that downstream tools (sqlmap, dalfox) would then
            # probe. The engagement_scope allowlist is populated by
            # the worker (set_engagement_target_hosts) before the
            # graph runs.
            ep_host = (urlparse(endpoint).hostname or "").lower()
            # V10 HOSTILE P2-3 FIX: fail-closed on empty/unparseable
            # hostname. Previously an endpoint with no hostname (e.g.
            # a relative URL or a malformed entry) was appended
            # UNFILTERED — downstream tools would then probe it with
            # unpredictable results. Now: drop it.
            if not ep_host:
                dropped_offscope += 1
                logger.warning(
                    "katana SSRF guard: dropping endpoint with empty/"
                    "unparseable hostname: %s",
                    endpoint,
                )
                continue
            if ep_host != _seed_host and not is_engagement_target_host(ep_host):
                dropped_offscope += 1
                logger.warning(
                    "katana SSRF guard: dropping off-scope endpoint "
                    "%s (host %s is not the engagement target %s)",
                    endpoint, ep_host, _seed_host,
                )
                continue
            endpoints.append(endpoint)

    if dropped_offscope:
        logger.info(
            "katana SSRF guard: dropped %d off-scope endpoint(s) "
            "(engagement target host=%s)",
            dropped_offscope, _seed_host,
        )

    logger.info(
        "katana discovered %d unique endpoint(s) for %s (depth=%d)",
        len(endpoints),
        url,
        depth,
    )
    # V7 Phase 6: Classify tool failure mode.  Do not inspect stdout for
    # words such as ``panic`` or ``fatal``: stdout is target-controlled JSON
    # and response bodies may legitimately contain those strings.  Non-zero
    # exits/timeouts are handled by ``run_command`` above; an empty successful
    # output is the only failure signal available at this layer.
    if not raw_output.strip():
        logger.warning("TOOL_INFRA_FAILURE: katana produced no output.")

    return endpoints
