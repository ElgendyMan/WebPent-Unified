# src/webpent/shared/http.py
"""webpent.shared.http

V6 Omniscient Audit Fix (P0 — SSRF via HTTP Redirects)
=======================================================

A malicious target can answer an httpx request with a ``302 Found`` whose
``Location`` header points at an internal address such as
``http://169.254.169.254/latest/meta-data/`` (AWS instance metadata) or
``http://redis:6379/`` (an internal Docker service). When the calling
code constructs its client with ``follow_redirects=True``, httpx will
silently follow that redirect — effectively turning WebPent into an
SSRF proxy that exfiltrates cloud metadata or probes internal services
on behalf of the attacker.

This module provides two factories:

  * :func:`make_safe_httpx_client` — synchronous :class:`httpx.Client`
  * :func:`make_safe_httpx_async_client` — async :class:`httpx.AsyncClient`

Both return a standard httpx client augmented with TWO layers of SSRF
defense:

Layer 1 — ``response`` event-hook interceptor
    Inspects every 3xx response's ``Location`` header, resolves the
    redirect target's hostname via DNS, and raises
    :class:`SSRFRedirectBlockedError` (a subclass of
    :class:`httpx.RequestError`) if the resolved IP falls in any of
    the blocked internal networks:

      * ``127.0.0.0/8``       — IPv4 loopback
      * ``10.0.0.0/8``        — RFC 1918 private (Class A)
      * ``172.16.0.0/12``     — RFC 1918 private (Class B)
      * ``192.168.0.0/16``    — RFC 1918 private (Class C)
      * ``169.254.0.0/16``    — IPv4 link-local (AWS/GCP/Azure metadata)
      * ``::1/128``           — IPv6 loopback
      * ``fc00::/7``          — IPv6 unique-local (ULA)

Layer 2 — custom transport that pins the validated IP (V6 Absolute-Flawless)
    The hook validates the redirect target's DNS, but httpx resolves
    DNS a SECOND time when it actually opens the connection. A
    malicious DNS server can return a public IP for the first lookup
    (passing the hook) and an internal IP for the second lookup (when
    httpx connects) — the classic DNS-rebinding TOCTOU race.

    We close the race by installing a custom
    :class:`httpx.BaseTransport` (sync) / :class:`httpx.AsyncBaseTransport`
    (async) that:

      1. Resolves the request host once (via :func:`socket.getaddrinfo`).
      2. Checks every returned address against the blocklist —
         blocked IPs raise :class:`SSRFRedirectBlockedError` before
         any TCP connect.
      3. Re-writes the request URL's host to the validated IP literal
         so httpx's internal resolver never gets a chance to do a
         second, poisoned lookup. (The original ``Host`` header is
         preserved so virtual-hosted targets still route correctly.)

    This means even a DNS-rebinding attack that flips the A record
    between the hook's lookup and httpx's connect cannot land — the
    connection uses the EXACT IP the hook validated, not a fresh
    lookup. The hook and the transport share the same
    :func:`_is_blocked_host` checker, so the security posture is
    identical for origin requests and redirect targets.

V6 Absolute-Flawless P0 FIX (Async SSRF Bypass + DNS TOCTOU Race):
    The previous version only provided the sync factory. ``webhook.py``
    was using a raw ``httpx.AsyncClient`` and bypassing the guard
    entirely — an attacker-controlled webhook URL (set via
    ``WEBHOOK_URL``) could be pointed at internal services. The new
    :func:`make_safe_httpx_async_client` plugs that hole. Both
    factories now install the IP-pinning transport, closing the
    DNS-rebinding TOCTOU race that the hook alone could not prevent.

Usage
-----
Sync::

    from webpent.shared.http import make_safe_httpx_client
    with make_safe_httpx_client(timeout=10.0, follow_redirects=True, verify=True) as c:
        resp = c.get(url)

Async::

    from webpent.shared.http import make_safe_httpx_async_client
    async with make_safe_httpx_async_client(timeout=10.0, verify=True) as c:
        resp = await c.post(url, json=payload)

All caller-supplied keyword arguments (``timeout``, ``verify``,
``follow_redirects``, ``headers``, ``proxies``, etc.) are forwarded
verbatim to the underlying :class:`httpx.Client` /
:class:`httpx.AsyncClient`. Pre-existing user-supplied ``event_hooks``
are preserved and run alongside the SSRF guard. Pre-existing
``transport`` is honored ONLY if it is also an SSRFPinningTransport
instance; otherwise it is wrapped so the pinning runs first.

V7 P0 FIX (Private-IP auth/crawl blocker):
    The blocklist above previously had no concept of "this private IP
    is the engagement's own target" — it blocked an operator's own
    lab target (e.g. a DVWA VM at ``192.168.40.128``) exactly the same
    as it would block an attacker-controlled redirect to
    ``169.254.169.254``. That's correct for hosts discovered
    *mid-scan* but wrong for the engagement's declared target, which
    is the entire point of the framework.

    Every blocking chokepoint below (the sync/async pinning
    transports, the redirect guard, and the Playwright route/WebSocket
    guards) now consults
    :func:`webpent.shared.engagement_scope.is_engagement_target_host`
    before refusing a private/reserved-network host: if the host is
    the operator-declared engagement target, the connection is
    allowed even though it is RFC1918/loopback/link-local. Any OTHER
    private-network host — a redirect target, a crawled link, a
    webhook URL — is still blocked exactly as before. See
    ``shared/engagement_scope.py`` for how the allowlist is populated
    and scoped (one engagement's target per worker task/CLI run,
    never a process-wide setting).

    This replaces the old Dev-Mode ``mock_target_hosts`` allowlist,
    which has been removed entirely (see the P0 fix write-up): that
    allowlist was a separate, redundant mechanism that operators had
    to manage by hand and that did not even apply in Prod Mode, which
    was not the actual blocker for this bug.
"""

from __future__ import annotations

import contextvars
import ipaddress
import logging
import re
import socket
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

# Narrow typed error alias for callers; transport construction remains centralized here.
HTTPTransportError = httpx.HTTPError

from webpent.shared.engagement_scope import (
    get_engagement_target_hosts,
    is_engagement_origin_allowed,
    is_engagement_target_host,
    normalize_scope_host,
)
from webpent.shared.untrusted_content import wrap_httpx_response

logger = logging.getLogger(__name__)


# ===========================================================================
# V9 P3: Cookie sanitization helper (CRLF / header-injection safe).
# ===========================================================================
# Cookie names and values from Playwright or operator input could
# theoretically contain \r\n sequences that inject arbitrary HTTP headers.
# This helper strips CR and LF from both keys and values before they
# are concatenated into a Cookie header string. It is used by every
# tool wrapper and agent that constructs a Cookie header.

_CRLF_PATTERN = re.compile(r"[\r\n]")


def sanitize_cookie_pair(name: str, value: str) -> tuple[str, str]:
    """Strip CR/LF from a cookie name and value.

    Returns a (name, value) tuple with all \\r and \\n characters
    removed. This prevents CRLF injection into HTTP headers when
    cookie values are concatenated into a ``Cookie:`` header string.
    """
    safe_name = _CRLF_PATTERN.sub("", str(name)) if name else ""
    safe_value = _CRLF_PATTERN.sub("", str(value)) if value else ""
    return safe_name, safe_value


def build_cookie_header(cookies: dict[str, str] | None) -> str:
    """Build a sanitized Cookie header value from a dict.

    Returns a string like ``"PHPSESSID=abc; security=low"`` with all
    CR/LF characters stripped from both names and values. Returns an
    empty string if cookies is None or empty.
    """
    if not cookies:
        return ""
    parts: list[str] = []
    for k, v in cookies.items():
        safe_k, safe_v = sanitize_cookie_pair(k, v)
        if safe_k:
            parts.append(f"{safe_k}={safe_v}")
    return "; ".join(parts)


def sanitize_request_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """Return bounded, transport-safe operator/request headers.

    Cookie is deliberately excluded because session cookies have a dedicated
    validated channel. Host and hop-by-hop headers are excluded so callers
    cannot redirect or corrupt the transport; values containing CR/LF are
    rejected rather than silently transformed. Invalid entries fail closed by
    returning an empty mapping only for that entry.
    """
    if not headers:
        return {}
    forbidden = {
        "connection",
        "content-length",
        "cookie",
        "host",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
    result: dict[str, str] = {}
    for raw_name, raw_value in list(headers.items())[:32]:
        name, value = str(raw_name).strip(), str(raw_value).strip()
        if (
            not name
            or len(name) > 128
            or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
            or name.lower() in forbidden
            or len(value) > 2048
            or _CRLF_PATTERN.search(name)
            or _CRLF_PATTERN.search(value)
        ):
            continue
        result[name] = value
    return result


# ===========================================================================
# Blocklist of internal / reserved networks.
# ===========================================================================
# Tuple of IPv4Network / IPv6Network objects. Membership is checked via
# ``ip in net`` which is O(n) but n is tiny (7 entries) so the linear
# scan is faster than building a set or trie.
BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    # --- IPv4 ---
    ipaddress.ip_network("127.0.0.0/8"),  # IPv4 loopback
    ipaddress.ip_network("10.0.0.0/8"),  # RFC 1918 private (Class A)
    ipaddress.ip_network("172.16.0.0/12"),  # RFC 1918 private (Class B)
    ipaddress.ip_network("192.168.0.0/16"),  # RFC 1918 private (Class C)
    ipaddress.ip_network("169.254.0.0/16"),  # IPv4 link-local (cloud metadata)
    # V10 AUDIT FIX (H7): missing IPv4 ranges that allow SSRF bypass.
    ipaddress.ip_network("0.0.0.0/8"),  # "this host" network
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT shared address space (RFC 6598)
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1 (documentation)
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2 (documentation)
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3 (documentation)
    ipaddress.ip_network("240.0.0.0/4"),  # reserved (Class E)
    ipaddress.ip_network("255.255.255.255/32"),  # broadcast
    # V10 P3-10 FIX: additional missing IPv4 ranges that allow SSRF
    # bypass or otherwise should not be reachable from a pentest target
    # fetcher. Multicast (224.0.0.0/4) can be abused to scan local
    # multicast subscribers; benchmarking (198.18.0.0/15, RFC 2544) is
    # routable on some networks and used for SSRF pivots.
    ipaddress.ip_network("224.0.0.0/4"),  # IPv4 multicast (RFC 5771)
    ipaddress.ip_network("198.18.0.0/15"),  # RFC 2544 benchmarking
    # --- IPv6 ---
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique-local (ULA)
    # V10 AUDIT FIX (H7): missing IPv6 ranges that allow SSRF bypass.
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local (MISSING — critical)
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped IPv6 (bypass via ::ffff:169.254.169.254)
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64 (can reach IPv4 hosts via IPv6 translation)
    ipaddress.ip_network("2001:db8::/32"),  # documentation prefix
    # V10 P3-10 FIX: additional missing IPv6 ranges. The unspecified
    # address (::/128) is sometimes accepted by servers as "any local"
    # and can bypass naive allow-lists; multicast (ff00::/8) can scan
    # local IPv6 multicast subscribers.
    ipaddress.ip_network("::/128"),  # IPv6 unspecified
    ipaddress.ip_network("ff00::/8"),  # IPv6 multicast
)


class SSRFRedirectBlockedError(httpx.RequestError):
    """Raised when a request or redirect target points to an internal/blocked network.

    Subclasses :class:`httpx.RequestError` so callers that already
    handle transport errors (timeouts, connection resets, etc.) get
    the SSRF block for free without changing their exception handling.
    """


class RateLimitExceeded(httpx.RequestError):
    """Raised when the transport-level rate ceiling denies a request.

    M1-A (M-3): ``SSRFPinningTransport.handle_request`` — the chokepoint
    wrapping every client built by ``make_safe_httpx_client`` — enforces
    the process-wide :class:`GlobalRateGovernor` ceiling whenever
    ``settings.rate_limit_enabled`` is on.  Like the SSRF block it
    subclasses :class:`httpx.RequestError` so existing transport-error
    handling catches it without changes.

    UM-DR-34 §5 (default-on request governance): inside an ACTIVE
    ENGAGEMENT context the ceiling is ALWAYS on (independent of
    ``stealth_mode`` and of the legacy ``rate_limit_enabled`` switch),
    it applies to the ASYNC transport exactly as to the sync one, and
    a governor internal failure DENIES the request (fail-closed) — a
    governor bug must never silently un-limit a campaign.  Outside an
    engagement (plain library use / control plane) the legacy
    settings-gated, fail-open-on-governor-bug behavior is preserved.
    """


# ===========================================================================
# UM-DR-34 Phase 5 — one coherent transport rate gate (sync + async)
# ===========================================================================

def _engagement_rate_ceiling_active() -> bool:
    """Return True when the ACTIVE ENGAGEMENT ceiling is mandatory.

    Fail-closed on settings-load errors INSIDE an engagement (the
    ceiling must not silently disappear because settings failed to
    load, UM-DR-34 §5.4).
    """
    from webpent.shared.engagement_scope import get_engagement_context

    if get_engagement_context().egress_mode == "ENGAGEMENT":
        return True
    try:
        from webpent.config.settings import get_settings

        return bool(get_settings().rate_limit_enabled)
    except (ImportError, ValueError):  # legacy non-engagement posture
        logger.warning(
            "SSRF transport: settings unavailable while checking "
            "rate_limit_enabled — proceeding WITHOUT the rate ceiling "
            "(non-engagement context only).",
        )
        return False


def _transport_rate_gate(request: httpx.Request) -> tuple[bool, Any]:
    """Rate-ceiling admission for one transport-level request.

    Returns ``(granted, governor)``.  ``granted`` is False when the
    request exceeds the ceiling — the caller MUST raise
    :class:`RateLimitExceeded` and must NOT call ``release``.
    On success the caller MUST call ``governor.release(campaign_id)``
    in a ``finally`` block.

    Failure posture (UM-DR-34 §5.4):

    * ACTIVE ENGAGEMENT — a governor internal failure DENIES the
      request (fail-closed): ``granted=False``.
    * non-engagement — legacy posture preserved (fail-open + CRITICAL
      log) so a governor bug cannot take down unrelated tooling.
    """
    from webpent.shared.engagement_scope import get_engagement_context

    engagement = get_engagement_context().egress_mode == "ENGAGEMENT"
    from webpent.shared.global_rate_governor import get_global_rate_governor

    # One unique campaign id per in-flight request: the governor's
    # release() is all-or-nothing per campaign, so a shared id would
    # let the first finishing request release every concurrent
    # request's slot.  A per-request id makes each request hold
    # exactly its own unit for exactly its own lifetime.
    campaign = f"http-transport:{id(request):x}"
    governor = get_global_rate_governor()
    try:
        granted = governor.try_acquire(campaign)
    except (RuntimeError, ValueError, TypeError, KeyError, ArithmeticError):
        if engagement:
            # UM-DR-34 §5.4: an active campaign must not lose its
            # request ceiling to a governor bug — deny the request.
            logger.critical(
                "GlobalRateGovernor raised during try_acquire in an "
                "ACTIVE ENGAGEMENT — failing CLOSED: request to %s "
                "denied (rate ceiling could not be enforced).",
                request.url,
                exc_info=True,
            )
            return False, None
        logger.critical(
            "GlobalRateGovernor raised during try_acquire — failing "
            "OPEN (non-engagement context): request to %s proceeds, "
            "rate ceiling NOT enforced for this request. This is a "
            "governor bug and must be investigated.",
            request.url,
            exc_info=True,
        )
        return True, None
    if not granted:
        return False, None
    return True, (governor, campaign)


# ---------------------------------------------------------------------------
# M1-C (UM-DR-12): loopback-trusted-endpoint exemption
# ---------------------------------------------------------------------------
# The SSRF blocklist includes loopback (127.0.0.0/8, ::1) — correct for
# TARGET traffic. But two FIRST-PARTY channels legitimately talk to a
# loopback listener: the OOB poll against a local OAST collector and the
# notification dispatch to a local webhook receiver. M1-A's M-5 migration
# of both channels onto the safe transport made their documented
# "loopback allowed" rule unreachable (the transport vetoed it) and broke
# the OAST collector round-trip (4 live test failures). The exemption is
# CONTEXT-SCOPED (contextvar), LOOPBACK-ONLY (enforced here, not by the
# caller — a 192.168.x or 169.254.x host can never qualify), and DEFAULT-
# OFF: no other safe client changes behavior. Non-loopback private
# collectors stay blocked (M-5's pinned contract holds).
_LOOPBACK_TRUSTED_ENDPOINT: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "webpent_loopback_trusted_endpoint", default=False
)


def set_loopback_trusted_endpoint(enabled: bool = True) -> contextvars.Token:
    """Allow THIS execution context's safe-client requests to reach LOOPBACK.

    First-party infrastructure exception (M1-C, UM-DR-12): the OOB poll
    (``shared.oob.poll_remote_collector``) and notification dispatch
    (``integrations.notifications.dispatch._default_send``) set this around
    their single request when the operator-configured endpoint is a loopback
    listener. The exemption is enforced LOOPBACK-ONLY inside the transport —
    callers cannot widen it to any other host — and the default is OFF, so
    every other safe client (targets, redirects, webhooks to public hosts)
    keeps the exact M-5/M-1 behavior. Always reset the returned token in a
    ``finally`` block.
    """
    return _LOOPBACK_TRUSTED_ENDPOINT.set(bool(enabled))


def clear_loopback_trusted_endpoint(token: contextvars.Token | None = None) -> None:
    """Reset the loopback-trusted-endpoint flag (fail-closed)."""
    try:
        if token is not None:
            _LOOPBACK_TRUSTED_ENDPOINT.reset(token)
            return
    except (ValueError, LookupError):  # pragma: no cover — wrong-context reset falls through
        # (UM-DR-25: narrowed from broad Exception per the P-1 hygiene
        # contract — ContextVar reset errors are ValueError/LookupError.)
        pass
    try:
        _LOOPBACK_TRUSTED_ENDPOINT.set(False)
    except (ValueError, LookupError):  # pragma: no cover
        logger.warning(
            "clear_loopback_trusted_endpoint: failed to reset flag; "
            "context may retain the exemption until it ends."
        )


def _is_loopback_host(host: str | None) -> bool:
    """Return True only for literal or resolved IPv4/IPv6 LOOPBACK hosts."""
    if not host:
        return False
    cleaned = host.strip().strip("[]").lower()
    if not cleaned:
        return False
    if cleaned == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        return False  # hostnames never qualify — literal loopback only
    return ip.is_loopback


# ===========================================================================
# Internal helpers
# ===========================================================================
def _is_blocked_host(host: str | None) -> bool:
    """Return ``True`` if ``host`` resolves to a blocked network.

    Accepts either an IP literal (IPv4 or IPv6, with or without
    surrounding brackets) or a DNS hostname. For hostnames, we resolve
    via :func:`socket.getaddrinfo` and check every returned address —
    this defeats DNS-rebinding attacks where an attacker's nameserver
    returns a public IP for the first lookup (passing any naive
    allow-list check) and an internal IP for the second lookup (when
    httpx actually connects).
    """
    if not host:
        return False

    # Strip brackets from bracketed IPv6 literals like "[::1]".
    cleaned = host.strip().strip("[]")
    if not cleaned:
        return False

    # --- Case 1: host is already an IP literal ---
    try:
        ip = ipaddress.ip_address(cleaned)
        return any(ip in net for net in BLOCKED_NETWORKS)
    except ValueError:
        pass  # Not an IP literal — fall through to DNS resolution.

    # --- Case 2: host is a DNS hostname — resolve and check every A/AAAA ---
    try:
        infos = socket.getaddrinfo(cleaned, None)
    except (socket.gaierror, OSError) as exc:
        # DNS failure is intentionally fail-closed.  A hostname that cannot
        # be resolved is not evidence of a safe public destination, and
        # treating it as clean would let a later resolver/redirect path make
        # an independent decision.  Callers may surface this as an
        # infrastructure/inconclusive result, but never as a permitted host.
        logger.warning("SSRF host resolution failed for %s: %s", cleaned, exc)
        return True

    for _family, _stype, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if any(ip in net for net in BLOCKED_NETWORKS):
            return True
    return False


def _resolve_first_ip(
    host: str,
    port: int,
    *,
    allow_blocked: bool | None = None,
) -> str | None:
    """Resolve ``host`` to a single IP literal string.

    Returns the first A/AAAA record's IP as a string. IPv6 addresses
    are returned WITHOUT surrounding brackets (callers must add them
    when constructing a URL). Returns ``None`` if resolution fails or
    if every resolved IP is on the blocklist.

    Args:
        allow_blocked: If ``True``, a resolved IP on the private/
            reserved-network blocklist is still returned (used for
            DNS-pinning the engagement's OWN target when it is a
            hostname that happens to resolve to a private IP).
            Defaults to ``None``, which means "look up whether
            ``host`` is the current engagement's declared target via
            :func:`webpent.shared.engagement_scope.is_engagement_target_host`" —
            callers that already know the answer (e.g. because they
            are iterating a caller-supplied host list) may pass an
            explicit ``True``/``False`` to skip that lookup.
    """
    if allow_blocked is None:
        allow_blocked = is_engagement_target_host(host)
    try:
        infos = socket.getaddrinfo(host, port)
    except (socket.gaierror, OSError) as exc:
        # No usable pin means no connection.  This is deliberately a typed
        # fail-closed outcome rather than a fallback to httpx's resolver.
        logger.warning("DNS pinning failed for %s: %s", host, exc)
        return None
    for _family, _stype, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if not allow_blocked and any(ip in net for net in BLOCKED_NETWORKS):
            # Skip blocked IPs — but keep scanning for a public one
            # in case the hostname has both A and AAAA records. Not
            # applied when allow_blocked is True (engagement target).
            continue
        return ip_str
    return None


def _redirect_guard(response: httpx.Response) -> None:
    """``response`` event-hook that blocks SSRF via redirects (sync).

    Fires on every HTTP response received by the client. When the
    response is a 3xx redirect carrying a ``Location`` header, the
    hook resolves the redirect target and raises
    :class:`SSRFRedirectBlockedError` if it points at a blocked
    internal network. Raising inside the response hook aborts the
    redirect chain — httpx will not issue the next request, so even
    clients configured with ``follow_redirects=True`` are protected.

    Note: the custom transport also re-validates on the actual
    connection, so this hook is defence-in-depth — even if an
    attacker races the hook's DNS lookup, the transport's own
    lookup at connect-time will catch the rebinding.
    """
    _redirect_guard_decision(response)


async def _redirect_guard_async(response: httpx.Response) -> None:
    """Async twin of :func:`_redirect_guard` (UM-DR-34 §4.2).

    httpx awaits every response hook on the async client, so the async
    factory MUST register a coroutine function; delegating to the same
    synchronous decision keeps the two transports' redirect semantics
    byte-identical.
    """
    _redirect_guard_decision(response)


def _redirect_guard_decision(response: httpx.Response) -> None:
    """Shared redirect decision used by the sync and async guards."""
    # Only 3xx responses carry redirect semantics.
    if not (300 <= response.status_code < 400):
        return

    location = response.headers.get("location")
    if not location:
        return

    # ``Location`` may be a relative URL (``/new-path``) — resolve it
    # against the request URL to extract a usable host.
    try:
        redirect_url = str(response.url.join(location))
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        # Malformed Location — let httpx's own redirect handling
        # surface the error rather than crashing the hook.
        return

    host = urlsplit(redirect_url).hostname
    if not host:
        return

    # UM-DR-34 §4.3 — every redirect target undergoes a FRESH, FULL
    # scope decision (not an origin-only comparison).  The decision is
    # method-aware: 307/308 re-issue the original method, 301/302/303
    # downgrade to GET — a redirect is allowed only if the target
    # passes under the semantics it will actually be issued with.
    original_method = getattr(getattr(response, "request", None), "method", None) or "GET"
    if not is_engagement_origin_allowed(redirect_url, method=original_method) and not (
        original_method.upper() not in {"GET", "HEAD"}
        and is_engagement_origin_allowed(redirect_url, method="GET")
    ):
        logger.warning(
            "OriginPolicy blocked redirect from %s to out-of-scope origin %s "
            "(method=%s).",
            response.url,
            redirect_url,
            original_method,
        )
        raise SSRFRedirectBlockedError(
            f"Refusing to follow redirect outside the engagement OriginPolicy: {redirect_url}",
            request=response.request,
        )

    if _is_blocked_host(host) and not is_engagement_target_host(host):
        logger.warning(
            "SSRF guard: blocked redirect from %s to internal/reserved "
            "target %s (host=%s). Aborting redirect chain.",
            response.url,
            redirect_url,
            host,
        )
        raise SSRFRedirectBlockedError(
            f"Refusing to follow redirect to internal/reserved network: "
            f"{redirect_url} (host={host}). This protects WebPent from "
            f"being abused as an SSRF proxy against cloud metadata "
            f"(169.254.169.254) or internal Docker services.",
            request=response.request,
        )


def _attach_untrusted_content(response: httpx.Response) -> None:
    """Attach a masked target-content view without changing raw response data."""
    response.read()
    response.extensions["untrusted_content"] = wrap_httpx_response(
        response, source="response"
    )


async def _attach_untrusted_content_async(response: httpx.Response) -> None:
    """Async response-hook twin for the safe AsyncClient factory."""
    await response.aread()
    response.extensions["untrusted_content"] = wrap_httpx_response(
        response, source="response"
    )


# ===========================================================================
# Custom transports — DNS-pinning to defeat TOCTOU / DNS rebinding
# ===========================================================================
class SSRFPinningTransport(httpx.BaseTransport):
    """Sync transport that pins the validated IP for every connection.

    V6 Absolute-Flawless P0 FIX (DNS TOCTOU Race):
        httpx resolves DNS at connection time. If we validate a host
        in the event hook (Layer 1) and then let httpx re-resolve at
        connect-time (Layer 2), a malicious DNS server can return a
        public IP for the hook and an internal IP for the connect —
        the classic DNS-rebinding TOCTOU race.

        This transport resolves the host ONCE, validates every
        returned IP against the blocklist, and rewrites the request
        URL's host to the validated IP literal so httpx's internal
        resolver never gets a second, poisoned lookup. The original
        ``Host`` header is preserved so virtual-hosted targets still
        route correctly.

        The transport wraps an underlying ``httpx.HTTPTransport`` that
        actually opens the TCP connection — so all of httpx's normal
        connection pooling, HTTP/2 support, and timeout handling is
        preserved.
    """

    def __init__(self, wrapped: httpx.BaseTransport | None = None) -> None:
        # If no underlying transport is supplied, create a default
        # HTTPTransport. We use a fresh one rather than reusing
        # httpx's default so callers can still configure proxies /
        # HTTP/2 via the wrapped transport if they wish.
        self._wrapped: httpx.BaseTransport = wrapped or httpx.HTTPTransport()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Rate-ceiling gate (M1-A/M-3 + UM-DR-34 §5), then the pinned-IP pipeline.

        Inside an ACTIVE ENGAGEMENT the ceiling is ALWAYS on and a
        governor failure DENIES the request.  Outside an engagement the
        legacy ``rate_limit_enabled`` switch governs (default off for
        plain library use).
        """
        if not _engagement_rate_ceiling_active():
            return self._handle_request_pinned(request)

        granted, lease = _transport_rate_gate(request)
        if not granted:
            raise RateLimitExceeded(
                "Transport-level rate ceiling reached: request to "
                f"{request.url} denied.",
                request=request,
            )
        if lease is None:
            # Non-engagement fail-open path (governor bug, logged above).
            return self._handle_request_pinned(request)
        governor, campaign = lease
        try:
            return self._handle_request_pinned(request)
        finally:
            governor.release(campaign)

    def _handle_request_pinned(self, request: httpx.Request) -> httpx.Response:
        """Validate the request host, pin the IP, then delegate.

        V6 Titanium P1 FIX (httpx 0.27.x Read-Only URL & SNI Drop):
            The previous implementation mutated ``request.url`` in
            place via ``request.url = httpx.URL(new_url)``. Two
            problems:

              1. In httpx 0.27.x, ``Request.url`` is a read-only
                 property — assignment raises ``AttributeError``.
                 The mutation only "worked" on 0.28+ where ``url``
                 happens to be a plain instance attribute, but even
                 there it was an undocumented escape hatch.

              2. More importantly: rewriting the URL host to the
                 pinned IP causes httpx's TLS layer to send the
                 IP (not the original hostname) as the SNI
                 (Server Name Indication) in the TLS ClientHello.
                 Many HTTPS targets — especially those behind CDNs
                 or name-based virtual hosts — reject connections
                 whose SNI doesn't match a configured vhost,
                 producing cryptic TLS handshake failures that
                 look like the target is down.

            The fix: instead of mutating the request, CONSTRUCT A
            NEW ``httpx.Request`` with the pinned-IP URL, copy the
            original headers (so the wire ``Host`` header still
            carries the DNS name), copy the stream (so the body is
            preserved), and — critically — set
            ``new_request.extensions["sni_hostname"] = host`` so
            the TLS layer sends the ORIGINAL hostname as SNI even
            though the TCP connection goes to the pinned IP. The
            underlying ``httpx.HTTPTransport`` reads
            ``extensions["sni_hostname"]`` and uses it verbatim for
            the SNI, overriding the URL-derived hostname.

            This gives us all three properties simultaneously:
              * TCP connects to the pinned IP (no DNS rebinding).
              * HTTP ``Host`` header carries the original DNS name
                (vhost routing works).
              * TLS SNI carries the original DNS name (CDN/vhost
                TLS handshake succeeds).
        """
        host = urlsplit(str(request.url)).hostname
        if not host:
            # No host (e.g. relative URL with no base) — let the
            # underlying transport surface the error.
            return self._wrapped.handle_request(request)

        # M1-C (UM-DR-12): a loopback-trusted context may reach a loopback
        # listener (first-party OOB collector / local webhook receiver) even
        # when engagement origin policies are configured for the campaign —
        # the collector is infrastructure, not an engagement origin. The
        # exemption is loopback-ONLY and default-off (see module docstring
        # of set_loopback_trusted_endpoint).
        loopback_trusted = bool(
            _LOOPBACK_TRUSTED_ENDPOINT.get() and _is_loopback_host(host)
        )

        if not loopback_trusted and not is_engagement_origin_allowed(
            str(request.url), method=request.method
        ):
            raise SSRFRedirectBlockedError(
                f"Refusing to connect outside the engagement OriginPolicy: {request.url}",
                request=request,
            )

        # V7 P0 FIX: the engagement's own declared target is allowed
        # through the private/reserved-network blocklist below (see
        # webpent.shared.engagement_scope). Any OTHER host — including
        # any other private IP — is still blocked exactly as before.
        target_allowed = is_engagement_target_host(host) or loopback_trusted

        # V10 P1-1 (RCA follow-up): DEBUG log when a private/reserved
        # host is ALLOWED by the engagement scope, so the operator can
        # verify the allowlist wiring works end-to-end. Without this
        # log, a successful lab scan looks identical to a scan where
        # the SSRF guard was silently bypassed — operators had no
        # positive signal that the engagement-scope allowlist fired.
        if target_allowed and _is_blocked_host(host):
            logger.debug(
                "SSRF transport: ALLOWED private/reserved host %s via "
                "engagement-scope allowlist (operator-declared target). "
                "Request proceeds; all other private hosts remain blocked.",
                host,
            )

        # If host is already a blocked IP literal, block immediately
        # — unless it's the engagement's own target (or the loopback-
        # trusted first-party endpoint, M1-C UM-DR-12).
        if _is_blocked_host(host) and not target_allowed:
            logger.warning(
                "SSRF transport: blocked direct request to "
                "internal/reserved host %s. Aborting before connect.",
                host,
            )
            raise SSRFRedirectBlockedError(
                f"Refusing to connect to internal/reserved network: "
                f"host={host}. This protects WebPent from being abused "
                f"as an SSRF proxy.",
                request=request,
            )

        # If host is a DNS name, resolve and re-write the URL to the
        # IP literal so httpx doesn't do a second lookup. If host is
        # already a non-blocked IP literal, we skip the rewrite
        # entirely — the request goes through unchanged.
        try:
            ipaddress.ip_address(host.strip("[]"))
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False

        if not is_ip_literal:
            port = request.url.port or (443 if request.url.scheme == "https" else 80)
            pinned_ip = _resolve_first_ip(host, port, allow_blocked=target_allowed)
            if pinned_ip is None:
                # V10 P0-2 FIX (DNS-rebinding TOCTOU): The FIRST DNS
                # resolution above is AUTHORITATIVE. Either DNS failed
                # OR every resolved IP was blocked. We do NOT re-check
                # via _is_blocked_host() — that would trigger a SECOND
                # DNS lookup which a malicious DNS server could flip to
                # a public IP between the two calls, causing us to fall
                # through to the un-pinned request below and connect to
                # an internal IP. Fail CLOSED with no second DNS check.
                logger.warning(
                    "SSRF transport: refusing to connect to %s — first "
                    "DNS resolution returned no usable IP (DNS failed "
                    "or all resolved IPs blocked). Failing CLOSED to "
                    "prevent DNS-rebinding TOCTOU.",
                    host,
                )
                raise SSRFRedirectBlockedError(
                    f"Refusing to connect to {host}: first DNS "
                    f"resolution returned no usable IP (DNS failed or "
                    f"all resolved IPs in blocked networks). Failing "
                    f"closed to prevent DNS-rebinding TOCTOU.",
                    request=request,
                )

            # V6 Titanium P1: construct a NEW request instead of
            # mutating the original. The new request carries the
            # pinned-IP URL (so TCP connects to the validated IP),
            # the original headers (so the wire Host header carries
            # the DNS name for vhost routing), the original stream
            # (so the request body is preserved), and an
            # ``sni_hostname`` extension so the TLS layer sends the
            # original hostname as SNI (so CDN/vhost TLS handshakes
            # succeed).
            pinned_host = (
                f"[{pinned_ip}]"
                if ":" in pinned_ip  # IPv6 needs brackets in URL
                else pinned_ip
            )
            original_url = str(request.url)
            new_url = _replace_host_in_url(original_url, host, pinned_host)
            try:
                new_request = httpx.Request(
                    method=request.method,
                    url=new_url,
                    headers=dict(request.headers),
                    stream=request.stream,
                )
            except (AttributeError, OSError, RuntimeError, TypeError, ValueError, httpx.HTTPError) as exc:
                # V6 Diamond P1 FIX (CISO audit — Fail-Open TOCTOU):
                #   The previous implementation fell back to
                #   ``self._wrapped.handle_request(request)`` here,
                #   sending the ORIGINAL (un-pinned) request through.
                #   That re-introduced the DNS Time-of-Check to
                #   Time-of-Use (TOCTOU) race the transport exists
                #   to prevent: a malicious DNS server could return a
                #   public IP for the hook's validation lookup, then
                #   flip the A record to an internal IP for httpx's
                #   connection-time lookup — and the fallback path
                #   would happily connect to the internal IP.
                #
                #   A security component MUST fail closed. We raise
                #   ``SSRFRedirectBlockedError`` (a subclass of
                #   ``httpx.RequestError``) so the caller's existing
                #   transport-error handler catches it. The original
                #   exception is chained via ``from exc`` so the
                #   operator can see WHY reconstruction failed (e.g.
                #   the stream was already consumed by an upstream
                #   event hook).
                logger.warning(
                    "SSRF transport: failed to reconstruct request for "
                    "%s — failing CLOSED to prevent TOCTOU (original "
                    "error: %s).",
                    host,
                    exc,
                )
                raise SSRFRedirectBlockedError(
                    "Failed to rebuild request for IP pinning. Failing closed to prevent TOCTOU.",
                    request=request,
                ) from exc

            # Preserve the original DNS name in the wire Host header
            # so virtual-hosted targets route correctly. The new
            # request's headers were copied from the original, which
            # already had Host set — but httpx.Request construction
            # may have overwritten it from the pinned-IP URL, so we
            # set it explicitly here.
            new_request.headers["host"] = host
            # V6 Titanium P1: set the SNI hostname extension so the
            # TLS layer sends the ORIGINAL DNS name as SNI, not the
            # pinned IP. Without this, HTTPS targets behind CDNs or
            # name-based vhosts reject the TLS handshake because the
            # SNI doesn't match any configured vhost.
            new_request.extensions["sni_hostname"] = host
            logger.debug(
                "SSRF transport: pinned %s -> %s (Host + SNI preserved)",
                host,
                pinned_ip,
            )
            return self._wrapped.handle_request(new_request)

        return self._wrapped.handle_request(request)

    def close(self) -> None:
        self._wrapped.close()


class AsyncSSRFPinningTransport(httpx.AsyncBaseTransport):
    """Async transport that pins the validated IP for every connection.

    V6 Absolute-Flawless P0 FIX (Async SSRF Bypass + DNS TOCTOU Race):
        The async twin of :class:`SSRFPinningTransport`. Used by
        :func:`make_safe_httpx_async_client` so that ``webhook.py``
        (which uses ``httpx.AsyncClient``) is protected by the same
        SSRF guard as the sync paths.
    """

    def __init__(self, wrapped: httpx.AsyncBaseTransport | None = None) -> None:
        self._wrapped: httpx.AsyncBaseTransport = wrapped or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Rate-ceiling gate (UM-DR-34 §5 — async parity), then the pinned pipeline.

        The async transport applies the SAME rate ceiling, the SAME
        origin policy, the SAME private-target rules and the SAME
        loopback-trusted exemption as the sync transport — no reduced
        async policy (UM-DR-34 §4.2).
        """
        if _engagement_rate_ceiling_active():
            granted, lease = _transport_rate_gate(request)
            if not granted:
                raise RateLimitExceeded(
                    "Transport-level rate ceiling reached: async request "
                    f"to {request.url} denied.",
                    request=request,
                )
            if lease is not None:
                governor, campaign = lease
                try:
                    return await self._handle_request_pinned(request)
                finally:
                    governor.release(campaign)
            return await self._handle_request_pinned(request)
        return await self._handle_request_pinned(request)

    async def _handle_request_pinned(self, request: httpx.Request) -> httpx.Response:
        """Validate the request host, pin the IP, then delegate.

        V6 Titanium P1 FIX (httpx 0.27.x Read-Only URL & SNI Drop):
            Async twin of the sync transport's fix. Instead of mutating
            ``request.url``, a NEW ``httpx.Request`` is constructed with
            the pinned-IP URL, the original headers + stream are copied,
            and ``new_request.extensions["sni_hostname"] = host`` keeps
            the TLS SNI correct for CDN/vhost targets.
        """
        host = urlsplit(str(request.url)).hostname
        if not host:
            return await self._wrapped.handle_async_request(request)

        # M1-C (UM-DR-12) async twin: a loopback-trusted context may
        # reach a loopback listener (first-party OOB collector / local
        # webhook receiver) — loopback-ONLY, default-off, enforced here.
        loopback_trusted = bool(
            _LOOPBACK_TRUSTED_ENDPOINT.get() and _is_loopback_host(host)
        )

        if not loopback_trusted and not is_engagement_origin_allowed(
            str(request.url), method=request.method
        ):
            raise SSRFRedirectBlockedError(
                f"Refusing to connect outside the engagement OriginPolicy: {request.url}",
                request=request,
            )

        # V7 P0 FIX: async twin of the sync transport's check — the
        # engagement's own declared target is allowed through the
        # private/reserved-network blocklist below. Any OTHER host is
        # still blocked exactly as before.
        target_allowed = is_engagement_target_host(host) or loopback_trusted

        if _is_blocked_host(host) and not target_allowed:
            logger.warning(
                "SSRF async transport: blocked direct request to "
                "internal/reserved host %s. Aborting before connect.",
                host,
            )
            raise SSRFRedirectBlockedError(
                f"Refusing to connect to internal/reserved network: "
                f"host={host}. This protects WebPent from being abused "
                f"as an SSRF proxy.",
                request=request,
            )

        try:
            ipaddress.ip_address(host.strip("[]"))
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False

        if not is_ip_literal:
            port = request.url.port or (443 if request.url.scheme == "https" else 80)
            pinned_ip = _resolve_first_ip(host, port, allow_blocked=target_allowed)
            if pinned_ip is None:
                # V10 P0-2 FIX (DNS-rebinding TOCTOU): async twin of
                # the sync transport's fix. The FIRST DNS resolution is
                # AUTHORITATIVE — no second _is_blocked_host() check
                # (which would do another DNS lookup and re-open the
                # TOCTOU window). Fail CLOSED.
                logger.warning(
                    "SSRF async transport: refusing to connect to %s — "
                    "first DNS resolution returned no usable IP (DNS "
                    "failed or all resolved IPs blocked). Failing CLOSED "
                    "to prevent DNS-rebinding TOCTOU.",
                    host,
                )
                raise SSRFRedirectBlockedError(
                    f"Refusing to connect to {host}: first DNS "
                    f"resolution returned no usable IP (DNS failed or "
                    f"all resolved IPs in blocked networks). Failing "
                    f"closed to prevent DNS-rebinding TOCTOU.",
                    request=request,
                )

            # V6 Titanium P1: construct a NEW request instead of
            # mutating the original. See the sync transport for the
            # full rationale — the same SNI-preservation logic
            # applies here.
            pinned_host = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
            original_url = str(request.url)
            new_url = _replace_host_in_url(original_url, host, pinned_host)
            try:
                new_request = httpx.Request(
                    method=request.method,
                    url=new_url,
                    headers=dict(request.headers),
                    stream=request.stream,
                )
            except (AttributeError, OSError, RuntimeError, TypeError, ValueError, httpx.HTTPError) as exc:
                # V6 Diamond P1 FIX (CISO audit — Fail-Open TOCTOU):
                #   The previous implementation fell back to
                #   ``await self._wrapped.handle_async_request(request)``
                #   here, sending the ORIGINAL (un-pinned) request
                #   through. That re-introduced the DNS Time-of-Check
                #   to Time-of-Use (TOCTOU) race the transport exists
                #   to prevent: a malicious DNS server could return a
                #   public IP for the hook's validation lookup, then
                #   flip the A record to an internal IP for httpx's
                #   connection-time lookup — and the fallback path
                #   would happily connect to the internal IP.
                #
                #   A security component MUST fail closed. We raise
                #   ``SSRFRedirectBlockedError`` (a subclass of
                #   ``httpx.RequestError``) so the caller's existing
                #   transport-error handler catches it. The original
                #   exception is chained via ``from exc`` so the
                #   operator can see WHY reconstruction failed.
                logger.warning(
                    "SSRF async transport: failed to reconstruct request "
                    "for %s — failing CLOSED to prevent TOCTOU (original "
                    "error: %s).",
                    host,
                    exc,
                )
                raise SSRFRedirectBlockedError(
                    "Failed to rebuild request for IP pinning. Failing closed to prevent TOCTOU.",
                    request=request,
                ) from exc

            new_request.headers["host"] = host
            # V6 Titanium P1: preserve the original DNS name as SNI
            # so HTTPS targets behind CDNs / vhosts accept the TLS
            # handshake even though TCP connects to the pinned IP.
            new_request.extensions["sni_hostname"] = host
            logger.debug(
                "SSRF async transport: pinned %s -> %s (Host + SNI preserved)",
                host,
                pinned_ip,
            )
            return await self._wrapped.handle_async_request(new_request)

        return await self._wrapped.handle_async_request(request)

    async def aclose(self) -> None:
        await self._wrapped.aclose()


def _replace_host_in_url(url: str, old_host: str, new_host: str) -> str:
    """Replace the host portion of ``url`` with ``new_host``.

    Preserves scheme, port, path, query, and fragment. Handles
    bracketed IPv6 hosts correctly.
    """
    parts = urlsplit(url)
    # Preserve netloc's userinfo and port.
    netloc = parts.netloc
    # Strip the old host from netloc, keeping userinfo@ and :port.
    if "@" in netloc:
        userinfo, _, rest = netloc.partition("@")
        prefix = userinfo + "@"
    else:
        rest = netloc
        prefix = ""
    # ``rest`` is now ``host[:port]``. Replace the host portion.
    if rest.startswith("["):
        # Bracketed IPv6 — find the closing bracket.
        end = rest.find("]")
        if end == -1:
            # Malformed — fall through to literal replacement.
            new_rest = rest.replace(old_host, new_host, 1)
        else:
            port_suffix = rest[end + 1 :]  # includes ":port" if present
            new_rest = new_host + port_suffix
    else:
        # Plain host or IPv4 — split on the first ':' for the port.
        if ":" in rest:
            _host, _, port_suffix = rest.partition(":")
            new_rest = new_host + ":" + port_suffix
        else:
            new_rest = new_host
    new_netloc = prefix + new_rest
    return urlunsplit(parts._replace(netloc=new_netloc))


# ===========================================================================
# Public factories
# ===========================================================================
def make_safe_httpx_client(**kwargs: Any) -> httpx.Client:
    """Construct a hardened synchronous :class:`httpx.Client` that blocks SSRF.

    The returned client behaves identically to a stock
    ``httpx.Client(**kwargs)`` — same timeout, same verify, same
    follow_redirects, same transport semantics — except that TWO
    layers of SSRF defence are installed:

      1. A ``response`` event-hook interceptor inspects every 3xx
         ``Location`` header and raises
         :class:`SSRFRedirectBlockedError` if the redirect target
         resolves to a blocked internal network.
      2. A custom :class:`SSRFPinningTransport` resolves every
         request host ONCE, validates every IP against the blocklist,
         and rewrites the request URL to the validated IP literal so
         httpx's internal resolver cannot be poisoned by a
         DNS-rebinding TOCTOU attack.

    Parameters
    ----------
    **kwargs
        Forwarded verbatim to :class:`httpx.Client`. Commonly used
        keys include ``timeout``, ``verify``, ``follow_redirects``,
        ``headers``, ``max_redirects``, ``proxies``, and
        ``event_hooks``. If the caller supplies its own
        ``event_hooks``, those hooks are preserved and the SSRF
        guard is appended alongside them. If the caller supplies
        its own ``transport``, it is WRAPPED by the
        :class:`SSRFPinningTransport` so the SSRF check runs first
        and the caller's transport handles the actual TCP connect.

    Returns
    -------
    httpx.Client
        A configured, hardened client. Use it as a context manager
        (``with make_safe_httpx_client(...) as c:``) so the
        underlying connection pool is closed cleanly.

    Raises
    ------
    SSRFRedirectBlockedError
        Raised at request-time (not at construction-time) when a
        server response carries a redirect to a blocked network,
        OR when a direct request's host resolves to a blocked
        network. The exception subclasses
        :class:`httpx.RequestError`, so any existing
        ``except httpx.RequestError`` or ``except httpx.HTTPError``
        handler will catch it.
    """
    # TLS verification is a non-optional safety invariant.  Reject an
    # explicit false value rather than silently accepting a downgrade.
    if kwargs.pop("verify", True) is False:
        raise ValueError("TLS certificate verification cannot be disabled")
    kwargs["verify"] = True

    guard_redirects = bool(kwargs.pop("guard_redirects", True))

    # Pop the caller's event_hooks (if any) so we can merge ours in
    # without clobbering them.
    user_hooks: dict[str, list[Any]] = dict(kwargs.pop("event_hooks", None) or {})

    # Attach the masked response projection first, then preserve caller hooks,
    # then apply the redirect guard.
    response_hooks: list[Any] = [_attach_untrusted_content]
    response_hooks.extend(user_hooks.get("response", []))
    if guard_redirects:
        response_hooks.append(_redirect_guard)
    user_hooks["response"] = response_hooks

    # Wrap any caller-supplied transport in the SSRF-pinning transport
    # so the pinning runs first. If no transport was supplied, we let
    # SSRFPinningTransport create its own default HTTPTransport.
    user_transport = kwargs.pop("transport", None)
    pinning_transport = SSRFPinningTransport(wrapped=user_transport)

    return httpx.Client(
        event_hooks=user_hooks,
        transport=pinning_transport,
        **kwargs,
    )


def make_safe_httpx_async_client(**kwargs: Any) -> httpx.AsyncClient:
    """Construct a hardened async :class:`httpx.AsyncClient` that blocks SSRF.

    V6 Absolute-Flawless P0 FIX (Async SSRF Bypass):
        The async twin of :func:`make_safe_httpx_client`. Used by
        :mod:`webpent.integrations.webhook` so that webhook pushes
        to attacker-controllable URLs cannot be abused as an SSRF
        vector. Both the response event-hook AND the
    :class:`AsyncSSRFPinningTransport` are installed, identical to
    the sync factory.

    Parameters
    ----------
    **kwargs
        Forwarded verbatim to :class:`httpx.AsyncClient`. Same
        semantics as :func:`make_safe_httpx_client`.

    Returns
    -------
    httpx.AsyncClient
        A configured, hardened async client. Use it as an async
        context manager
        (``async with make_safe_httpx_async_client(...) as c:``) so
        the underlying connection pool is closed cleanly.

    Raises
    ------
    SSRFRedirectBlockedError
        Raised at request-time when a redirect target OR a direct
        request's host resolves to a blocked internal network.
    """
    # TLS verification is a non-optional safety invariant.  Reject an
    # explicit false value rather than silently accepting a downgrade.
    if kwargs.pop("verify", True) is False:
        raise ValueError("TLS certificate verification cannot be disabled")
    kwargs["verify"] = True

    # Same hook-merging logic as the sync factory.
    user_hooks: dict[str, list[Any]] = dict(kwargs.pop("event_hooks", None) or {})

    # UM-DR-34 §4.2 (latent async defect fix): httpx AWAITS every
    # response hook on the async client — the sync ``_redirect_guard``
    # returns None and ``await None`` raises TypeError, so the async
    # factory used to crash on every successful (non-redirect!) response
    # the moment a hook chain ran.  Existing coverage only exercised
    # transport-level denials, which bypass the hook chain entirely —
    # the defect surfaced with the first successful async response.
    # The redirect decision itself is identical to the sync guard.
    response_hooks: list[Any] = [_attach_untrusted_content_async]
    response_hooks.extend(user_hooks.get("response", []))
    response_hooks.append(_redirect_guard_async)
    user_hooks["response"] = response_hooks

    # Wrap any caller-supplied transport in the async SSRF-pinning
    # transport.
    user_transport = kwargs.pop("transport", None)
    pinning_transport = AsyncSSRFPinningTransport(wrapped=user_transport)

    return httpx.AsyncClient(
        event_hooks=user_hooks,
        transport=pinning_transport,
        **kwargs,
    )


# ===========================================================================
# Playwright SSRF guard (V6 Zero-Day Patched P0-1 / V6 The-Final-Seal P0,
# revised to pin via --host-resolver-rules instead of URL rewriting)
# ===========================================================================
def resolve_host_for_pinning(hostname: str, port: int = 443) -> str | None:
    """Resolve ``hostname`` to a single safe IP for launch-time pinning.

    Thin, public wrapper around :func:`_resolve_first_ip` so callers
    that launch a Chromium browser (rather than route an httpx/Playwright
    request) can build ``--host-resolver-rules`` arguments without
    reaching into this module's private helpers.

    Args:
        hostname: A DNS name (IP literals should not be passed here —
            they need no pinning; callers should check with
            ``ipaddress.ip_address`` first and skip this call).
        port: Port used only to select the address family/service during
            resolution; has no bearing on which IP is returned.

    Returns:
        The first resolved IP address that is NOT in a blocked/reserved
        network, or ``None`` if DNS resolution failed or every resolved
        address was blocked. A ``None`` return means the caller should
        NOT launch a browser against this host at all (or should launch
        without pinning and rely solely on the route-handler block, at
        the caller's discretion for non-security-critical paths).
    """
    return _resolve_first_ip(hostname, port)


def build_host_resolver_rules_args(*hostnames: str) -> list[str]:
    """Build Chromium ``--host-resolver-rules`` launch args that pin DNS.

    V6 Final-Seal-Revised (CISO audit follow-up — Playwright DNS TOCTOU,
    corrected mechanism):
        This is the ONLY way to pin a Chromium connection to a
        pre-validated IP without breaking TLS SNI / certificate
        validation for HTTPS targets. Unlike rewriting the request URL
        (the original, broken approach — see
        :func:`install_playwright_ssrf_guard`'s docstring), a
        ``--host-resolver-rules=MAP host ip`` launch argument makes
        Chromium substitute ``ip`` only at the socket-connection layer;
        Chromium's TLS stack still believes it is talking to ``host``
        and sends ``host`` as SNI and validates the certificate against
        ``host``, exactly as if no pinning were in effect.

        Each hostname passed in is resolved ONCE, here, before the
        browser exists — closing the DNS-rebinding race for that host
        completely (there is no second, connection-time resolution to
        race against, because Chromium never resolves a MAP-covered
        host itself). Hostnames that fail resolution or resolve
        exclusively to blocked/internal addresses are SKIPPED (not
        included in the rule set) rather than raising, so callers can
        decide how to handle "target itself is unresolvable/internal"
        as an application-level concern (e.g. aborting the scan) rather
        than a transport-level exception; combined with the
        block-or-allow route handler installed by
        :func:`install_playwright_ssrf_guard`, a skipped/unpinned host
        still cannot reach a blocked network — it is simply not
        pinned, so ordinary (non-adversarial) DNS resolution applies
        and the route handler's live check is the backstop.

        IP literals (the host is already an address, not a DNS name)
        are skipped silently — there is nothing to pin.

    Args:
        *hostnames: One or more DNS names to pin (typically just the
            target URL's host; callers MAY add known auxiliary hosts,
            e.g. an auth redirect target known in advance, but cannot
            cover hosts only discovered at request time).

    Returns:
        A list suitable for ``playwright.chromium.launch(args=...)``.
        Empty if no hostname could be safely resolved (callers still
        get the route-handler backstop with zero pinning in that case).

    Example::

        args = build_host_resolver_rules_args("example.com")
        browser = pw.chromium.launch(headless=True, args=args)
    """
    rules: list[str] = []
    for hostname in hostnames:
        if not hostname:
            continue
        try:
            ipaddress.ip_address(hostname.strip("[]"))
            continue  # already an IP literal — nothing to pin
        except ValueError:
            pass
            # Intentionally suppressed — reviewed 2026-09-03
        pinned_ip = _resolve_first_ip(hostname, 443)
        if pinned_ip is None:
            logger.warning(
                "Host-resolver pinning: could not resolve %s to a safe "
                "IP (DNS failure or every address is internal/reserved) "
                "— launching WITHOUT pinning for this host; the "
                "route-handler block is the only protection for it.",
                hostname,
            )
            continue
        rules.append(f"MAP {hostname} {pinned_ip}")
        logger.debug(
            "Host-resolver pinning: %s -> %s (SNI/cert validation "
            "unaffected — Chromium still believes it is connecting "
            "to %s)",
            hostname,
            pinned_ip,
            hostname,
        )
    if not rules:
        return []
    return [f"--host-resolver-rules={', '.join(rules)}"]


def install_playwright_ssrf_guard(
    context: Any,
    *,
    target_hosts: Any = None,
) -> None:
    """Install network-interception routes on a Playwright browser context.

    V7 P0 FIX (Private-IP auth/crawl blocker):
        ``target_hosts``, if given, is an iterable of hostnames/IPs
        that belong to the CURRENT engagement's own declared target
        (pass the same value you gave
        :func:`webpent.shared.engagement_scope.set_engagement_target_hosts`,
        or just the target URL's hostname). These hosts are allowed
        through the private/reserved-network blocklist below — the
        engagement's own private-IP lab target must be reachable.
        If omitted, defaults to
        :func:`webpent.shared.engagement_scope.get_engagement_target_hosts`
        (the ambient engagement-scope allowlist), read ONCE here in
        the calling thread and captured by value in the handler
        closures below — NOT re-read per-request — because
        Playwright's Python sync API may invoke route-handler
        callbacks off the calling stack frame, where a
        ``contextvars.ContextVar`` lookup would not reliably see the
        value set by the caller. Any host that is not in this set is
        still blocked exactly as before, including other private IPs
        discovered mid-navigation (redirects, sub-resources).

    V6 Zero-Day Patched P0-1 FIX (CISO audit — Playwright SSRF Bypass):
        While ``httpx`` is secured against SSRF via the
        :class:`SSRFPinningTransport` and the ``response`` event-hook
        interceptor, Playwright's ``browser.new_context()`` has NO
        built-in network interception. Without an explicit ``route``
        handler, Playwright happily navigates to internal IP addresses
        (``169.254.169.254`` AWS metadata, ``redis:6379`` Docker DNS,
        ``127.0.0.1`` loopback, etc.) — turning the framework's own
        browser into an SSRF proxy that exfiltrates cloud metadata or
        probes internal services.

        This helper installs a ``context.route("**/*", handler)`` that
        inspects EVERY outgoing HTTP request (main-frame navigation,
        sub-resource fetches, XHR/fetch). The handler parses the request
        URL, extracts the hostname, and delegates to
        :func:`_is_blocked_host` — the same checker used by the
        httpx SSRF guard. If the host resolves to a blocked internal
        network, the request is aborted with
        ``route.abort("accessdenied")``; otherwise,
        ``route.continue_()`` lets it proceed normally.

    V6 The-Final-Seal P0-1 FIX, SUPERSEDED (CISO audit — Playwright
    WebSocket SSRF Bypass; corrected in V6 Ready-For-Kali):
        ``context.route("**/*")`` does NOT intercept WebSocket
        connections in Playwright. Malicious JavaScript can open a
        ``new WebSocket("ws://redis:6379")`` and bypass the HTTP route
        guard entirely — exfiltrating data or probing internal services
        over the WS protocol. This round attempted to ALSO install a
        ``context.routeWebSocket("**/*", _ssrf_websocket_handler)``
        that would inspect every outgoing WebSocket connection,
        resolve the hostname, and abort internal-network targets with
        ``route.abort("accessdenied")`` — but ``routeWebSocket``
        (camelCase) and ``route.abort()``/``route.continue_()`` are
        the **JavaScript/TypeScript** API shape. Neither exists on
        Python's ``BrowserContext`` (which only has
        ``route_web_socket``, snake_case) or on ``WebSocketRoute``
        (which has ``close()`` / ``connect_to_server()``, not
        ``abort()``/``continue_()``). Registration therefore always
        raised ``AttributeError``, was silently caught, and the
        WebSocket guard never actually installed — this fix shipped
        as dead code across two further audit rounds before being
        caught by a Python-API introspection check
        (``hasattr(BrowserContext, "route_web_socket")``) rather than
        by code review alone. See V6 Ready-For-Kali below for the
        corrected implementation.

    V6 Ready-For-Kali FIX (CISO audit — WebSocket guard corrected):
        Re-registers via ``context.route_web_socket("**/*", ...)``
        (the actual Python method name) with a handler matching the
        real single-argument ``WebSocketRoute`` callback contract.
        Blocking now means never calling ``ws.connect_to_server()``
        (Playwright opens no real network connection unless told to)
        plus an explicit ``ws.close(code=1008, reason="accessdenied")``
        so the page's JS observes an immediate, unambiguous failure.

    V6 The-Final-Seal P0-2 FIX, SUPERSEDED (CISO audit — Playwright DNS
    TOCTOU Race, revised after a follow-up review):
        The original P0-2 fix resolved DNS to check the host, then
        called ``route.continue_(url=safe_ip_url, headers={"Host":
        original_host})`` — rewriting the request URL to the pinned IP
        literal while preserving the DNS name only in the HTTP ``Host``
        header. That closed the DNS-rebinding race but broke HTTPS:
        Playwright's ``route.continue_()`` has no parameter to control
        the TLS SNI value, so Chromium derives SNI from the URL it is
        actually connecting to. Once the URL held a raw IP, Chromium
        sent the IP as SNI (or none at all) instead of the original
        hostname, and validated the server's certificate against the
        IP rather than the DNS name. Every SNI-vhosted or
        certificate-bound HTTPS target — i.e. nearly the entire modern
        web — would fail to load with a certificate/handshake error.
        Host headers only affect HTTP-layer routing; they cannot
        retroactively change what TLS believes it is connecting to.

        The corrected fix moves IP pinning to the ONLY layer that can
        do it without touching SNI: the Chromium **process launch
        arguments**. ``--host-resolver-rules="MAP host ip"`` tells
        Chromium's own resolver to substitute ``ip`` for ``host``
        internally — Chromium still believes (and tells the TLS
        stack, via SNI, and the cert-validation logic) that it is
        connecting to ``host``; only the underlying socket target
        changes. See :func:`build_host_resolver_rules_args` and
        :func:`resolve_host_for_pinning`, which the Playwright-launching
        call sites now use to build ``args=[...]`` for
        ``chromium.launch()`` *before* creating a context.

        Because ``--host-resolver-rules`` is fixed at browser-launch
        time, it can only cover hostnames known in advance (the target
        URL's host, and any explicitly-added auth/redirect hosts). The
        route/route_web_socket handlers below remain installed as a
        **second, independent layer**: they still resolve and reject
        (``route.abort("accessdenied")``) any request to a blocked
        internal network, covering hosts discovered only at runtime
        (redirects, cross-origin subresources, WebSocket targets) that
        the launch-time pinning could not have known about. For those
        runtime-discovered hosts, the handlers now intentionally do
        **not** rewrite the URL — they only block-or-allow — so a
        residual DNS-rebinding TOCTOU window remains for hosts outside
        the pinned set. This is a deliberate, documented trade-off:
        it fully closes the rebinding race for the primary target (the
        common case, and the one Playwright is actually asked to
        navigate to) while preserving HTTPS functionality everywhere,
        at the cost of a narrower residual race against a fully
        adversarial DNS server for secondary/unplanned hosts.

    Usage::

        from webpent.shared.http import (
            build_host_resolver_rules_args,
            install_playwright_ssrf_guard,
        )
        launch_args = build_host_resolver_rules_args(target_hostname)
        browser = pw.chromium.launch(headless=True, args=launch_args)
        context = browser.new_context()
        install_playwright_ssrf_guard(context)  # before new_page() / goto()
        page = context.new_page()
        page.goto(url)

    Args:
        context: A ``playwright.sync_api.BrowserContext`` (sync) or
            ``playwright.async_api.BrowserContext`` (async). The
            ``route()`` and ``route_web_socket()`` methods have the same
            signature in both APIs — the handlers are plain callables,
            so this helper works for sync and async Playwright alike.
        target_hosts: Optional iterable of hostnames/IPs for the
            current engagement's own target. Defaults to the ambient
            engagement-scope allowlist (see V7 P0 FIX note above).
    """
    if target_hosts is None:
        allowed_hosts = get_engagement_target_hosts()
    else:
        allowed_hosts = frozenset(
            normalized for item in target_hosts if (normalized := normalize_scope_host(str(item)))
        )

    def _ssrf_route_handler(route: Any, request: Any) -> None:
        """Playwright HTTP route handler: block-or-allow, no URL rewrite.

        V6 Final-Seal-Revised: no longer rewrites the request URL to a
        pinned IP (see the module/function docstring above for why that
        broke TLS SNI). This handler is a pure allow/deny gate — the
        actual DNS pinning for the known target host happens once, at
        browser-launch time, via ``--host-resolver-rules`` (see
        :func:`build_host_resolver_rules_args`). For hosts NOT covered
        by launch-time pinning (redirects, cross-origin subresources),
        this handler still blocks the obvious case (a static redirect
        straight to a blocked internal network) even though a fully
        adversarial DNS server could still win a narrow TOCTOU race
        against it — a documented, accepted residual risk.
        """
        try:
            request_url = request.url
            host = urlsplit(str(request_url)).hostname
            if not host:
                # No host (e.g. data: URLs, about:blank) — let it
                # through; these cannot carry SSRF payloads.
                route.continue_()
                return
            if not is_engagement_origin_allowed(
                str(request_url), method=getattr(request, "method", None)
            ):
                logger.warning(
                    "Playwright OriginPolicy blocked request to out-of-scope origin %s.",
                    request_url,
                )
                route.abort("accessdenied")
                return
            # V7 P0 FIX: allow the engagement's own declared target
            # through the blocklist (allowed_hosts was captured by
            # value when this closure was created — see the V7 P0
            # note on install_playwright_ssrf_guard). Any other
            # private/reserved host is still blocked.
            if _is_blocked_host(host) and normalize_scope_host(host) not in allowed_hosts:
                logger.warning(
                    "Playwright SSRF guard: blocked navigation/fetch to "
                    "internal/reserved host %s (url=%s). Aborting with "
                    "accessdenied.",
                    host,
                    request_url,
                )
                route.abort("accessdenied")
                return
            # V10 P1-1 (RCA follow-up): DEBUG log when a private host
            # is ALLOWED by the engagement scope, mirroring the httpx
            # transport's allow-log. Positive signal that the allowlist
            # wiring fired for Playwright too.
            if _is_blocked_host(host) and normalize_scope_host(host) in allowed_hosts:
                logger.debug(
                    "Playwright SSRF guard: ALLOWED private/reserved host "
                    "%s via engagement-scope allowlist (url=%s).",
                    host,
                    request_url,
                )
            route.continue_()
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError, httpx.HTTPError) as exc:
            # Defensive: never let the route handler crash the
            # browser. Fail-closed for ambiguous cases.
            # V10 AUDIT FIX (H8): the previous version had a
            # ``route.continue_()`` fallback when ``route.abort()``
            # itself raised — this was FAIL-OPEN, contradicting the
            # "fail-closed" comment. A request that crashed the handler
            # AND caused route.abort to fail was ALLOWED through. Now:
            # if route.abort fails, we log the error but do NOT fall
            # through to continue_() — the request is dropped (the
            # browser sees a navigation failure, which is the correct
            # fail-closed behavior).
            logger.warning(
                "Playwright SSRF guard: error inspecting request %s "
                "(%s) — aborting as accessdenied (fail-closed).",
                getattr(request, "url", "<unknown>"),
                exc,
            )
            try:
                route.abort("accessdenied")
            except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as abort_exc:
                # route.abort itself failed — we cannot allow the
                # request through. Log and drop (do NOT continue_()).
                logger.error(
                    "Playwright SSRF guard: route.abort ALSO failed "
                    "for %s (%s) — DROPPING request (fail-closed, "
                    "no continue_ fallback).",
                    getattr(request, "url", "<unknown>"),
                    abort_exc,
                )

    def _ssrf_websocket_handler(ws: Any) -> None:
        """Playwright WebSocket route handler: block-or-allow, no URL rewrite.

        V6 Ready-For-Kali P0 FIX (CISO audit — WebSocket guard never
        installed): the previous implementation was written against
        the JS/TS API shape (``context.routeWebSocket``, camelCase,
        never present on Python's ``BrowserContext``) and against the
        HTTP ``Route`` contract (a two-argument ``(route, request)``
        callback using ``.abort()``/``.continue_()``, neither of
        which exists on ``WebSocketRoute``). Verified empirically
        against the installed ``playwright`` package:
        ``hasattr(BrowserContext, "routeWebSocket")`` is ``False``
        (only ``route_web_socket``, snake_case, exists), and
        ``WebSocketRoute`` exposes ``close()`` / ``connect_to_server()``
        / ``on_message()`` / ``send()`` / ``url`` — no ``abort()`` or
        ``continue_()``. Both mistakes meant registration always threw
        ``AttributeError``, was silently swallowed below, and the
        WebSocket SSRF bypass identified in an earlier round was never
        actually mitigated.

        The real ``route_web_socket`` callback receives a SINGLE
        ``WebSocketRoute`` argument. Playwright does not open a real
        network connection for a WebSocket unless the handler calls
        ``ws.connect_to_server()`` — so blocking is simply "don't call
        it" (plus an explicit page-side close so the page's JS sees an
        immediate, unambiguous failure rather than a socket that hangs
        open and never receives anything). We do not rewrite the
        connection target for the same SNI-safety reason the HTTP
        handler no longer does (``wss://`` connections are also TLS
        handshakes).
        """
        try:
            request_url = ws.url
            host = urlsplit(str(request_url)).hostname
            if not host:
                # No host — shouldn't happen for WS, but be defensive.
                ws.connect_to_server()
                return
            if not is_engagement_origin_allowed(str(request_url)):
                logger.warning(
                    "Playwright OriginPolicy blocked WebSocket to out-of-scope origin %s.",
                    request_url,
                )
                ws.close(code=1008, reason="accessdenied")
                return
            if _is_blocked_host(host) and normalize_scope_host(host) not in allowed_hosts:
                logger.warning(
                    "Playwright SSRF guard: blocked WebSocket to "
                    "internal/reserved host %s (url=%s). Closing "
                    "page-side socket with policy-violation (1008); "
                    "never connecting to the real server.",
                    host,
                    request_url,
                )
                ws.close(code=1008, reason="accessdenied")
                return
            ws.connect_to_server()
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError, httpx.HTTPError) as exc:
            logger.warning(
                "Playwright SSRF guard: error inspecting WebSocket %s "
                "(%s) — closing as policy-violation (fail-closed).",
                getattr(ws, "url", "<unknown>"),
                exc,
            )
            with contextlib_suppress():
                ws.close(code=1008, reason="accessdenied")

    # Install both route guards transactionally. A context without either
    # guard is unsafe, so registration failures must propagate to the caller
    # before it creates a page or performs navigation.
    http_registered = False
    try:
        # "**/*" matches every URL scheme and path for HTTP-family requests
        # (navigations, sub-resources, fetches, and XHR).
        context.route("**/*", _ssrf_route_handler)
        http_registered = True
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError, httpx.HTTPError) as exc:
        logger.error(
            "Failed to install Playwright HTTP SSRF route guard: %s — "
            "refusing to continue with an unprotected browser context.",
            exc,
        )
        raise RuntimeError("Playwright HTTP SSRF guard installation failed") from exc

    try:
        # WebSocket routing is a separate API because WS connections are not
        # HTTP requests despite their ws:// / wss:// URL schemes.
        context.route_web_socket("**/*", _ssrf_websocket_handler)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError, httpx.HTTPError) as exc:
        # Roll back the HTTP registration when Playwright exposes unroute().
        # If rollback itself fails, the context is still unusable and the
        # original registration error remains the actionable failure.
        if http_registered:
            try:
                context.unroute("**/*", _ssrf_route_handler)
            except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as rollback_exc:
                logger.error(
                    "Failed to roll back Playwright HTTP SSRF guard after "
                    "WebSocket guard failure: %s",
                    rollback_exc,
                )
        logger.error(
            "Failed to install Playwright WebSocket SSRF route guard: %s — "
            "refusing to continue with a partially protected context.",
            exc,
        )
        raise RuntimeError("Playwright WebSocket SSRF guard installation failed") from exc


class ContextlibSuppressContext:
    """Tiny stand-in for contextlib.suppress to avoid a module-level import.

    Used only inside the route handler's defensive fallback so we don't
    add a module-level ``import contextlib`` to http.py (keeping the
    import block minimal). Equivalent to ``contextlib.suppress(Exception)``.
    """

    def __enter__(self) -> None:
        pass

    def __exit__(self, *_exc_info: object) -> bool:
        return True


def contextlib_suppress() -> ContextlibSuppressContext:
    """Return a suppress() context manager without importing contextlib."""
    return ContextlibSuppressContext()
