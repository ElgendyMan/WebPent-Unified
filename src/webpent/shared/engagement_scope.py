# src/webpent/shared/engagement_scope.py
"""webpent.shared.engagement_scope

V7 P0 FIX — Private-IP auth/crawl blocker.

Root cause this module fixes
-----------------------------
``shared/http.py``'s SSRF guard (httpx transports + Playwright route
guard) blocks ALL RFC1918/loopback/link-local hosts unconditionally —
including the operator's own engagement target when that target is a
private lab host (e.g. ``192.168.40.128`` DVWA). This is correct
behaviour for hosts discovered *mid-scan* (redirects, crawled links,
webhook URLs) but wrong for the engagement's own declared target: a
pentest engagement against a private lab or internal corporate host is
the framework's entire purpose, so the target itself can never be
"out of scope for being private."

This module is the single source of truth for "is this host the
engagement's own declared target". Nothing else may bypass the SSRF
blocklist:

  * Only the operator-declared target (``ScanRequest.url`` / CLI
    ``--url`` / ``state["target"].url``) is ever added to the
    allowlist — see :func:`set_engagement_target_hosts`.
  * Hosts discovered mid-scan (redirect targets, crawled links, DNS
    results, webhook URLs) are NEVER added here. They remain subject
    to the private-network blocklist in ``shared/http.py`` and to
    ``scope_enforcer`` for newly-discovered hosts. This is what keeps
    WebPent from becoming an open SSRF proxy.

Threading / concurrency notes
------------------------------
The allowlist is stored in a :class:`contextvars.ContextVar` so it is
scoped to the current thread/async-task tree, not to the whole
process. A Celery worker process handles one engagement per task
invocation; the entry points (``run_pentest_task``,
``resume_pentest_task``, the Typer CLI) set the allowlist immediately
before invoking the graph and clear it in a ``finally`` block, so a
worker process reused for a *different* engagement never inherits the
previous scan's target host.

``contextvars`` propagate to code called directly (including
``async``/``await`` chains within the same task) but do **not**
automatically propagate into a manually-created ``threading.Thread``.
Callers that spawn raw threads which need the allowlist (there is
exactly one such caller — the business-logic-fuzzer's concurrent
burst sender) must read :func:`get_engagement_target_hosts` in the
parent thread and pass the resulting value explicitly, or use
``contextvars.copy_context().run(...)`` to start the thread. See the
"Risks" note in the P0 fix write-up for the current status of that
call site.

For the same reason, ``shared/http.py``'s Playwright guard does not
rely on ambient context lookups inside the route-handler callback
(Playwright's Python sync API may dispatch callbacks off the calling
stack frame). Instead, :func:`get_engagement_target_hosts` is read
ONCE, in the calling thread, at ``install_playwright_ssrf_guard()``
time, and the resulting frozenset is captured directly in the handler
closures — a plain variable reference that works correctly regardless
of which thread/greenlet Playwright invokes the callback from.
"""

from __future__ import annotations

import contextvars
import ipaddress
import logging
from dataclasses import dataclass, field
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
_COMPATIBLE_PROTOCOLS = {
    "http": frozenset({"http", "ws"}),
    "https": frozenset({"https", "wss"}),
    "ws": frozenset({"ws", "http"}),
    "wss": frozenset({"wss", "https"}),
}


@dataclass(frozen=True)
class OriginPolicy:
    """Exact transport policy for one declared engagement origin.

    Host matching is exact (never a suffix/subdomain match). Ports use the
    scheme's effective default when omitted, and paths use a segment-boundary
    prefix so ``/app`` does not accidentally allow ``/app2``. Empty methods
    means all methods; protocols defaults to the HTTP/WebSocket pair that
    shares the same TLS posture.
    """

    scheme: str
    hostname: str
    effective_port: int
    path_prefix: str = "/"
    methods: frozenset[str] = field(default_factory=frozenset)
    protocols: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_url(
        cls,
        value: str,
        *,
        methods: frozenset[str] | set[str] | None = None,
        protocols: frozenset[str] | set[str] | None = None,
    ) -> OriginPolicy:
        parsed = urlsplit(str(value).strip())
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        if (
            scheme not in _DEFAULT_PORTS
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError(
                "OriginPolicy requires an http(s)/ws(s) URL with a host and no userinfo"
            )
        hostname = _normalize_hostname(hostname)
        if not hostname:
            raise ValueError("OriginPolicy hostname is invalid")

        port = parsed.port or _DEFAULT_PORTS[scheme]

        if not 1 <= port <= 65535:
            raise ValueError("OriginPolicy port must be between 1 and 65535")
        path = parsed.path or "/"
        if not path.startswith("/"):
            path = f"/{path}"
        path = path.rstrip("/") or "/"
        normalized_methods = frozenset(str(item).upper() for item in (methods or ()))
        normalized_protocols = frozenset(
            str(item).lower() for item in (protocols or _COMPATIBLE_PROTOCOLS[scheme])
        )
        return cls(
            scheme=scheme,
            hostname=hostname,
            effective_port=port,
            path_prefix=path,
            methods=normalized_methods,
            protocols=normalized_protocols,
        )

    def allows(self, value: str, *, method: str | None = None) -> bool:
        """Return whether a URL belongs to this exact origin policy."""
        try:
            parsed = urlsplit(str(value).strip())
            scheme = parsed.scheme.lower()
            if parsed.username is not None or parsed.password is not None:
                return False
            hostname = _normalize_hostname(parsed.hostname or "")
            port = parsed.port or _DEFAULT_PORTS.get(scheme)
            if not hostname or port is None:
                return False
            if scheme not in self.protocols:
                return False
            if hostname != self.hostname or port != self.effective_port:
                return False
            path = parsed.path or "/"
            if self.path_prefix != "/" and not (
                path == self.path_prefix or path.startswith(f"{self.path_prefix}/")
            ):
                return False
            return not self.methods or (method or "GET").upper() in self.methods
        except (TypeError, ValueError):
            return False


_ENGAGEMENT_TARGET_HOSTS: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar(
    "webpent_engagement_target_hosts", default=frozenset()
)
_ENGAGEMENT_ORIGIN_POLICIES: contextvars.ContextVar[tuple[OriginPolicy, ...]] = (
    contextvars.ContextVar("webpent_engagement_origin_policies", default=())
)


def normalize_scope_host(value: str | None) -> str | None:
    """Return the exact normalized host from a URL, host, or IP literal."""
    return _extract_host(value or "")


def _normalize_hostname(value: str) -> str | None:
    """Canonicalize DNS/IDNA names and IP literals for exact comparisons."""
    cleaned = str(value or "").strip().strip("[]").rstrip(".")
    if not cleaned:
        return None
    # ``localhost`` is the hostname browsers commonly use for a local
    # frontend while the operator may declare the same companion origin as
    # ``127.0.0.1``.  Canonicalise this one loopback alias for exact
    # engagement-scope comparisons only; it does not add any host to the
    # allowlist and therefore cannot broaden an unscoped request.
    if cleaned.lower() == "localhost":
        return "127.0.0.1"
    try:
        return ipaddress.ip_address(cleaned).compressed.lower()
    except ValueError:
        try:
            return cleaned.encode("idna").decode("ascii").lower().rstrip(".")
        except (UnicodeError, ValueError):
            return None


def _extract_host(value: str) -> str | None:
    """Extract a canonical hostname from a URL or bare host/IP string."""
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    # urlsplit needs a scheme (or "//") to recognise a netloc, so bare
    # hosts/IPs ("192.168.40.128") need the "//" prefix; full URLs
    # ("http://192.168.40.128/dvwa") already parse correctly.
    parsed = urlsplit(value if "://" in value else f"//{value}")
    host = parsed.hostname
    if not host:
        return None
    return _normalize_hostname(host)


def normalize_declared_origins(
    values: list[str] | tuple[str, ...] | None,
    *,
    max_items: int = 8,
) -> list[str]:
    """Validate and normalize operator-declared companion HTTP origins.

    Origins are explicit scope input, never discovered data.  Credentials,
    query strings, fragments, non-HTTP schemes, malformed ports, and more
    than ``max_items`` values are rejected fail-closed.
    """
    raw_values = list(values or [])
    if len(raw_values) > max_items:
        raise ValueError(f"at most {max_items} additional target origins are allowed")
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_value in raw_values:
        value = str(raw_value).strip()
        if not value:
            raise ValueError("additional target origins must not be blank")
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("additional target origins must be absolute HTTP(S) URLs")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("additional target origins cannot contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("additional target origins cannot contain query or fragment")
        try:
            _ = parsed.port
            canonical = value.rstrip("/") or value
            OriginPolicy.from_url(canonical)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid additional target origin: {value!r}") from exc
        if canonical not in seen:
            seen.add(canonical)
            normalized.append(canonical)
    return normalized


_LINK_LOCAL_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    # Cloud-metadata / link-local — NEVER a legitimate pentest target.
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
)


def _host_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return the parsed IP if ``host`` is a literal address, else None."""
    cleaned = host.strip("[]").lower()
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        return None


def admission_target_check(url: str, *, allow_private_target: bool = False) -> None:
    """F-06 (0.33.0): server-side admission gate for engagement targets.

    Contract (mirrors ``shared/target_spec.py``: ``allow_private_target``
    defaults to False and requires explicit operator confirmation):

    - Link-local (169.254.0.0/16, fe80::/10 — cloud metadata) is refused
      UNCONDITIONALLY. No confirmation flag can admit it.
    - Other private/loopback/ULA address literals are refused unless
      ``allow_private_target=True`` (the operator-confirmed lab case).
    - Hostnames are NOT resolved here on purpose: the SSRF pinning
      transport keeps enforcing the blocklist at connection time, so
      admission stays cheap and cannot be TOCTOU'd via DNS TTLs.

    Raises ``ValueError`` with a stable reason token on refusal.
    """
    if not url or not str(url).strip():
        raise ValueError("admission_target_url_required")
    try:
        host = (urlsplit(str(url)).hostname or "").strip().lower()
    except ValueError as exc:
        raise ValueError("admission_target_malformed_url") from exc
    if not host:
        raise ValueError("admission_target_host_required")
    ip = _host_ip_literal(host)
    if ip is None:
        return  # hostname — connection-time SSRF guard remains authoritative
    if any(ip in network for network in _LINK_LOCAL_NETWORKS):
        raise ValueError("admission_target_link_local_forbidden")
    if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast:
        if not allow_private_target:
            raise ValueError("admission_target_private_requires_confirmation")


def set_engagement_target_hosts(*urls_or_hosts: str | None) -> contextvars.Token:
    """Declare the host(s) that belong to the CURRENT engagement's own target.

    Call this ONCE per engagement, immediately before invoking the
    graph (``graph.invoke`` / ``graph.ainvoke``), with the
    operator-declared target URL(s) only. Accepts full URLs
    (``http://192.168.40.128/dvwa``) or bare hosts/IPs
    (``192.168.40.128``); either form is normalised to a bare,
    lower-cased hostname for comparison.

    Do NOT call this with anything other than the operator-declared
    engagement target. Hosts discovered mid-scan must never be added
    here — that would defeat the SSRF blocklist entirely.

    Returns the :class:`contextvars.Token` from the underlying
    ``ContextVar.set()`` call so the caller can restore the previous
    value via :func:`clear_engagement_target_hosts` in a ``finally``
    block.
    """
    hosts: set[str] = set()
    for item in urls_or_hosts:
        if not item:
            continue
        host = _extract_host(item)
        if host:
            # F-06 (0.33.0) defence in depth: link-local (cloud metadata)
            # can never be declared an engagement target, no matter which
            # caller reaches this function. Private lab targets stay
            # allowed here — the confirmation gate lives at API admission
            # (:func:`admission_target_check`).
            ip = _host_ip_literal(host)
            if ip is not None and any(
                ip in network for network in _LINK_LOCAL_NETWORKS
            ):
                raise ValueError(
                    f"engagement_target_link_local_forbidden:{host}"
                )
            hosts.add(host)
    frozen = frozenset(hosts)
    policies: list[OriginPolicy] = []
    for item in urls_or_hosts:
        if not item or "://" not in item:
            continue
        try:
            policies.append(OriginPolicy.from_url(item))
        except ValueError:
            logger.warning("Ignoring malformed engagement origin: %r", item)
    _ENGAGEMENT_ORIGIN_POLICIES.set(tuple(policies))
    token = _ENGAGEMENT_TARGET_HOSTS.set(frozen)
    logger.info(
        "Engagement target-host allowlist set: %s; origin policies=%s",
        sorted(frozen),
        len(policies),
    )
    return token


def clear_engagement_target_hosts(token: contextvars.Token | None = None) -> None:
    """Reset the engagement target-host allowlist.

    Always call this in a ``finally`` block after the engagement
    finishes (success, failure, or exception) so a worker process —
    or the CLI process, in a long-running shell session — never
    carries one engagement's target allowlist into the next.

    If ``token`` (from the matching :func:`set_engagement_target_hosts`
    call) is supplied, the ContextVar is reset to its prior value
    (correct for nested/rare re-entrant use). If ``token`` is omitted
    or the reset fails (e.g. wrong context), the allowlist is forced
    back to empty — fail-closed.
    """
    try:
        if token is not None:
            _ENGAGEMENT_TARGET_HOSTS.reset(token)
            _ENGAGEMENT_ORIGIN_POLICIES.set(())
            return
    except Exception:
        logger.debug(
            "clear_engagement_target_hosts: token reset failed — forcing allowlist to empty.",
            exc_info=True,
        )
    try:
        _ENGAGEMENT_TARGET_HOSTS.set(frozenset())
        _ENGAGEMENT_ORIGIN_POLICIES.set(())
    except Exception:
        logger.warning(
            "clear_engagement_target_hosts: failed to clear allowlist.",
            exc_info=True,
        )


def get_engagement_origin_policies() -> tuple[OriginPolicy, ...]:
    """Return the current engagement's exact origin policies."""
    return _ENGAGEMENT_ORIGIN_POLICIES.get()


def is_engagement_origin_allowed(value: str, *, method: str | None = None) -> bool:
    """Check a URL against the current origin policy, if configured.

    Returning ``True`` when no policy is configured preserves legacy callers
    that use the HTTP helpers outside a graph engagement.
    """
    policies = get_engagement_origin_policies()
    return not policies or any(policy.allows(value, method=method) for policy in policies)


def get_engagement_target_hosts() -> frozenset[str]:
    """Return the current engagement's declared target host(s), if any."""
    return _ENGAGEMENT_TARGET_HOSTS.get()


def is_engagement_target_host(host: str | None) -> bool:
    """Return True only if ``host`` is the current engagement's own declared target.

    This is the ONLY thing that lets the SSRF guard connect to a
    private/reserved-network host: an exact (case-insensitive) match
    against the operator-declared target set by
    :func:`set_engagement_target_hosts`. No wildcard or subdomain
    matching — a host discovered mid-scan that merely shares a domain
    with the target is NOT automatically allowed; that is
    ``scope_enforcer``'s job, not this module's.

    Fail-closed: any error normalising ``host`` returns ``False``.
    """
    if not host:
        return False
    try:
        cleaned = _normalize_hostname(host)
    except Exception:
        return False
    return bool(cleaned and cleaned in _ENGAGEMENT_TARGET_HOSTS.get())
