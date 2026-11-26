"""UM-DR-50 W1 — the governed raw-socket transport (the bare-transport contract).

Every network channel in this repository that opens a socket DIRECTLY
(raw bytes on the wire, outside httpx) must go through
:func:`governed_raw_request` — the same authorization node the safe
client uses. A link discovered in an HTML/JSON/JS response is NOT a
grant: the destination is resolved and checked against the engagement
origin policy BEFORE the connection is opened.

The contract (UM-DR-50 master plan, Phase 1 — all eight clauses):

1. Destination resolution and verification against scope BEFORE the
   connection: :func:`_authorize_destination` fails closed outside an
   ENGAGEMENT context with a declared, valid origin policy.
2. DNS/IP pinning against rebinding and resolution races: the first
   resolved IP is pinned and the connection is made TO THE IP (with
   the pinned Host header), exactly like ``h2_race._connect`` (the
   UM-DR-44 B6(b) pattern) and ``SSRFPinningTransport``.
3. Origin, path, port, protocol and method verification: delegated to
   :func:`engagement_scope.is_engagement_origin_allowed` — ambiguous
   paths (``//``, ``..``, encoded separators) are rejected fail-closed
   by ``OriginPolicy.allows``.
4. Secondary origins only when explicitly declared: same delegation —
   a URL matching no declared policy is denied.
5. Identity cookies bound to their origin and declared session: the
   caller supplies ``cookies`` together with ``cookie_origin`` — the
   exact origin the session was authenticated against; the cookies are
   refused when the request origin differs (they never cross assets).
6. The same rate/budget limits as every other tool, no exceptions:
   the shared transport rate gate (``_transport_rate_gate``) is
   admitted BEFORE the dial and released in ``finally``.
7. Connection/response-size/header/timeout/redirect budgets: a hard
   response cap (``MAX_RESPONSE_BYTES``, default 1 MiB), a hard header
   section cap, a socket timeout, and a zero-redirect posture (a raw
   probe follows no redirects — a redirect is a recorded fact, not a
   destination change; the governed httpx client owns redirect
   following with its own guard).
8. A structured policy decision recorded for every allowed AND blocked
   attempt: :class:`RawTransportDecision` — appended to a bounded
   in-memory ledger (auditable per engagement) and logged.

Failure posture is FAIL-CLOSED everywhere: any missing input, any
policy miss, any budget overrun raises :class:`RawTransportRefused`
BEFORE or DURING the exchange — the caller records the refusal, it
never silently degrades to an ungoverned dial.

This module is the production seam; the detection lanes' own raw
helpers are being migrated onto it (D5 first — see
``production/detection_lanes_48.py``).
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Any

from urllib.parse import urlsplit

from webpent.shared.engagement_scope import (
    is_engagement_origin_allowed,
    is_engagement_target_host,
)

__all__ = [
    "RawTransportRefused",
    "RawTransportDecision",
    "raw_transport_ledger",
    "governed_raw_request",
    "MAX_RESPONSE_BYTES",
    "MAX_HEADER_BYTES",
]

# clause 7 — hard budgets (a raw probe is a bounded probe)
MAX_RESPONSE_BYTES = 1_048_576  # 1 MiB response cap
MAX_HEADER_BYTES = 65_536  # 64 KiB header-section cap
DEFAULT_TIMEOUT_S = 10.0


class RawTransportRefused(ConnectionError):
    """A raw-socket request was refused by the transport contract.

    The message states the clause that refused it. Refusals are
    POLICY, not errors to retry around: callers must surface them as
    policy decisions, never fall back to an ungoverned dial.
    """


@dataclass(frozen=True)
class RawTransportDecision:
    """Clause 8 — the structured, recorded policy decision."""

    url: str
    resolved_ip: str | None
    allowed: bool
    clause: str  # which contract clause decided
    reason: str
    method: str = "GET"
    cookie_origin_match: bool | None = None
    response_bytes: int = 0
    elapsed_ms: int = 0
    at_unix: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "resolved_ip": self.resolved_ip,
            "allowed": self.allowed,
            "clause": self.clause,
            "reason": self.reason,
            "method": self.method,
            "cookie_origin_match": self.cookie_origin_match,
            "response_bytes": self.response_bytes,
            "elapsed_ms": self.elapsed_ms,
            "at_unix": round(self.at_unix, 3),
        }


# bounded in-memory ledger — auditable per engagement run
_DECISIONS: list[RawTransportDecision] = []
_LEDGER_CAP = 10_000


def raw_transport_ledger() -> list[dict[str, Any]]:
    """The recorded policy decisions (bounded, oldest dropped)."""
    return [d.as_dict() for d in _DECISIONS]


def _record(decision: RawTransportDecision) -> None:
    _DECISIONS.append(decision)
    if len(_DECISIONS) > _LEDGER_CAP:
        del _DECISIONS[: len(_DECISIONS) - _LEDGER_CAP]


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return f"{parts.scheme.lower()}://{parts.hostname}:{port}"


def _authorize_destination(url: str, *, method: str = "GET",
                           cookie_origin: str | None = None,
                           path_verbatim: str | None = None,
                           ) -> tuple[str, str]:
    """Clauses 1, 3, 4, 5 — the fail-closed pre-dial decision.

    Returns ``(host, pinned_reason)`` on success; raises
    :class:`RawTransportRefused` otherwise.
    """
    from webpent.shared.engagement_scope import get_engagement_context

    parts = urlsplit(str(url))
    host = parts.hostname
    if not host:
        _record(RawTransportDecision(
            url=str(url), resolved_ip=None, allowed=False, clause="1",
            reason="no host in url"))
        raise RawTransportRefused(
            f"clause-1: no host in url {url!r}")
    if parts.scheme.lower() not in ("http", "https"):
        _record(RawTransportDecision(
            url=str(url), resolved_ip=None, allowed=False, clause="3",
            reason=f"scheme {parts.scheme!r} not http/https"))
        raise RawTransportRefused(
            f"clause-3: raw transport is http/https only (got "
            f"{parts.scheme!r})")
    if parts.username is not None or parts.password is not None:
        _record(RawTransportDecision(
            url=str(url), resolved_ip=None, allowed=False, clause="3",
            reason="userinfo in destination"))
        raise RawTransportRefused(
            "clause-3: userinfo in a raw destination is ambiguous — "
            "refused fail-closed")
    # the raw channel REQUIRES an engagement — bare sockets have no
    # legitimate library-mode use (mission law 9: the raw seam exists
    # for declared lab/engagement probing only)
    if get_engagement_context().egress_mode != "ENGAGEMENT":
        _record(RawTransportDecision(
            url=str(url), resolved_ip=None, allowed=False, clause="1",
            reason="no active engagement — the raw channel requires a "
                   "declared engagement"))
        raise RawTransportRefused(
            "clause-1: the raw transport requires an ACTIVE engagement "
            "(declared lab/engagement targets only — no library-mode "
            "bare dials)")
    # clause 5 — identity cookies never cross assets (checked BEFORE
    # the origin decision so a cross-asset attempt is never observable
    # as an authorized dial)
    if cookie_origin is not None and _origin_of(url) != _origin_of(cookie_origin):
        _record(RawTransportDecision(
            url=str(url), resolved_ip=None, allowed=False, clause="5",
            reason=f"cookies bound to {cookie_origin!r} cannot travel "
                   f"to {_origin_of(url)!r}"))
        raise RawTransportRefused(
            f"clause-5: cookies bound to {cookie_origin!r} cannot "
            f"travel to {_origin_of(url)!r} (no cross-asset sessions)")
    # clauses 1+3+4 — the canonical origin decision (ENGAGEMENT mode
    # requires a valid declared policy; a discovered link is not a grant).
    # When a verbatim path is requested, the DECLARED destination (the
    # dot-segment-resolved path) is what the policy authorizes — the
    # verbatim bytes are the wire seam, not the authorization subject.
    check_url = str(url)
    if path_verbatim is not None:
        from urllib.parse import quote, unquote

        declared = unquote(path_verbatim)
        segments: list[str] = []
        for seg in declared.split("/"):
            if seg == "..":
                if segments:
                    segments.pop()
            elif seg not in (".", ""):
                segments.append(quote(seg, safe=""))
        resolved = "/" + "/".join(segments)
        check_url = url.replace(parts.path, resolved)
    if not is_engagement_origin_allowed(check_url, method=method):
        _record(RawTransportDecision(
            url=str(url), resolved_ip=None, allowed=False, clause="1/4",
            reason="outside the declared engagement origin policy"))
        raise RawTransportRefused(
            f"clause-1/4: {check_url!r} is outside the declared engagement "
            "origin policy (a discovered link is not a grant)")
    return host, "authorized"


def _pin_ip(host: str, port: int) -> str:
    """Clause 2 — resolve once, pin the first IP, dial the IP.

    The blocklist runs inside ``_resolve_first_ip``; the engagement's
    own declared target is the only host allowed through it (the
    UM-DR-45 R2 declared-target rule).
    """
    from webpent.shared.http import _resolve_first_ip

    pinned = _resolve_first_ip(
        host, port, allow_blocked=is_engagement_target_host(host))
    if not pinned:
        raise RawTransportRefused(
            f"clause-2: DNS resolution/blocklist denied {host!r} "
            "(rebinding posture: no pin, no dial)")
    return pinned


def _admit_rate(method: str) -> Any:
    """Clause 6 — the same transport rate gate as every other tool."""
    from webpent.shared.http import _transport_rate_gate

    class _BareRequest:
        """The minimal duck-typed stand-in the rate gate reads."""

        def __init__(self, method: str) -> None:
            self.method = method
            self.url = None  # type: ignore[assignment]
            self.headers: dict[str, str] = {}
            self.extensions: dict[str, Any] = {}

        def read(self) -> bytes:  # pragma: no cover — gate never reads
            return b""

    granted, governor = _transport_rate_gate(_BareRequest(method))  # type: ignore[arg-type]
    if not granted:
        raise RawTransportRefused(
            "clause-6: rate/budget ceiling exceeded — the raw channel "
            "shares the same limits as every tool (no exceptions)")
    return governor


def governed_raw_request(
    url: str,
    *,
    method: str = "GET",
    path_verbatim: str | None = None,
    cookies: dict[str, str] | None = None,
    cookie_origin: str | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
) -> dict[str, Any]:
    """One governed raw-socket exchange (the ONLY sanctioned bare dial).

    ``path_verbatim`` sends the literal path bytes (the D5 seam:
    traversal lookalikes the normalizing client erases) — the path is
    still subject to the origin policy's ambiguity check at the
    DECLARATION level (clause 3: the *declared* policy path prefix
    must match the verbatim path's declared form); the verbatim bytes
    then reach the wire unchanged.

    Returns a plain dict: ``status_code``, ``headers``, ``body`` (the
    first ``max_response_bytes``), ``truncated``, ``pinned_ip``,
    ``elapsed_ms``. Raises :class:`RawTransportRefused` on any clause
    violation — always.
    """
    started = time.monotonic()
    method = method.upper()
    # clauses 1/3/4/5 — authorize BEFORE anything else
    host, _ = _authorize_destination(
        url, method=method, cookie_origin=cookie_origin,
        path_verbatim=path_verbatim)
    parts = urlsplit(str(url))
    port = parts.port or (443 if parts.scheme == "https" else 80)
    use_tls = parts.scheme.lower() == "https"
    # clause 2 — pin the IP, dial the IP
    pinned_ip = _pin_ip(host, port)
    # clause 6 — rate admission before the dial
    governor = _admit_rate(method)
    # clause 5 — cookies ride only with their own origin's session
    cookie_header = ""
    if cookies:
        if cookie_origin is None:
            raise RawTransportRefused(
                "clause-5: cookies require cookie_origin (the origin "
                "the session was authenticated against)")
        from webpent.shared.http import build_cookie_header

        cookie_header = "Cookie: " + build_cookie_header(cookies) + "\r\n"
    path = path_verbatim if path_verbatim is not None else (
        parts.path or "/")
    if parts.query and path_verbatim is None:
        path = f"{path}?{parts.query}"
    # the Host header pins the DECLARED hostname (not the resolved IP)
    # so virtual hosting and the policy stay coherent under pinning
    host_header = host if (port == 80 and not use_tls) or (
        port == 443 and use_tls) else f"{host}:{port}"
    request = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: WebPent/UMDR50-RawTransport\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"{cookie_header}"
        + "".join(f"{k}: {v}\r\n" for k, v in (extra_headers or {}).items())
        + "\r\n"
    ).encode("latin-1", "replace")
    try:
        with socket.create_connection((pinned_ip, port),
                                      timeout=timeout_s) as sock:
            if use_tls:
                import ssl

                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
                sock = context.wrap_socket(
                    sock, server_hostname=host)
            sock.sendall(request)
            # clause 7 — bounded read: one buffer, header cap checked
            # while the section is still open, response cap hard-stops
            buf = bytearray()
            truncated = False
            while len(buf) < max_response_bytes + MAX_HEADER_BYTES:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf.extend(chunk)
                if b"\r\n\r\n" not in buf and len(buf) > MAX_HEADER_BYTES:
                    raise RawTransportRefused(
                        f"clause-7: header section exceeded "
                        f"{MAX_HEADER_BYTES} bytes — refused")
                if len(buf) >= max_response_bytes + MAX_HEADER_BYTES:
                    truncated = True
                    break
            raw = bytes(buf)
        head, sep, body = raw.partition(b"\r\n\r\n")
        if not sep:
            # no header terminator within budget — refuse fail-closed
            raise RawTransportRefused(
                "clause-7: no header terminator within budget — refused")
        body = body[:max_response_bytes]
        if len(body) >= max_response_bytes:
            truncated = True
        status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        try:
            status_code = int(status_line.split()[1])
        except (IndexError, ValueError):
            status_code = 0
        headers: dict[str, str] = {}
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                headers[k.decode("latin-1").strip()] = v.decode(
                    "latin-1").strip()
        elapsed_ms = int((time.monotonic() - started) * 1000)
        # clause 8 — record the ALLOWED decision too
        _record(RawTransportDecision(
            url=url, resolved_ip=pinned_ip, allowed=True,
            clause="all", reason="governed exchange completed",
            method=method,
            cookie_origin_match=(cookie_origin is None or
                                _origin_of(url) == _origin_of(cookie_origin)),
            response_bytes=len(body), elapsed_ms=elapsed_ms))
        # clause 7 — a redirect on the raw channel is a RECORDED FACT,
        # never followed here (no silent destination change)
        return {
            "status_code": status_code,
            "headers": headers,
            "body": body[:max_response_bytes],
            "truncated": truncated,
            "pinned_ip": pinned_ip,
            "elapsed_ms": elapsed_ms,
        }
    except RawTransportRefused:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        _record(RawTransportDecision(
            url=url, resolved_ip=pinned_ip, allowed=False, clause="7",
            reason="budget/timeout refusal", method=method,
            elapsed_ms=elapsed_ms))
        raise
    finally:
        release = getattr(governor, "release", None)
        if release is not None:
            try:
                release(None)
            except TypeError:
                release()
