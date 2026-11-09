# src/webpent/shared/grounding.py
"""webpent.shared.grounding

V5 Sprint 10 — Enterprise AI Grounding & Zero-Hallucination utilities.

This module centralises four anti-hallucination mechanisms that are
consumed by the validator agent and the Devil's Advocate node:

  1. :func:`verify_citation` — Grounding Check: verify that a string
     the LLM cited from tool output actually exists in the raw output.
     Catches LLM hallucinations where the model fabricates evidence.

  2. :func:`generate_canary_token` — Canary Token: generate a unique
     UUID4 per payload so the validator can search the HTTP response
     for the exact token rather than a static, predictable marker.

  3. :func:`capture_evidence_bundle` — Evidence Bundle: build a
     mini-HAR dict (request + response headers/body/status) that gets
     attached to every confirmed Finding for human-audit reproducibility.

  4. :func:`baseline_differential_test` — Differential/Baseline Testing:
     send a clean control request (no payload) and compare its response
     against the payload response. If the delta is negligible, the
     "signal" is a default server behavior, not a true positive.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field, replace
from typing import Any
from uuid import uuid4

from webpent.shared.redaction import redact_value

logger = logging.getLogger(__name__)

_EVIDENCE_BODY_MAX_CHARS = 32_768
_EVIDENCE_TOOL_OUTPUT_MAX_CHARS = 16_384
_MIN_REASONING_CITATION_LENGTH = 4
_MIN_REASONING_TOKEN_OVERLAP = 1.0


def _bounded_evidence_text(value: str | None, *, limit: int) -> str | None:
    """Redact and cap persisted evidence text without changing its type."""
    if value is None:
        return None
    redacted = str(redact_value(value))
    if len(redacted) <= limit:
        return redacted
    return redacted[:limit] + f"...[truncated at {limit} chars]"


def _bounded_evidence_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """Return a JSON-safe, redacted copy of HTTP headers."""
    if not headers:
        return {}
    bounded = {str(key): str(value)[:2_048] for key, value in headers.items()}
    return dict(redact_value(bounded))


# ===========================================================================
# 1. Grounding Check — Citation Verification
# ===========================================================================
def verify_citation(
    cited_string: str,
    raw_tool_output: str,
    *,
    case_sensitive: bool = False,
) -> tuple[bool, str]:
    """Verify that a string the LLM cited actually exists in tool output.

    V5 Sprint 14 P1: Removed the ``min_citation_length`` parameter.
    Citations of arbitrary length (e.g. "500", "1=1") are now verified.
    Previously, citations shorter than 4 characters were skipped, which
    allowed the LLM to cite short fabricated strings without verification.
    """
    if not cited_string or not cited_string.strip():
        # V10 P3-7 FIX: previously returned True for empty citations,
        # which meant an LLM that produced no citation at all was
        # treated as "verified". Fail-closed instead — an empty
        # citation cannot be verified against the tool output, so the
        # caller must treat it as a grounding failure (the validator
        # then downgrades the finding rather than rubber-stamping it).
        return False, "empty citation — nothing to verify"

    cited = cited_string.strip()

    haystack = raw_tool_output if case_sensitive else raw_tool_output.lower()
    needle = cited if case_sensitive else cited.lower()

    if needle in haystack:
        return True, "citation verified in tool output"
    return False, (
        f"HALLUCINATION DETECTED: LLM cited {cited[:80]!r} but this "
        f"string does not appear in the raw tool output. The LLM may "
        f"have fabricated evidence."
    )


def extract_cited_strings(llm_reasoning: str) -> list[str]:
    """Extract candidate cited strings from an LLM reasoning field.

    V5 Sprint 14 P0: Now parses ``<quote>...</quote>`` tags as the
    primary citation mechanism. Falls back to legacy quote-mark
    parsing (double-quote, single-quote, backtick) for backward compat.

    The LLM system prompt is updated to mandate wrapping all cited
    evidence in ``<quote>`` tags. This eliminates the bypass vector
    where the LLM could avoid verification by not quoting its claims.

    Args:
        llm_reasoning: The LLM's free-text reasoning/justification.

    Returns:
        A list of cited substrings (without the surrounding tags),
        in order of appearance. Empty list if no citations are found.
    """
    if not llm_reasoning:
        return []

    # V5 Sprint 14: Primary — parse <quote> tags.
    quote_pattern = re.compile(r"<quote>(.*?)</quote>", re.DOTALL)
    citations = quote_pattern.findall(llm_reasoning)

    # Fallback — parse legacy quote marks (for backward compat with
    # LLM responses that don't use <quote> tags yet).
    legacy_pattern = re.compile(r'[`"\']([^`"\']{1,})[`"\']')
    citations.extend(legacy_pattern.findall(llm_reasoning))

    return citations


def citation_overlap_ratio(cited_string: str, raw_tool_output: str) -> float:
    """Return the fraction of cited tokens present in tool output.

    This is intentionally token-based rather than length-based: a short but
    meaningful exact quote should not be rejected merely because a tool emits
    a large amount of unrelated output.  ``verify_all_citations`` combines
    this metric with exact substring verification and a minimum quote length.
    """
    cited_tokens = re.findall(r"\w+", (cited_string or "").lower())
    if not cited_tokens:
        return 0.0
    output_tokens = set(re.findall(r"\w+", (raw_tool_output or "").lower()))
    matched = sum(token in output_tokens for token in cited_tokens)
    return matched / len(cited_tokens)


def verify_all_citations(
    llm_reasoning: str,
    raw_tool_output: str,
    *,
    min_citation_length: int = _MIN_REASONING_CITATION_LENGTH,
    min_overlap_ratio: float = _MIN_REASONING_TOKEN_OVERLAP,
) -> tuple[bool, list[str], int]:
    """Verify every cited string in the LLM reasoning field.

    V5 Sprint 14 P0: Returns a third element — the count of
    ``<quote>`` tags found. The validator uses this to detect the
    bypass where the LLM asserts YES but provides zero ``<quote>``
    tags, which triggers an automatic downgrade to
    ``"Needs Human Review"``.

    Args:
        min_citation_length: Minimum non-whitespace characters required for
            citations extracted from LLM reasoning. Direct ``verify_citation``
            calls remain backward-compatible and do not apply this policy.
        min_overlap_ratio: Minimum fraction of citation tokens that must be
            present in the raw tool output before exact substring verification.

    Returns:
        A tuple of ``(all_grounded, hallucinated_citations, quote_tag_count)``.
    """
    if min_citation_length < 1 or not 0.0 <= min_overlap_ratio <= 1.0:
        raise ValueError("invalid grounding policy thresholds")

    # Count <quote> tags specifically.
    quote_tag_count = len(re.findall(r"<quote>", llm_reasoning or ""))

    citations = extract_cited_strings(llm_reasoning)
    hallucinated: list[str] = []
    for cited in citations:
        normalized = cited.strip()
        if len(normalized) < min_citation_length:
            hallucinated.append(cited)
            continue
        if citation_overlap_ratio(normalized, raw_tool_output) < min_overlap_ratio:
            hallucinated.append(cited)
            continue
        grounded, _reason = verify_citation(normalized, raw_tool_output)
        if not grounded:
            hallucinated.append(cited)
    return len(hallucinated) == 0, hallucinated, quote_tag_count


# ===========================================================================
# 2. Canary Token — Dynamic UUID4 per payload
# ===========================================================================
def generate_canary_token() -> str:
    """Generate a unique UUID4 canary token for payload embedding.

    V5 Sprint 10: Replaces static verification markers like
    ``webpent_verified`` or ``4444``. Static markers are predictable —
    an attacker could pre-seed them, or a WAF could fingerprint the
    scanner. A fresh UUID4 per payload makes both attacks infeasible.

    Returns:
        A 36-character UUID4 string (e.g.
        ``"550e8400-e29b-41d4-a716-446655440000"``).
    """
    return str(uuid4())


def canary_in_response(canary_token: str, response_body: str) -> bool:
    """Check whether the canary token appears in the HTTP response body.

    V5 Sprint 10: The validator calls this after sending a payload
    containing the canary token. If the token is reflected in the
    response, the vulnerability is confirmed in-band — no LLM needed.

    Args:
        canary_token: The UUID4 token that was embedded in the payload.
        response_body: The HTTP response body to search.

    Returns:
        ``True`` if the canary token appears verbatim in the response.
    """
    if not canary_token or not response_body:
        return False
    return canary_token in response_body


# ===========================================================================
# 3. Evidence Bundle — mini-HAR capture
# ===========================================================================
@dataclass
class EvidenceBundle:
    """Structured evidence container for confirmed findings.

    V5 Sprint 10: Attached to every ``Tool-Confirmed`` finding so a
    human auditor can reproduce the exploit without re-running the
    tool. Serialised to JSON for persistence in the ``evidence_bundle``
    DB column.
    """

    request: dict[str, Any] = field(
        default_factory=dict,
        metadata={
            "description": (
                "Request dict: method, url, headers (dict), body (str)"
            )
        },
    )
    response: dict[str, Any] = field(
        default_factory=dict,
        metadata={
            "description": (
                "Response dict: status_code, headers (dict), body (str), "
                "elapsed_ms (float)"
            )
        },
    )
    tool_output: str | None = field(
        default=None,
        metadata={
            "description": (
                "Raw stdout from the external tool (dalfox/sqlmap/etc.), "
                "if applicable. None for in-band checks that did not "
                "invoke an external tool."
            )
        },
    )
    captured_at: str = field(
        default_factory=lambda: time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
        ),
        metadata={"description": "ISO-8601 UTC capture timestamp."},
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-safe dict for Finding.evidence_bundle."""
        return {
            "request": self.request,
            "response": self.response,
            "tool_output": self.tool_output,
            "captured_at": self.captured_at,
        }


def capture_evidence_bundle(
    *,
    request_method: str,
    request_url: str,
    request_headers: dict[str, str] | None = None,
    request_body: str | None = None,
    response_status_code: int | None = None,
    response_headers: dict[str, str] | None = None,
    response_body: str | None = None,
    response_elapsed_ms: float | None = None,
    tool_output: str | None = None,
) -> dict[str, Any]:
    """Build an evidence bundle dict from an HTTP exchange + tool output.

    V5 Sprint 10: Called by the validator after a successful exploit.
    The returned dict is suitable for direct assignment to
    ``Finding.evidence_bundle``.

    All arguments are keyword-only to prevent positional-arg confusion
    between request_* and response_* parameters.

    Args:
        request_method: HTTP method (GET, POST, etc.).
        request_url: Absolute request URL.
        request_headers: Request headers dict (optional).
        request_body: Request body string (optional).
        response_status_code: HTTP status code (optional — some tools
            don't expose it).
        response_headers: Response headers dict (optional).
        response_body: Response body string (optional).
        response_elapsed_ms: Round-trip time in milliseconds (optional).
        tool_output: Raw stdout from the external tool, if applicable.

    Returns:
        A JSON-safe dict with ``request``, ``response``, ``tool_output``,
        and ``captured_at`` keys.
    """
    bundle = EvidenceBundle(
        request={
            "method": request_method,
            "url": str(request_url)[:4_096],
            "headers": _bounded_evidence_headers(request_headers),
            "body": _bounded_evidence_text(
                request_body, limit=_EVIDENCE_BODY_MAX_CHARS
            ),
        },
        response={
            "status_code": response_status_code,
            "headers": _bounded_evidence_headers(response_headers),
            "body": _bounded_evidence_text(
                response_body, limit=_EVIDENCE_BODY_MAX_CHARS
            ),
            "elapsed_ms": response_elapsed_ms,
        },
        tool_output=_bounded_evidence_text(
            tool_output, limit=_EVIDENCE_TOOL_OUTPUT_MAX_CHARS
        ),
    )
    return bundle.to_dict()


# ===========================================================================
# 4. Differential / Baseline Testing
# ===========================================================================
@dataclass
class BaselineDifferential:
    """Result of a baseline-vs-payload differential test.

    V5 Sprint 10: Used to filter out default server behaviors that
    produce identical responses regardless of the payload. If the
    baseline and payload responses are identical (or the delta is
    negligible), the "signal" is not a true positive.
    """

    is_false_positive: bool
    reason: str
    baseline_status: int | None = None
    payload_status: int | None = None
    baseline_length: int | None = None
    payload_length: int | None = None
    body_delta: int | None = None
    status_delta: int | None = None
    baseline_request_digest: str | None = None
    payload_request_digest: str | None = None
    baseline_response_digest: str | None = None
    payload_response_digest: str | None = None
    negative_control_status: int | None = None
    negative_control_length: int | None = None
    negative_control_request_digest: str | None = None
    negative_control_response_digest: str | None = None
    target_fingerprint: str | None = None


def _exchange_digest(
    *, method: str, url: str, headers: dict[str, str] | None, body: str | None = None
) -> str:
    # Digest only: never persist cookies, authorization values, or bodies.
    safe_headers = sorted(str(k).lower() for k in (headers or {}))
    payload = json.dumps({
        "method": method.upper(),
        "url": str(url),
        "header_names": safe_headers,
        "body_present": bool(body),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _target_fingerprint(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(str(url))
    shape = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path or '/'}"
    return hashlib.sha256(shape.encode("utf-8")).hexdigest()


def _normalize_body(body: str | None) -> str:
    """Normalize a response body for comparison.

    Strips whitespace and lowercases so that trivial formatting
    differences don't produce false negatives in the differential test.
    """
    if not body:
        return ""
    return " ".join(body.split()).lower()


def compare_responses(
    baseline_status: int | None,
    baseline_body: str | None,
    baseline_headers: dict[str, str] | None,
    payload_status: int | None,
    payload_body: str | None,
    payload_headers: dict[str, str] | None,
    *,
    max_body_delta_pct: float = 5.0,
    max_body_delta_bytes: int = 150,
) -> BaselineDifferential:
    """Compare a baseline response against a payload response.

    V5 Sprint 14 P1: Added ``max_body_delta_bytes`` absolute threshold.
    Previously, a padding bypass could evade the percentage-based check
    by making the baseline response very large (e.g. 100KB), so a 5%
    delta allowed up to 5KB of injected content to pass as a false
    positive. The absolute threshold (default 150 bytes) catches this
    regardless of the baseline size.

    Args:
        baseline_status: Status code from the clean (no-payload) request.
        baseline_body: Response body from the clean request.
        baseline_headers: Response headers from the clean request.
        payload_status: Status code from the payload request.
        payload_body: Response body from the payload request.
        payload_headers: Response headers from the payload request.
        max_body_delta_pct: Maximum body length delta (as a percentage
            of the baseline length) that is still considered a false
            positive. Defaults to 5% — if the payload response is
            within 5% of the baseline length AND the status codes
            match AND the normalized bodies are identical or nearly
            identical, it's a false positive.

    Returns:
        A :class:`BaselineDifferential` with the comparison result.
    """
    b_body = baseline_body or ""
    p_body = payload_body or ""
    b_len = len(b_body)
    p_len = len(p_body)

    b_norm = _normalize_body(b_body)
    p_norm = _normalize_body(p_body)

    # V10 P3-7 FIX: if BOTH bodies are empty, the differential cannot
    # be determined — the original "identical responses → false
    # positive" branch below would classify two empty bodies as a
    # definite false positive, which is wrong (the server may simply
    # have returned nothing for both requests due to a network error
    # or 204 No Content; that says nothing about whether the payload
    # was effective). Bail out explicitly with is_false_positive=False
    # so the validator does not suppress the finding based on no data.
    if b_len == 0 and p_len == 0:
        _empty_status_delta = (
            abs((baseline_status or 0) - (payload_status or 0))
            if baseline_status is not None and payload_status is not None
            else None
        )
        return BaselineDifferential(
            is_false_positive=False,
            reason=(
                "both bodies empty — cannot determine differential"
            ),
            baseline_status=baseline_status,
            payload_status=payload_status,
            baseline_length=b_len,
            payload_length=p_len,
            body_delta=0,
            status_delta=_empty_status_delta,
        )

    status_delta = (
        abs((baseline_status or 0) - (payload_status or 0))
        if baseline_status is not None and payload_status is not None
        else None
    )

    body_delta_pct = (
        abs(p_len - b_len) / b_len * 100
        if b_len > 0
        else 100.0 if p_len > 0 else 0.0
    )

    body_delta = abs(p_len - b_len)

    # ---- Identical responses → definite false positive ----
    if (
        baseline_status == payload_status
        and b_norm == p_norm
        and b_len == p_len
    ):
        return BaselineDifferential(
            is_false_positive=True,
            reason=(
                "Baseline and payload responses are IDENTICAL (same "
                "status, same body length, same normalized content). "
                "The 'signal' is a default server behavior, not a true "
                "vulnerability."
            ),
            baseline_status=baseline_status,
            payload_status=payload_status,
            baseline_length=b_len,
            payload_length=p_len,
            body_delta=body_delta,
            status_delta=status_delta,
        )

    # ---- Negligible delta → likely false positive ----
    # V5 Sprint 14: BOTH percentage AND absolute thresholds must be
    # satisfied to classify as a false positive. This prevents the
    # padding bypass where a large baseline response makes a 5% delta
    # permit kilobytes of injected content.
    if (
        status_delta == 0
        and body_delta_pct <= max_body_delta_pct
        and body_delta <= max_body_delta_bytes
        and b_norm == p_norm
    ):
        return BaselineDifferential(
            is_false_positive=True,
            reason=(
                f"Baseline and payload responses are nearly identical "
                f"(body delta {body_delta_pct:.1f}% <= {max_body_delta_pct}%, "
                f"{body_delta} bytes <= {max_body_delta_bytes} bytes, "
                f"normalized bodies match). The minor length difference "
                f"is likely due to the payload itself being reflected, "
                f"not a genuine vulnerability signal."
            ),
            baseline_status=baseline_status,
            payload_status=payload_status,
            baseline_length=b_len,
            payload_length=p_len,
            body_delta=body_delta,
            status_delta=status_delta,
        )

    # ---- Meaningful delta → not a false positive ----
    return BaselineDifferential(
        is_false_positive=False,
        reason=(
            f"Payload response differs meaningfully from baseline "
            f"(status_delta={status_delta}, body_delta={body_delta} bytes "
            f"({body_delta_pct:.1f}%)). The signal is likely a true "
            f"vulnerability indicator."
        ),
        baseline_status=baseline_status,
        payload_status=payload_status,
        baseline_length=b_len,
        payload_length=p_len,
        body_delta=body_delta,
        status_delta=status_delta,
    )


def baseline_differential_test(
    target_url: str,
    *,
    payload_url: str | None = None,
    request_headers: dict[str, str] | None = None,
    request_cookies: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> BaselineDifferential:
    """Send a clean baseline request + a payload request, compare them.

    V5 Sprint 10: The top-level differential testing entry point. The
    caller provides the clean target URL (no payload) and optionally
    a payload URL (target URL + injected payload). This function
    fetches both via httpx and delegates to :func:`compare_responses`.

    Args:
        target_url: The clean target URL with NO payload (e.g.
            ``https://example.com/page?id=1``).
        payload_url: The target URL WITH the injected payload (e.g.
            ``https://example.com/page?id=1' OR '1'='1``). If None,
            only the baseline is fetched and the result is always
            ``is_false_positive=False`` (nothing to compare).
        request_headers: Optional headers to send with all requests.
        request_cookies: Optional cookies to send with all requests.
        timeout: httpx timeout in seconds.

    Returns:
        A :class:`BaselineDifferential` describing whether the payload
        response differs meaningfully from the baseline.
    """
    if payload_url is None:
        return BaselineDifferential(
            is_false_positive=False,
            reason="No payload URL provided — skipping differential test.",
        )

    # V6 Omniscient Audit Fix (P0 — SSRF): use the hardened httpx
    # factory that blocks redirects to internal networks (169.254.169.254,
    # 10.x, 172.16.x, 192.168.x, 127.x, ::1, fc00::/7). A malicious
    # target could otherwise 302 us to AWS metadata or internal Docker
    # services, turning WebPent into an SSRF proxy.
    from webpent.shared.http import make_safe_httpx_client

    baseline_status: int | None = None
    baseline_body: str | None = None
    baseline_headers: dict[str, str] | None = None

    try:
        with make_safe_httpx_client(
            timeout=timeout, follow_redirects=True, verify=True
        ) as client:
            resp = client.get(
                target_url, headers=request_headers, cookies=request_cookies
            )
            baseline_status = resp.status_code
            baseline_body = resp.text
            baseline_headers = dict(resp.headers)
    except Exception as exc:
        logger.warning(
            "baseline_differential_test: baseline fetch failed for %s: %s",
            target_url, exc,
        )
        return BaselineDifferential(
            is_false_positive=False,
            reason=f"Baseline fetch failed: {exc}. Cannot determine false positive.",
        )

    payload_status: int | None = None
    payload_body: str | None = None
    payload_headers: dict[str, str] | None = None

    try:
        with make_safe_httpx_client(
            timeout=timeout, follow_redirects=True, verify=True
        ) as client:
            resp = client.get(
                payload_url, headers=request_headers, cookies=request_cookies
            )
            payload_status = resp.status_code
            payload_body = resp.text
            payload_headers = dict(resp.headers)
    except Exception as exc:
        logger.warning(
            "baseline_differential_test: payload fetch failed for %s: %s",
            payload_url, exc,
        )
        return BaselineDifferential(
            is_false_positive=False,
            reason=f"Payload fetch failed: {exc}. Cannot determine false positive.",
        )

    negative_control_status: int | None = None
    negative_control_body: str | None = None
    try:
        with make_safe_httpx_client(
            timeout=timeout, follow_redirects=True, verify=True
        ) as client:
            control_headers = dict(request_headers or {})
            control_headers["Cache-Control"] = "no-cache"
            control_headers["X-WebPent-Negative-Control"] = "1"
            resp = client.get(
                target_url, headers=control_headers, cookies=request_cookies
            )
            negative_control_status = resp.status_code
            negative_control_body = resp.text
    except Exception as exc:
        logger.warning(
            "baseline_differential_test: negative control fetch failed for %s: %s",
            target_url,
            exc,
        )
        return BaselineDifferential(
            is_false_positive=False,
            reason=f"Negative control fetch failed: {exc}. Cannot determine false positive.",
        )

    diff = compare_responses(
        baseline_status=baseline_status,
        baseline_body=baseline_body,
        baseline_headers=baseline_headers,
        payload_status=payload_status,
        payload_body=payload_body,
        payload_headers=payload_headers,
    )
    return replace(
        diff,
        baseline_request_digest=_exchange_digest(
            method="GET", url=target_url, headers=request_headers
        ),
        payload_request_digest=_exchange_digest(
            method="GET", url=payload_url, headers=request_headers
        ),
        baseline_response_digest=hashlib.sha256(
            (baseline_body or "").encode("utf-8", errors="replace")
        ).hexdigest(),
        payload_response_digest=hashlib.sha256(
            (payload_body or "").encode("utf-8", errors="replace")
        ).hexdigest(),
        negative_control_status=negative_control_status,
        negative_control_length=len(negative_control_body or ""),
        negative_control_request_digest=_exchange_digest(
            method="GET",
            url=target_url,
            headers={
                **(request_headers or {}),
                "Cache-Control": "no-cache",
                "X-WebPent-Negative-Control": "1",
            },
        ),
        negative_control_response_digest=hashlib.sha256(
            (negative_control_body or "").encode("utf-8", errors="replace")
        ).hexdigest(),
        target_fingerprint=_target_fingerprint(target_url),
    )


def post_form_differential_test(
    target_url: str,
    *,
    clean_data: dict[str, str],
    payload_data: dict[str, str],
    request_headers: dict[str, str] | None = None,
    request_cookies: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> BaselineDifferential:
    """POST-form sibling of :func:`baseline_differential_test`.

    E2E WAVE R-4 (runtime-discovered 2026-09-15): the strict replay verifier
    requires a baseline+candidate observation for any dalfox promotion, but
    Stage 0 could only build one for GET query-param findings. POST-form XSS
    findings (discovered form bodies) therefore could NEVER reach
    Tool-Confirmed even when dalfox + the LLM supervisor both confirmed —
    the promotion gate was structurally unreachable for the whole POST
    surface. This function closes that gap with the SAME evidence bar as the
    GET path: real baseline (clean form), real candidate (payload form),
    real negative control (clean form + control headers), real digests —
    no observation is fabricated; every field is captured from actual
    requests through the SSRF-hardened httpx factory.

    Args:
        target_url: Form action URL (no payload encoding differences).
        clean_data: The discovered form body with its original values.
        payload_data: The form body with the target field set to the payload.
        request_headers: Optional headers sent with every request.
        request_cookies: Optional cookies sent with every request.
        timeout: httpx timeout in seconds.

    Returns:
        A :class:`BaselineDifferential` with the same digest/observation
        fields as the GET variant (request digests carry method=POST and
        the urlencoded body).
    """
    if not clean_data or not payload_data:
        return BaselineDifferential(
            is_false_positive=False,
            reason="POST differential requires both clean and payload form bodies.",
        )

    from urllib.parse import urlencode

    from webpent.shared.http import make_safe_httpx_client

    clean_body = urlencode([(str(k), str(v)) for k, v in clean_data.items()])
    payload_body = urlencode([(str(k), str(v)) for k, v in payload_data.items()])

    baseline_status: int | None = None
    baseline_body: str | None = None
    baseline_headers: dict[str, str] | None = None
    try:
        with make_safe_httpx_client(
            timeout=timeout, follow_redirects=True, verify=True
        ) as client:
            resp = client.post(
                target_url,
                content=clean_body,
                headers={
                    **(request_headers or {}),
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                cookies=request_cookies,
            )
            baseline_status = resp.status_code
            baseline_body = resp.text
            baseline_headers = dict(resp.headers)
    except Exception as exc:
        logger.warning(
            "post_form_differential_test: baseline POST failed for %s: %s",
            target_url, exc,
        )
        return BaselineDifferential(
            is_false_positive=False,
            reason=f"Baseline POST failed: {exc}. Cannot determine false positive.",
        )

    payload_status: int | None = None
    payload_resp_body: str | None = None
    payload_resp_headers: dict[str, str] | None = None
    try:
        with make_safe_httpx_client(
            timeout=timeout, follow_redirects=True, verify=True
        ) as client:
            resp = client.post(
                target_url,
                content=payload_body,
                headers={
                    **(request_headers or {}),
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                cookies=request_cookies,
            )
            payload_status = resp.status_code
            payload_resp_body = resp.text
            payload_resp_headers = dict(resp.headers)
    except Exception as exc:
        logger.warning(
            "post_form_differential_test: payload POST failed for %s: %s",
            target_url, exc,
        )
        return BaselineDifferential(
            is_false_positive=False,
            reason=f"Payload POST failed: {exc}. Cannot determine false positive.",
        )

    negative_control_status: int | None = None
    negative_control_body: str | None = None
    try:
        with make_safe_httpx_client(
            timeout=timeout, follow_redirects=True, verify=True
        ) as client:
            control_headers = {
                **(request_headers or {}),
                "Content-Type": "application/x-www-form-urlencoded",
                "Cache-Control": "no-cache",
                "X-WebPent-Negative-Control": "1",
            }
            resp = client.post(
                target_url,
                content=clean_body,
                headers=control_headers,
                cookies=request_cookies,
            )
            negative_control_status = resp.status_code
            negative_control_body = resp.text
    except Exception as exc:
        logger.warning(
            "post_form_differential_test: negative control POST failed for %s: %s",
            target_url, exc,
        )
        return BaselineDifferential(
            is_false_positive=False,
            reason=f"Negative control POST failed: {exc}. Cannot determine false positive.",
        )

    diff = compare_responses(
        baseline_status=baseline_status,
        baseline_body=baseline_body,
        baseline_headers=baseline_headers,
        payload_status=payload_status,
        payload_body=payload_resp_body,
        payload_headers=payload_resp_headers,
    )
    return replace(
        diff,
        baseline_request_digest=_exchange_digest(
            method="POST", url=target_url, headers=request_headers, body=clean_body
        ),
        payload_request_digest=_exchange_digest(
            method="POST", url=target_url, headers=request_headers, body=payload_body
        ),
        baseline_response_digest=hashlib.sha256(
            (baseline_body or "").encode("utf-8", errors="replace")
        ).hexdigest(),
        payload_response_digest=hashlib.sha256(
            (payload_resp_body or "").encode("utf-8", errors="replace")
        ).hexdigest(),
        negative_control_status=negative_control_status,
        negative_control_length=len(negative_control_body or ""),
        negative_control_request_digest=_exchange_digest(
            method="POST",
            url=target_url,
            headers={
                **(request_headers or {}),
                "Cache-Control": "no-cache",
                "X-WebPent-Negative-Control": "1",
            },
            body=clean_body,
        ),
        negative_control_response_digest=hashlib.sha256(
            (negative_control_body or "").encode("utf-8", errors="replace")
        ).hexdigest(),
        target_fingerprint=_target_fingerprint(target_url),
    )
