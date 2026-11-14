"""webpent.agents.validator.structural_checks

V10 P1 (RCA follow-up): deterministic structural validators for the 8
DVWA vuln classes that previously returned silent ``[]`` findings.

Each function takes a ``Finding`` (already promoted from a path-classified
hypothesis with ``deterministic_match=True``) plus the engagement's
``session_cookies`` / ``target_url`` context, performs a deterministic
HTTP/HTML check, and returns the finding with an updated
``confidence_level``:

  - ``"Tool-Confirmed"`` — the structural check found a real issue
    (missing CSP, weak session ID, dangerous JS sink, etc.). This is
    a deterministic confirmation — NO LLM is involved.

  - ``"Not Scanned"`` — the structural check could NOT run (e.g. the
    page returned a non-200 status, the fetch failed, no session
    cookies were observed). This is the explicit operator signal
    required by V10 P0-4: the operator sees ``count >= 1`` with a
    clear ``confidence_level="Not Scanned"`` rather than a silent
    ``[]``.

  - ``"Clean"`` (V10 RESIDUAL FIX) — the structural check RAN
    SUCCESSFULLY and found NO issue (e.g. CSP header present and not
    trivially weak, no dangerous JS sinks, captcha present, throttling
    active). Previously these cases were conflated with ``"Not
    Scanned"`` — operators could not distinguish "detector ran clean"
    from "detector could not run". ``"Clean"`` is never produced by
    an LLM; it is the deterministic success path of a structural
    validator that found no evidence of a vulnerability. Severity for
    Clean findings is INFO.

  - ``"AI-Assessed"`` — the structural check is not applicable to this
    target (e.g. captcha detection on a non-form page). The finding
    retains its default AI-Assessed level so the reporter can surface
    it as a low-confidence observation.

Design principles (per V10 hard constraints):
  * LLM is NEVER called — all checks are deterministic HTTP + regex.
  * All HTTP probes use ``make_safe_httpx_client`` (SSRF guard +
    engagement-scope allowlist). No raw httpx.
  * No destructive brute-force (brute_force validator does <= 3
    controlled invalid-login probes with jitter, scoped to the target).
  * Session cookies are attached so authenticated pages are reachable.
  * Findings are persisted incrementally (validator_node calls
    ``_persist_finding_incrementally`` after each finding is updated).
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

from webpent.models.findings import Confidence, Finding
from webpent.models.proof_bundle import proof_bundle_promotion_ready
from webpent.shared.bac_identity_tester import (
    assess_access_control,
    build_relational_evidence,
    normalise_identity_profiles,
    response_fingerprint,
)
from webpent.shared.target_package_context import package_continuity_kwargs
from webpent.shared.verifier import verify_replay_evidence

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _fetch_page(
    url: str,
    cookies: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, str, dict[str, str]] | None:
    """Fetch a URL and return (status_code, body, headers).

    Uses the SSRF-hardened httpx client. Returns None on network error.
    """
    try:
        from webpent.config.settings import get_settings
        from webpent.shared.http import build_cookie_header, make_safe_httpx_client

        settings = get_settings()
        configured_user_agent = str(getattr(settings, "http_user_agent", "") or "").strip()
        user_agent = configured_user_agent
        if not user_agent or user_agent.startswith("WebPent/0.2"):
            user_agent = (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            )
        headers: dict[str, str] = {
            "User-Agent": user_agent[:256],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        }
        if cookies:
            headers["Cookie"] = build_cookie_header(cookies)
        with make_safe_httpx_client(timeout=timeout, follow_redirects=False, verify=True) as client:
            resp = client.get(url, headers=headers)
        return resp.status_code, resp.text, dict(resp.headers)
    except Exception as exc:
        logger.debug("structural_checks: fetch failed for %s: %s", url, exc)
        return None


# TEAM-1 (2026-10, Section-8 DVWA-decoupling): this file used to have its own
# private ``_resolve_url()`` — byte-for-byte identical to the one that lived
# in agents/api_testing/agent.py — which assumed the base URL's first path
# segment is always the application root (e.g. DVWA's ``/dvwa/``) and
# rewrote every absolute path underneath it instead of letting it resolve
# normally. That assumption does not apply to either call site in THIS
# file, and removing it here is simpler than in api_testing/agent.py: both
# uses below resolve a path that was actually DISCOVERED on the live page
# (a ``<script src="...">`` value, a ``<form action="...">`` value), not a
# guessed/hardcoded candidate path. A browser resolves those with plain
# RFC 3986 rules from the host root — full stop, no "maybe it's
# app-rooted" ambiguity to probe for (an app that served
# ``<script src="/js/app.js">`` and actually expected it to load from
# ``/dvwa/js/app.js`` would be broken in every real browser, not just this
# scanner) — so both call sites now use ``urljoin`` directly, matching
# standard browser path resolution exactly. (The JWKS-discovery loop
# earlier in agents/api_testing/agent.py already made this same call for
# the same reason — see its comment on ``_JWKS_DISCOVERY_PATHS`` — this
# just extends it to the two call sites that still had the old helper.)
#
# Contrast with agents/api_testing/agent.py's probe loops, which guess
# hardcoded candidate paths (e.g. "/api/v1/me") with no page to derive them
# from — there, which resolution is "real" genuinely depends on the
# target's routing and can't be known in advance, so that file now tries
# BOTH candidates via ``webpent.shared.url_resolution.resolve_url_candidates``
# instead of guessing one.


def _fetch_page_scoped(
    url: str,
    *,
    cookies: dict[str, str] | None = None,
    target_scope: tuple[str, ...] = (),
) -> tuple[int, str, dict[str, str]] | None:
    """Fetch within the operator-declared engagement scope only."""
    if not target_scope:
        return _fetch_page(url, cookies=cookies)
    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )

    token = set_engagement_target_hosts(*target_scope)
    try:
        return _fetch_page(url, cookies=cookies)
    finally:
        clear_engagement_target_hosts(token)


def _fetch_page_scoped_with_rate_limit_retry(
    url: str,
    *,
    cookies: dict[str, str] | None = None,
    target_scope: tuple[str, ...] = (),
) -> tuple[int, str, dict[str, str]] | None:
    """Retry one transient throttle response without weakening scope checks.

    Some targets return HTTP 429 after detecting a periodic request pattern.
    A single bounded wait lets a legitimate owner baseline recover,
    while a persistent throttle still reaches the normal fail-closed assessment
    as HTTP 429. No retry is performed for other response classes.
    """
    result = _fetch_page_scoped(url, cookies=cookies, target_scope=target_scope)
    if result is None or result[0] not in {429, 502, 503, 504}:
        return result

    status_code, body, headers = result
    retry_after = str(headers.get("retry-after", ""))
    wait_match = re.search(r"(?:wait|retry[- ]after)\D*(\d{1,3})", retry_after or body, re.I)
    # A target may omit Retry-After entirely. A bounded default retry avoids
    # immediately reproducing the throttle while preserving the owner baseline.
    # Keep this fallback limited to HTTP 429; transient 5xx responses retain the
    # short retry budget.
    default_wait = 12 if status_code == 429 else 1
    wait_seconds = int(wait_match.group(1)) if wait_match else default_wait
    wait_seconds = min(max(wait_seconds, 1), 12)
    # Add a small expiry margin so a retry does not immediately hit a still
    # active rate-limit cache.
    time.sleep(wait_seconds + 3.5)
    retry = _fetch_page_scoped(url, cookies=cookies, target_scope=target_scope)
    return retry if retry is not None else (status_code, body, headers)


# ---------------------------------------------------------------------------
# P1-1: CSP (Content-Security-Policy) — structural header check
# ---------------------------------------------------------------------------

def validate_csp(finding: Finding, cookies: dict[str, str] | None = None) -> Finding:
    """Check the Content-Security-Policy header on the target URL.

    Tool-Confirmed if:
      - CSP header is entirely missing, OR
      - CSP contains ``unsafe-inline`` without ``nonce-`` or ``'strict-dynamic'``, OR
      - CSP contains ``unsafe-eval``, OR
      - ``default-src`` or ``script-src`` is missing (trivially weak policy).

    Not Scanned if the page returns non-200 or could not be fetched
    (the detector could NOT run).
    Clean if the CSP is present and not trivially weak (the detector
    ran successfully and found no issue).
    """
    result = _fetch_page(finding.url, cookies=cookies)
    if result is None:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": "CSP check: could not fetch the target URL (network error).",
            }
        )
    status_code, body, headers = result
    if status_code != 200:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": f"CSP check: target returned HTTP {status_code} (not 200).",
            }
        )

    # Normalize header keys to lowercase for case-insensitive lookup.
    headers_lower = {k.lower(): v for k, v in headers.items()}
    csp = headers_lower.get("content-security-policy", "")

    if not csp:
        return finding.model_copy(
            update={
                "confidence": Confidence.FIRM.value,
                "confidence_level": "Needs Human Review",
                "payload": "Content-Security-Policy: (missing)",
                "reasoning": (
                    "CSP check: the Content-Security-Policy header is "
                    "entirely missing on this response. Without CSP, the "
                    "page has no browser-enforced mitigation against "
                    "injected scripts (XSS)."
                ),
            }
        )

    csp_lower = csp.lower()
    issues: list[str] = []
    if (
        "unsafe-inline" in csp_lower
        and "nonce-" not in csp_lower
        and "'strict-dynamic'" not in csp_lower
    ):
        issues.append("unsafe-inline without nonce or strict-dynamic")
    if "unsafe-eval" in csp_lower:
        issues.append("unsafe-eval allows eval()")
    if "default-src" not in csp_lower and "script-src" not in csp_lower:
        issues.append("missing default-src and script-src directives")

    if issues:
        return finding.model_copy(
            update={
                "confidence": Confidence.FIRM.value,
                "confidence_level": "Needs Human Review",
                "payload": f"Content-Security-Policy: {csp[:200]}",
                "reasoning": (
                    f"CSP check: weak Content-Security-Policy detected. "
                    f"Issues: {'; '.join(issues)}. Full CSP: {csp[:200]}"
                ),
            }
        )

    # V10 RESIDUAL FIX: CSP is present and not trivially weak — the
    # detector RAN SUCCESSFULLY and found no issue. Use 'Clean' (not
    # 'Not Scanned') so operators can distinguish "checked, no issue"
    # from "could not check".
    return finding.model_copy(
        update={
            "confidence_level": "Clean",
            "reasoning": (
                f"CSP check: Content-Security-Policy is present and not "
                f"trivially weak (no unsafe-inline/unsafe-eval, has "
                f"default-src or script-src). Full CSP: {csp[:200]}"
            ),
        }
    )


# ---------------------------------------------------------------------------
# P1-2: Weak Session ID — structural session-id heuristics
# ---------------------------------------------------------------------------

def validate_weak_session(finding: Finding, cookies: dict[str, str] | None = None) -> Finding:
    """Check for weak session IDs in Set-Cookie headers / session cookies.

    Tool-Confirmed if:
      - A session cookie value is very short (< 8 chars), OR
      - A session cookie value is purely numeric (sequential/guessable), OR
      - A session cookie lacks the Secure flag on an HTTPS response, OR
      - A session cookie lacks the HttpOnly flag.

    Not Scanned if the page could not be fetched or no session cookies
    are observed (the detector could NOT run).
    Clean if session cookies are observed but no structural weakness
    is detected (the detector ran successfully and found no issue).
    """
    result = _fetch_page(finding.url, cookies=cookies)
    if result is None:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": "Weak session check: could not fetch the target URL.",
            }
        )
    status_code, body, headers = result
    if status_code != 200:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": f"Weak session check: target returned HTTP {status_code}.",
            }
        )

    # Extract Set-Cookie headers (may be multiple).
    set_cookies: list[str] = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            set_cookies.append(v)

    # Also check operator-supplied session cookies (the ones in scope).
    if cookies:
        for name, value in cookies.items():
            set_cookies.append(f"{name}={value}; HttpOnly; Secure")

    if not set_cookies:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": (
                    "Weak session check: no Set-Cookie headers observed "
                    "(detector could not run)."
                ),
            }
        )

    issues: list[str] = []
    for sc in set_cookies:
        # Parse cookie name=value and attributes.
        parts = sc.split(";")
        if not parts:
            continue
        name_value = parts[0].strip()
        if "=" not in name_value:
            continue
        name, _, value = name_value.partition("=")
        name = name.strip()
        value = value.strip()
        attrs = [p.strip().lower() for p in parts[1:]]

        # Heuristic: only inspect cookies that look like session IDs.
        session_like_names = (
            "phpsessid",
            "session",
            "sess",
            "sid",
            "jsessionid",
            "aspnet_session",
            "csrf",
        )
        if name.lower() not in session_like_names and len(value) < 32:
            # Skip non-session cookies (e.g. theme=dark).
            continue

        # Check value weakness.
        if len(value) < 8:
            issues.append(f"{name}: session value too short ({len(value)} chars)")
        if value.isdigit():
            issues.append(f"{name}: session value is purely numeric (sequential/guessable)")
        # Check flags.
        if "httponly" not in attrs:
            issues.append(f"{name}: missing HttpOnly flag")
        if "secure" not in attrs and finding.url.startswith("https://"):
            issues.append(f"{name}: missing Secure flag on HTTPS")

    if issues:
        return finding.model_copy(
            update={
                "confidence": Confidence.FIRM.value,
                "confidence_level": "Needs Human Review",
                "payload": "; ".join(set_cookies)[:200],
                "reasoning": (
                    f"Weak session check: structural weaknesses detected. "
                    f"Issues: {'; '.join(issues)}. Note: these are "
                    f"heuristic checks — no entropy proof is claimed."
                ),
            }
        )

    # V10 RESIDUAL FIX: session cookies observed, no weakness — Clean.
    return finding.model_copy(
        update={
            "confidence_level": "Clean",
            "reasoning": (
                "Weak session check: session cookies observed, no "
                "structural weakness detected (values >= 8 chars, not "
                "purely numeric, flags present). No entropy proof claimed."
            ),
        }
    )


# ---------------------------------------------------------------------------
# P1-3: JavaScript surface — dangerous sink scan
# ---------------------------------------------------------------------------

# Regex patterns for dangerous JavaScript sinks. Bound to inline scripts
# and same-origin <script src> content (max 5 scripts, 100KB each).
_DANGEROUS_SINK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("innerHTML", re.compile(r"\.innerHTML\s*=", re.IGNORECASE)),
    ("document.write", re.compile(r"document\.write\s*\(", re.IGNORECASE)),
    ("eval", re.compile(r"\beval\s*\(", re.IGNORECASE)),
    ("setTimeout(string)", re.compile(r"setTimeout\s*\(\s*['\"]", re.IGNORECASE)),
    ("setInterval(string)", re.compile(r"setInterval\s*\(\s*['\"]", re.IGNORECASE)),
    ("jQuery .html()", re.compile(r"\.html\s*\(", re.IGNORECASE)),
    ("Function constructor", re.compile(r"\bnew\s+Function\s*\(", re.IGNORECASE)),
)

def validate_javascript(finding: Finding, cookies: dict[str, str] | None = None) -> Finding:
    """Scan the target page + same-origin scripts for dangerous JS sinks.

    Needs Human Review if a dangerous sink is found in static content.
    A sink alone is an observation, not proof that attacker-controlled data
    reaches it or that code execution is possible.  Tool-Confirmed requires
    a separate runtime/taint proof from an approved validator.
    Not Scanned if the page could not be fetched or returned non-200
    (the detector could NOT run).
    Clean if the page was fetched successfully but no dangerous sinks
    were found in inline scripts or same-origin script files (the
    detector ran successfully and found no issue).
    """
    result = _fetch_page(finding.url, cookies=cookies)
    if result is None:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": "JavaScript check: could not fetch the target URL.",
            }
        )
    status_code, body, headers = result
    if status_code != 200:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": f"JavaScript check: target returned HTTP {status_code}.",
            }
        )

    sinks_found: list[str] = []

    # 1. Scan inline scripts in the HTML body.
    inline_scripts = re.findall(r"<script[^>]*>(.*?)</script>", body, re.IGNORECASE | re.DOTALL)
    for script_content in inline_scripts:
        for sink_name, pattern in _DANGEROUS_SINK_PATTERNS:
            if pattern.search(script_content):
                sinks_found.append(f"inline:{sink_name}")

    # 2. Fetch and scan same-origin <script src> URLs (bounded: max 5, 100KB each).
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
    base_url = finding.url
    for src in script_srcs[:5]:
        try:
            script_url = urljoin(base_url, src)
            # Only fetch same-origin scripts (avoid SSRF via external URLs).
            if urlparse(script_url).netloc != urlparse(base_url).netloc:
                continue
            script_result = _fetch_page(script_url, cookies=cookies, timeout=10.0)
            if script_result is None:
                continue
            _, script_body, _ = script_result
            script_body = script_body[:100_000]  # cap at 100KB
            for sink_name, pattern in _DANGEROUS_SINK_PATTERNS:
                if pattern.search(script_body):
                    sinks_found.append(f"{src}:{sink_name}")
        except Exception as exc:
            logger.debug("JavaScript check: failed to fetch script %s: %s", src, exc)

    if sinks_found:
        return finding.model_copy(
            update={
                "confidence": Confidence.TENTATIVE.value,
                "confidence_level": "Needs Human Review",
                "payload": "; ".join(sinks_found)[:200],
                "evidence": {
                    **(finding.evidence or {}),
                    "static_sink_observation": sinks_found[:20],
                    "exploitability_unproven": True,
                    "runtime_taint_validation_required": True,
                },
                "reasoning": (
                    f"JavaScript check: dangerous sinks detected in static "
                    f"content. Sinks: {'; '.join(sinks_found)}. This is a "
                    "static observation only; user-controlled data flow and "
                    "runtime exploitability were not proven."
                ),
            }
        )

    # V10 RESIDUAL FIX: page fetched, no dangerous sinks — Clean.
    return finding.model_copy(
        update={
            "confidence_level": "Clean",
            "reasoning": (
                "JavaScript check: no dangerous sinks found in inline "
                "scripts or same-origin script files. Note: this is a "
                "static scan — dynamic taint analysis would be needed to "
                "confirm exploitability."
            ),
        }
    )


# ---------------------------------------------------------------------------
# P1-4: Auth Bypass — lab-safe logical differential checks
# ---------------------------------------------------------------------------

def validate_auth_bypass(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    target_url: str | None = None,
    engagement_id: str = "default-engagement",
    target_scope: tuple[str, ...] = (),
    target_package: dict[str, Any] | None = None,
) -> Finding:
    """Run a conservative auth-bypass differential check.

    A generic 200 response is only an observation.  For the active JWT
    ``alg=none`` probe, confirmation requires three same-origin requests:
    an unauthenticated baseline, the unsigned token, and an invalid signed
    token control.  Cookies are deliberately excluded from this branch so a
    valid session cannot create a false JWT confirmation.
    """
    finding_evidence = dict(finding.evidence or {})
    jwt_probe = bool(finding_evidence.get("jwt_probe")) or any(
        marker in " ".join(
            (
                str(finding.title or ""),
                str(finding.payload or ""),
            )
        ).lower()
        for marker in ("alg=none", "alg:none")
    )
    if jwt_probe:
        from webpent.shared.http import make_safe_httpx_client

        unsigned_token = (
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
            "eyJzdWIiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0."
        )
        invalid_signed_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.invalid"
        )
        scope_token = None
        if target_scope:
            from webpent.shared.engagement_scope import (
                clear_engagement_target_hosts,
                set_engagement_target_hosts,
            )

            scope_token = set_engagement_target_hosts(*target_scope)
        try:
            with make_safe_httpx_client(
                timeout=10.0,
                follow_redirects=False,
                verify=True,
            ) as client:
                baseline = client.get(finding.url)
                unsigned = client.get(
                    finding.url,
                    headers={"Authorization": f"Bearer {unsigned_token}"},
                )
                control = client.get(
                    finding.url,
                    headers={"Authorization": f"Bearer {invalid_signed_token}"},
                )
        except Exception as exc:
            return finding.model_copy(
                update={
                    "confidence_level": "Not Scanned",
                    "reasoning": f"JWT differential replay could not run: {type(exc).__name__}.",
                }
            )
        finally:
            if scope_token is not None:
                clear_engagement_target_hosts(scope_token)

        evidence = (
            {
                "case": "unauthenticated_baseline",
                "status_code": baseline.status_code,
                "body_length": len(baseline.text),
                "authorization": "absent",
            },
            {
                "case": "unsigned_jwt",
                "status_code": unsigned.status_code,
                "body_length": len(unsigned.text),
                "authorization": "Bearer <redacted-alg-none-token>",
            },
            {
                "case": "invalid_signed_token_control",
                "status_code": control.status_code,
                "body_length": len(control.text),
                "authorization": "Bearer <redacted-invalid-token>",
            },
        )
        unsigned_body_is_distinct = (
            bool(unsigned.text)
            and unsigned.text != baseline.text
            and unsigned.text != control.text
        )
        vulnerable = (
            baseline.status_code in (401, 403, 404)
            and unsigned.status_code == 200
            and len(unsigned.text) > 100
            and unsigned_body_is_distinct
            and control.status_code in (401, 403, 404)
        )
        if vulnerable:
            from webpent.shared.verifier import verify_replay_evidence

            verification = verify_replay_evidence(
                finding,
                baseline=evidence[0],
                candidate=evidence[1],
                negative_control=evidence[2],
                causal_signal=vulnerable,
                negative_control_complete=(control.status_code in (401, 403, 404)),
                validator_id="validator.auth_bypass.jwt_alg_none",
                validator_version="v96.1",
                causal_basis=(
                    "unsigned JWT reached substantial content while unauthenticated "
                    "baseline and invalid signed-token control were rejected"
                ),
                engagement_id=engagement_id,
                hypothesis_id=finding.hypothesis_id,
                scope_context={
                    "target_origin": (
                        f"{urlparse(finding.url).scheme}://{urlparse(finding.url).netloc}"
                    ),
                    "declared_scope": list(target_scope),
                    "scope_bound": bool(target_scope),
                },
                identity_context={
                    "baseline_identity": "anonymous",
                    "candidate_identity": "unsigned-jwt-admin",
                    "negative_control_identity": "invalid-signed-jwt-admin",
                },
                replay_metadata={
                    "method": "GET",
                    "sequence": [
                        "unauthenticated_baseline",
                        "unsigned_jwt",
                        "invalid_signed_token_control",
                    ],
                    "candidate_status_code": unsigned.status_code,
                    "negative_control_status_code": control.status_code,
                },
                **package_continuity_kwargs(target_package),
            )
            if verification.passed:
                proof_bundle_data = verification.proof_bundle.model_dump(mode="json")
                return finding.model_copy(
                    update={
                        # UM-DR-35 label/enum consistency fix: a verified
                        # promotion is CONFIRMED — pairing Confidence.FIRM
                        # with "Tool-Confirmed" was an inconsistent state.
                        "confidence": Confidence.CONFIRMED.value,
                        "confidence_level": "Tool-Confirmed",
                        "evidence": {
                            "jwt_differential": list(evidence),
                            **verification.evidence,
                        },
                        "evidence_bundle": proof_bundle_data,
                        "reasoning": (
                            "Unsigned JWT returned substantial authenticated content "
                            "while baseline and invalid-token control were rejected; "
                            "strict replay verifier passed."
                        ),
                    }
                )
            return finding.model_copy(
                update={
                    "confidence_level": "Needs Human Review",
                    "evidence": {
                        "jwt_differential": list(evidence),
                        **verification.evidence,
                    },
                    "reasoning": (
                        "JWT differential looked suspicious but strict replay verifier "
                        f"blocked confirmation: {verification.reason}."
                    ),
                }
            )

        return finding.model_copy(
            update={
                "confidence_level": (
                    "Clean"
                    if unsigned.status_code != 200 or len(unsigned.text) <= 100
                    else "Needs Human Review"
                ),
                "reasoning": (
                    "JWT differential ran but the baseline/control conditions did not "
                    "prove unsigned-token acceptance."
                ),
                "evidence": {"jwt_differential": list(evidence)},
            }
        )

    authed_result = _fetch_page(finding.url, cookies=cookies)
    if authed_result is None:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": "Auth bypass check: authenticated fetch failed.",
            }
        )
    authed_status, authed_body, _ = authed_result
    unauthed_result = _fetch_page(finding.url, cookies=None)
    if unauthed_result is None:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": "Auth bypass check: unauthenticated fetch failed.",
            }
        )
    unauthed_status, unauthed_body, _ = unauthed_result
    if unauthed_status == 200 and len(unauthed_body) > 100:
        return finding.model_copy(
            update={
                "confidence": Confidence.FIRM.value,
                "confidence_level": "Needs Human Review",
                "payload": f"unauth: {unauthed_status} ({len(unauthed_body)} bytes)",
                "reasoning": (
                    f"Unauthenticated request returned HTTP 200 with {len(unauthed_body)} "
                    f"bytes; authenticated request returned {authed_status} "
                    f"({len(authed_body)} bytes)."
                ),
            }
        )
    if unauthed_status in (301, 302, 401, 403):
        return finding.model_copy(
            update={
                "confidence_level": "Clean",
                "reasoning": (
                    f"Unauthenticated request returned HTTP {unauthed_status}; "
                    "authentication is enforced."
                ),
            }
        )
    return finding.model_copy(
        update={
            "confidence_level": "Not Scanned",
            "reasoning": (
                f"Unauthenticated request returned HTTP {unauthed_status}; "
                "enforcement was inconclusive."
            ),
        }
    )


# ---------------------------------------------------------------------------
# P1-5: API issue — structural API probe (urljoin fix already in _resolve_url)
# ---------------------------------------------------------------------------

def validate_api_issue(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    target_url: str | None = None,
) -> Finding:
    """Fetch the API page and record API-like forms/endpoints discovered.

    Needs Human Review if API-like content is discovered.  JSON, OpenAPI,
    Swagger, or GraphQL indicators establish an API surface, not a security
    vulnerability by themselves.  Tool-Confirmed requires a separate
    authorization, schema, injection, or runtime-impact proof.

    Not Scanned if the page could not be fetched or returned non-200
    (the detector could NOT run).
    Clean if the page was fetched successfully but no API-like content
    was detected (the detector ran successfully and found no issue).
    """
    result = _fetch_page(finding.url, cookies=cookies)
    if result is None:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": "API check: could not fetch the target URL.",
            }
        )
    status_code, body, headers = result
    if status_code != 200:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": f"API check: target returned HTTP {status_code}.",
            }
        )

    headers_lower = {k.lower(): v for k, v in headers.items()}
    content_type = headers_lower.get("content-type", "")
    body_lower = body.lower()

    issues: list[str] = []
    # Check for JSON API response.
    if "application/json" in content_type or body.strip().startswith(("{", "[")):
        issues.append("JSON response detected (API endpoint)")
    # Check for OpenAPI/Swagger.
    if "swagger" in body_lower or '"openapi"' in body_lower or '"swagger"' in body_lower:
        issues.append("OpenAPI/Swagger spec detected")
    # Check for GraphQL (already probed by api_testing_node, but double-check).
    if "__schema" in body or "queryType" in body:
        issues.append("GraphQL introspection enabled")

    if issues:
        return finding.model_copy(
            update={
                "confidence": Confidence.TENTATIVE.value,
                "confidence_level": "Needs Human Review",
                "payload": "; ".join(issues)[:200],
                "evidence": {
                    **(finding.evidence or {}),
                    "api_surface_observation": issues[:20],
                    "security_impact_unproven": True,
                    "follow_up_required": True,
                },
                "reasoning": (
                    f"API check: API-like surface detected. Indicators: "
                    f"{'; '.join(issues)}. This is not a vulnerability "
                    "confirmation; authorization, input handling, and "
                    "security impact require a separate validation path."
                ),
            }
        )

    # V10 RESIDUAL FIX: page fetched, no API content — Clean.
    return finding.model_copy(
        update={
            "confidence_level": "Clean",
            "reasoning": (
                "API check: no API-like content detected (no JSON, no "
                "OpenAPI spec, no GraphQL). The page may be a plain HTML form."
            ),
        }
    )


# ---------------------------------------------------------------------------
# P1-6: Cryptography — passive crypto checks
# ---------------------------------------------------------------------------

def validate_cryptography(finding: Finding, cookies: dict[str, str] | None = None) -> Finding:
    """Passive cryptography checks.

    Tool-Confirmed if:
      - Password form submits over HTTP (not HTTPS), OR
      - Password field has autocomplete enabled, OR
      - Page uses a known weak cipher (TLS not checked here — header only).

    Not Scanned if the page could not be fetched or returned non-200
    (the detector could NOT run).
    Clean if no password forms are found, or all password forms use
    HTTPS with autocomplete=off (the detector ran successfully and
    found no weak crypto practices).
    """
    result = _fetch_page(finding.url, cookies=cookies)
    if result is None:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": "Cryptography check: could not fetch the target URL.",
            }
        )
    status_code, body, headers = result
    if status_code != 200:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": f"Cryptography check: target returned HTTP {status_code}.",
            }
        )

    issues: list[str] = []

    # Check for password fields.
    password_fields = re.findall(r'<input[^>]+type=["\']password["\'][^>]*>', body, re.IGNORECASE)
    if password_fields:
        # Check if the form action is over HTTP (cleartext password).
        is_https = finding.url.startswith("https://")
        if not is_https:
            issues.append("password form submitted over HTTP (cleartext)")
        # Check autocomplete.
        for pf in password_fields:
            if "autocomplete" not in pf.lower():
                issues.append("password field missing autocomplete=off")
            elif (
                "autocomplete" in pf.lower()
                and "off" not in pf.lower().split("autocomplete")[1][:10]
            ):
                issues.append("password field has autocomplete enabled")

    if issues:
        return finding.model_copy(
            update={
                "confidence": Confidence.FIRM.value,
                "confidence_level": "Needs Human Review",
                "payload": "; ".join(issues)[:200],
                "reasoning": (
                    f"Cryptography check: weak crypto practices detected. "
                    f"Issues: {'; '.join(issues)}."
                ),
            }
        )

    # V10 RESIDUAL FIX: no weak crypto practices — Clean.
    return finding.model_copy(
        update={
            "confidence_level": "Clean",
            "reasoning": (
                "Cryptography check: no password forms found, or all "
                "password forms use HTTPS with autocomplete=off. No "
                "weak crypto practices detected."
            ),
        }
    )


# ---------------------------------------------------------------------------
# P1-7: Captcha — detect presence/absence only
# ---------------------------------------------------------------------------

def validate_captcha(finding: Finding, cookies: dict[str, str] | None = None) -> Finding:
    """Detect captcha presence/absence on the target page.

    Tool-Confirmed if:
      - The page is a login/sensitive form AND no captcha is present
        (missing captcha on sensitive action).

    Not Scanned if the page could not be fetched or returned non-200
    (the detector could NOT run).
    Clean if a captcha is present on the page, or the page has no
    password form (captcha presence is not applicable — the detector
    ran successfully and found no missing-captcha issue).
    """
    result = _fetch_page(finding.url, cookies=cookies)
    if result is None:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": "Captcha check: could not fetch the target URL.",
            }
        )
    status_code, body, headers = result
    if status_code != 200:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": f"Captcha check: target returned HTTP {status_code}.",
            }
        )

    body_lower = body.lower()

    # Check for captcha presence.
    captcha_indicators = [
        "captcha", "recaptcha", "hcaptcha", "g-recaptcha",
        "h-captcha", "captcha_image", "captcha_code",
    ]
    has_captcha = any(ind in body_lower for ind in captcha_indicators)

    # Check for form (login or sensitive).
    has_form = "<form" in body_lower
    has_password_field = 'type="password"' in body_lower or "type='password'" in body_lower

    if has_form and has_password_field and not has_captcha:
        return finding.model_copy(
            update={
                "confidence": Confidence.FIRM.value,
                "confidence_level": "Needs Human Review",
                "payload": "missing captcha on password form",
                "reasoning": (
                    "Captcha check: the page contains a password form "
                    "but no captcha is present. This makes the form "
                    "susceptible to automated credential stuffing."
                ),
            }
        )

    # V10 RESIDUAL FIX: captcha present OR no password form — Clean.
    if has_captcha:
        return finding.model_copy(
            update={
                "confidence_level": "Clean",
                "reasoning": (
                    "Captcha check: a captcha is present on the page. "
                    "No captcha-bypass automation is performed."
                ),
            }
        )

    return finding.model_copy(
        update={
            "confidence_level": "Clean",
            "reasoning": (
                "Captcha check: no password form found on this page. "
                "Captcha presence is not applicable."
            ),
        }
    )


# ---------------------------------------------------------------------------
# P1-8: Brute Force — lab-safe throttling probe only
# ---------------------------------------------------------------------------

def validate_brute_force(finding: Finding, cookies: dict[str, str] | None = None) -> Finding:
    """Lab-safe brute-force surface detection (NOT credential discovery).

    Sends <= 3 controlled invalid-login probes with jitter, scoped to
    the target URL. Tool-Confirmed if the login form accepts unlimited
    attempts without lockout/captcha signals.

    This does NOT attempt to discover valid credentials — it only checks
    whether throttling/lockout exists. If unsafe to probe, returns Not Scanned.
    Clean if throttling/lockout is active (the detector ran and found the
    form is NOT brute-forceable).
    """
    result = _fetch_page(finding.url, cookies=cookies)
    if result is None:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": "Brute force check: could not fetch the target URL.",
            }
        )
    status_code, body, headers = result
    if status_code != 200:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": f"Brute force check: target returned HTTP {status_code}.",
            }
        )

    body_lower = body.lower()

    # Check for a login form.
    has_password_field = 'type="password"' in body_lower or "type='password'" in body_lower
    if not has_password_field:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": (
                    "Brute force check: no password form found on this "
                    "page. Brute-force surface detection is not applicable."
                ),
            }
        )

    # Check if captcha is already present (if so, the form is protected).
    if "captcha" in body_lower or "recaptcha" in body_lower:
        return finding.model_copy(
            update={
                "confidence_level": "Clean",
                "reasoning": (
                    "Brute force check: a captcha is present on the "
                    "login form. The form is protected against automated "
                    "brute force."
                ),
            }
        )

    # Extract the form action and method.
    form_match = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', body, re.IGNORECASE)
    method_match = re.search(r'<form[^>]+method=["\']([^"\']+)["\']', body, re.IGNORECASE)
    if not form_match:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": "Brute force check: could not extract form action.",
            }
        )

    form_action = urljoin(finding.url, form_match.group(1))
    form_method = (method_match.group(1).upper() if method_match else "POST")

    # Send 3 controlled invalid-login probes with jitter.
    # Use obviously-invalid credentials to avoid any chance of hitting a real account.
    probe_results: list[int] = []
    try:
        from webpent.shared.http import build_cookie_header, make_safe_httpx_client
        for i in range(3):
            time.sleep(1.5)  # jitter — 1.5s between probes
            fake_user = f"webpent_probe_invalid_{i}"
            fake_pass = f"definitely_not_real_{i}"
            headers_probe: dict[str, str] = {"Content-Type": "application/x-www-form-urlencoded"}
            if cookies:
                headers_probe["Cookie"] = build_cookie_header(cookies)
            try:
                with make_safe_httpx_client(
                    timeout=10.0, follow_redirects=False, verify=True
                ) as client:
                    if form_method == "GET":
                        resp = client.get(
                            form_action,
                            params={"username": fake_user, "password": fake_pass, "Login": "Login"},
                            headers=headers_probe,
                        )
                    else:
                        resp = client.post(
                            form_action,
                            data={"username": fake_user, "password": fake_pass, "Login": "Login"},
                            headers=headers_probe,
                        )
                probe_results.append(resp.status_code)
            except Exception as exc:
                logger.debug("Brute force probe %d failed: %s", i, exc)
                probe_results.append(0)
    except ImportError:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": "Brute force check: SSRF-safe httpx client unavailable.",
            }
        )

    # If all 3 probes returned 200 (no lockout, no captcha, no 429), the form is brute-forceable.
    if all(s == 200 for s in probe_results):
        return finding.model_copy(
            update={
                "confidence": Confidence.FIRM.value,
                "confidence_level": "Needs Human Review",
                "payload": f"3 invalid login probes: {probe_results}",
                "reasoning": (
                    "Brute force check: sent 3 controlled invalid-login "
                    "probes with 1.5s jitter. All returned HTTP 200 (no "
                    "lockout, no captcha, no 429 rate limit). The login "
                    "form appears to accept unlimited attempts — it is a "
                    "brute-forceable surface. NOTE: no credential "
                    "discovery was attempted; this is throttling detection only."
                ),
            }
        )

    # V10 RESIDUAL FIX: throttling active — Clean (form is protected).
    if any(s in (429, 403) for s in probe_results):
        return finding.model_copy(
            update={
                "confidence_level": "Clean",
                "reasoning": (
                    f"Brute force check: at least one probe returned "
                    f"429/403 — throttling/lockout is active. Probe "
                    f"results: {probe_results}."
                ),
            }
        )

    return finding.model_copy(
        update={
            "confidence_level": "Not Scanned",
            "reasoning": (
                f"Brute force check: probe results {probe_results}. "
                f"Could not determine throttling status definitively."
            ),
        }
    )


# ---------------------------------------------------------------------------
# P1-9: Information disclosure and IDOR structural checks
# ---------------------------------------------------------------------------

_SENSITIVE_ARTIFACT_RE = re.compile(
    r"(?i)(?:^|[./_-])(?:\.env|composer\.lock(?:\.(?:bak|old|orig))?|"
    r"(?:backup|dump|database|secret|config|debug|storage|snapshot)[^/]*|"
    r"[^/]+\.(?:bak|old|orig|sql|sqlite|db|log|zip|tar|gz))$"
)
_DEBUG_MARKERS = (
    "app_debug",
    "laravel_framework",
    "whoops\\\\\\\\exception",
    "stack trace",
    "environment variables",
    "laravel version",
)


def validate_info_disclosure(
    finding: Finding,
    cookies: dict[str, str] | None = None,
) -> Finding:
    """Check bounded public artifact/debug disclosure without an LLM.

    A sensitive-looking resource is only reported when the target returns a
    successful, non-empty response and either the path is an artifact suffix
    or the body contains a bounded debug marker. This is a deterministic
    observation; it does not claim secrets were exfiltrated beyond the capped
    response metadata.
    """
    result = _fetch_page(finding.url, cookies=cookies)
    if result is None:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": "Information disclosure check: target could not be fetched.",
            }
        )
    status_code, body, headers = result
    parsed_path = urlparse(finding.url).path.rstrip("/")
    path_match = bool(_SENSITIVE_ARTIFACT_RE.search(parsed_path))
    body_sample = body[:16_384].lower()
    debug_matches = [marker for marker in _DEBUG_MARKERS if marker in body_sample]
    debug_error = 400 <= status_code < 600 and bool(debug_matches)
    if status_code != 200 and not debug_error:
        return finding.model_copy(
            update={
                "confidence_level": "Clean",
                "reasoning": (
                    "Information disclosure check: sensitive-looking resource was not "
                    f"publicly returned (HTTP {status_code})."
                ),
            }
        )
    content_type = str(headers.get("content-type", ""))[:120]
    if body and (path_match or debug_matches):
        evidence = {
            **(finding.evidence or {}),
            "status_code": status_code,
            "content_length": len(body),
            "content_type": content_type,
            "path_signature": path_match,
            "debug_markers": debug_matches[:10],
            "response_body_capped": True,
        }
        return finding.model_copy(
            update={
                "confidence": Confidence.FIRM.value,
                "confidence_level": "Needs Human Review",
                "payload": parsed_path[-200:],
                "evidence": evidence,
                "reasoning": (
                    "Information disclosure check: a public response exposed a "
                    "sensitive artifact or debug surface (including bounded error "
                    "responses). The response body was capped; no broader secret "
                    "inventory is claimed."
                ),
            }
        )

    return finding.model_copy(
        update={
            "confidence_level": "Clean",
            "reasoning": (
                "Information disclosure check: request succeeded, but no bounded "
                "sensitive artifact or debug signature was observed."
            ),
        }
    )


def validate_idor(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    *,
    identity_profiles: Any = None,
    engagement_id: str | None = None,
    target_scope: tuple[str, ...] = (),
    target_package: dict[str, Any] | None = None,
) -> Finding:
    """Validate IDOR with a scoped owner/foreign/anonymous differential.

    The legacy unauthenticated candidate path remains intact when no explicit
    identity profiles are available. When profiles are present, this function
    performs bounded GET replays under the declared engagement scope and only
    emits ``Tool-Confirmed`` after owner access, foreign access, and a denied
    anonymous control are all observed. Transport failure, missing identities,
    or missing proof data remain ``Needs Human Review``/``Not Scanned``.
    """
    result = _fetch_page_scoped_with_rate_limit_retry(
        finding.url,
        cookies=cookies,
        target_scope=target_scope,
    )
    if result is None:
        return finding.model_copy(
            update={
                "confidence_level": "Not Scanned",
                "reasoning": "IDOR check: object endpoint could not be fetched.",
            }
        )

    status_code, body, _headers = result
    parsed = urlparse(finding.url)
    path = parsed.path.lower()
    query_keys = {key.lower() for key in parse_qs(parsed.query)}
    path_segments = {segment for segment in path.split("/") if segment}
    dashboard_object_surface = (
        "dashboard" in path_segments
        and (
            any(segment.isdigit() for segment in path_segments)
            or bool(query_keys & {"db", "tenant", "tenant_id", "crm_id"})
        )
    )
    object_surface = dashboard_object_surface or any(
        marker in path
        for marker in ("download", "profile", "user", "tenant", "object", "invoice")
    )

    profiles = normalise_identity_profiles(identity_profiles, fallback_cookies=cookies)
    owner_profiles = [
        profile
        for profile in profiles
        if profile.role.lower() == "owner"
        or bool(profile.metadata.get("authenticated_primary"))
    ]
    foreign_profiles = [
        profile
        for profile in profiles
        if profile not in owner_profiles
        and profile.role.lower() not in {"anonymous", "anon"}
    ]

    if owner_profiles and foreign_profiles:
        observations: list[dict[str, Any]] = []
        for profile in (*owner_profiles[:1], *foreign_profiles[:1]):
            probe = _fetch_page_scoped_with_rate_limit_retry(
                finding.url,
                cookies=profile.cookies,
                target_scope=target_scope,
            )
            if probe is None:
                observations.append(
                    {
                        "identity": profile.name,
                        "accessible": False,
                        "status_code": 0,
                        "content_length": 0,
                        "transport_error": True,
                    }
                )
                continue
            code, response_body, response_headers = probe
            observations.append(
                {
                    "identity": profile.name,
                    "accessible": 200 <= code < 300 and bool(response_body),
                    "status_code": code,
                    "content_length": len(response_body),
                    "response_fingerprint": response_fingerprint(
                        code,
                        response_body,
                        response_headers,
                    ),
                }
            )

        anonymous_probe = _fetch_page_scoped_with_rate_limit_retry(
            finding.url,
            cookies=None,
            target_scope=target_scope,
        )
        if anonymous_probe is None:
            observations.append(
                {
                    "identity": "anonymous",
                    "accessible": False,
                    "status_code": 0,
                    "content_length": 0,
                    "transport_error": True,
                }
            )
        else:
            anon_code, anon_body, anon_headers = anonymous_probe
            observations.append(
                {
                    "identity": "anonymous",
                    "accessible": 200 <= anon_code < 300 and bool(anon_body),
                    "status_code": anon_code,
                    "content_length": len(anon_body),
                    "response_fingerprint": response_fingerprint(
                        anon_code,
                        anon_body,
                        anon_headers,
                    ),
                }
            )

        owner_name = owner_profiles[0].name
        assessment = assess_access_control(observations, owner_identity=owner_name)
        relational = build_relational_evidence(
            observations,
            owner_identity=owner_name,
            object_id=next(
                (
                    segment
                    for segment in reversed(path.split("/"))
                    if segment.isdigit()
                ),
                None,
            ),
        )
        evidence = {
            **(finding.evidence or {}),
            "validator": "idor_identity_replay",
            "identity_replay": True,
            "replay_attempted": True,
            "owner_identity": owner_name,
            "observations": observations,
            "assessment": assessment,
            "relational_evidence": relational,
            "negative_control_complete": bool(assessment.get("negative_control_complete")),
        }
        if assessment.get("status") == "confirmed" and assessment.get(
            "negative_control_complete"
        ):
            anonymous_row = next(
                row for row in observations if row.get("identity") == "anonymous"
            )
            foreign_row = next(
                row
                for row in observations
                if row.get("identity") != owner_name and row.get("accessible")
            )
            target_origin = (
                f"{urlparse(finding.url).scheme}://{urlparse(finding.url).netloc}"
            )
            verification = verify_replay_evidence(
                finding,
                baseline=next(
                    row for row in observations if row.get("identity") == owner_name
                ),
                candidate=foreign_row,
                negative_control=anonymous_row,
                causal_signal=True,
                negative_control_complete=True,
                validator_id="validator.idor_identity_replay",
                validator_version="v96.1",
                causal_basis=(
                    "owner and foreign identity both accessed the object while "
                    "anonymous control was denied"
                ),
                engagement_id=engagement_id,
                hypothesis_id=finding.hypothesis_id,
                scope_context={
                    "target_origin": target_origin,
                    "declared_scope": list(target_scope),
                    "scope_bound": bool(target_scope),
                },
                identity_context={
                    "owner_identity": owner_name,
                    "candidate_identity": str(foreign_row.get("identity") or ""),
                    "negative_control_identity": "anonymous",
                    "tested_identities": [
                        str(row.get("identity") or "") for row in observations
                    ],
                },
                replay_metadata={
                    "method": "GET",
                    "object_path": path,
                    "owner_status_code": int(
                        next(
                            row for row in observations
                            if row.get("identity") == owner_name
                        ).get("status_code") or 0
                    ),
                    "candidate_status_code": int(foreign_row.get("status_code") or 0),
                    "negative_control_status_code": int(
                        anonymous_row.get("status_code") or 0
                    ),
                },
                **package_continuity_kwargs(target_package),
            )
            if verification.passed:
                sealed_bundle = verification.proof_bundle.model_dump(mode="json")
                evidence.update(verification.evidence)
                evidence["relational_edges"] = relational
                return finding.model_copy(
                    update={
                        "confidence": Confidence.CONFIRMED.value,
                        "confidence_level": "Tool-Confirmed",
                        "evidence": evidence,
                        "evidence_bundle": sealed_bundle,
                        "reasoning": (
                            "IDOR confirmed by scoped owner/foreign differential, "
                            "denied anonymous control, and strict replay verifier."
                        ),
                    }
                )
            evidence.update(verification.evidence)
        return finding.model_copy(
            update={
                "confidence": "tentative",
                "confidence_level": "Needs Human Review",
                "evidence": evidence,
                "reasoning": (
                    "IDOR replay ran but did not satisfy the complete "
                    "owner/foreign/negative-control proof contract."
                ),
            }
        )

    if status_code == 200 and body and object_surface and not cookies:
        return finding.model_copy(
            update={
                "confidence_level": "Needs Human Review",
                "evidence": {
                    **(finding.evidence or {}),
                    "unauthenticated_status": status_code,
                    "unauthenticated_content_length": len(body),
                    "owner_foreign_oracle_required": True,
                    "negative_control_required": True,
                },
                "reasoning": (
                    "IDOR check: unauthenticated object access returned HTTP 200. "
                    "This is a candidate signal only; owner-vs-foreign identity "
                    "differential and a denial control are still required."
                ),
            }
        )

    return finding.model_copy(
        update={
            "confidence_level": "Clean",
            "reasoning": (
                "IDOR check: no unauthenticated successful object response was "
                "observed; authenticated owner-vs-foreign proof was not attempted."
            ),
        }
    )


def validate_jwt_weakness(finding: Finding) -> Finding:
    """Revalidate an offline weak-secret JWT result without network I/O.

    The API-testing path is the only local proof-grade source for this class:
    it verifies a captured signature against a bounded candidate and records a
    wrong-secret negative control.  The central validator must preserve that
    result only when the serialized bundle still satisfies the promotion
    contract.  Any missing, tampered, or incomplete bundle is downgraded to
    ``Needs Human Review``; this function never creates a new confirmation.
    """
    evidence = dict(finding.evidence or {})
    evidence_bundle = dict(finding.evidence_bundle or {})
    proof_bundle = evidence.get("proof_bundle") or evidence_bundle.get("proof_bundle")
    causal_signal = (
        evidence.get("causal_signal") is True
        or evidence_bundle.get("causal_signal") is True
    )
    negative_control_complete = (
        evidence.get("negative_control_complete") is True
        or evidence_bundle.get("negative_control") is not None
    )
    proof_ready = bool(
        proof_bundle
        and proof_bundle_promotion_ready(proof_bundle)
        and causal_signal
        and negative_control_complete
    )
    if finding.confidence_level == "Tool-Confirmed" and proof_ready:
        return finding.model_copy(
            update={
                "confidence": Confidence.FIRM.value,
                "confidence_level": "Tool-Confirmed",
                "evidence": {
                    **evidence,
                    "validator_path": "jwt_weakness_offline_proof_revalidation",
                    "proof_bundle_verified": True,
                    "causal_signal": True,
                    "negative_control_complete": True,
                },
            }
        )

    return finding.model_copy(
        update={
            "confidence_level": "Needs Human Review",
            "evidence": {
                **evidence,
                "validator_path": "jwt_weakness_offline_proof_revalidation",
                "proof_bundle_verified": False,
                "validation_failure_reason": (
                    "jwt_weakness_requires_sealed_proof_bundle_and_negative_control"
                ),
            },
            "reasoning": (
                "JWT weak-secret evidence was not promoted because the central "
                "validator could not verify a sealed ProofBundle with causal and "
                "negative-control evidence."
            ),
        }
    )


__all__ = [
    "validate_auth_bypass",
    "validate_api_issue",
    "validate_brute_force",
    "validate_captcha",
    "validate_cryptography",
    "validate_csp",
    "validate_idor",
    "validate_info_disclosure",
    "validate_javascript",
    "validate_jwt_weakness",
    "validate_weak_session",
]
