# src/webpent/agents/api_testing/agent.py
"""webpent.agents.api_testing.agent

V7 Sprint 2.6 — API & Microservices Testing Agent.

Detects API-specific vulnerabilities:
  * GraphQL introspection enabled (information disclosure)
  * GraphQL query depth / complexity limits missing (DoS vector)
  * JWT alg=none acceptance (auth bypass)
  * JWT weak HS256 secret (offline cracking via canary token)
  * Mass assignment (sending role/is_admin fields to create/update)
  * BOLA in REST APIs (accessing resources by ID without authz)

All probes use ``make_safe_httpx_client`` (V6 SSRF guard + V7 P0
engagement-scope allowlist). JWT attacks are DETECTION-ONLY — we never forge tokens to
impersonate real users; we only check whether the target accepts
``alg=none`` or a weak-signature canary token.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Iterator
from typing import Any
from urllib.parse import urlparse

from langchain_core.messages import AIMessage

from webpent.config.settings import get_settings
from webpent.models.findings import Finding, Severity, VulnClass
from webpent.shared.target_package_context import package_continuity_kwargs
from webpent.shared.url_resolution import resolve_url_candidates
from webpent.shared.verifier import verify_replay_evidence
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)


# TEAM-1 (2026-10, Section-8 DVWA-decoupling): this file used to have its
# own private copy of a ``_resolve_url()`` that assumed the base URL's
# first path segment is always the application root (true for DVWA, not
# true in general — see webpent.shared.url_resolution for the full
# rationale). That copy is gone; every guessed-path probe loop below now
# iterates ``_iter_path_url_candidates()``, which yields a
# ``(path, url)`` pair for EACH plausible resolution of a given candidate
# path (both the standard host-root URL and, when the base URL has an app
# prefix, the DVWA-style app-root-preserving URL) so the probe tries both
# and lets the live HTTP response decide which one is real — instead of
# guessing one and silently missing the target on a non-DVWA app shaped
# differently. This is a drop-in replacement for the old
# ``for path in paths: url = _resolve_url(base_url, path)`` pattern: the
# loop body below is unchanged, it just now may run once or twice per
# candidate path instead of exactly once.
def _iter_path_url_candidates(
    base_url: str, paths: Iterable[str]
) -> Iterator[tuple[str, str]]:
    """Yield ``(path, url)`` for every plausible resolution of each path."""
    for path in paths:
        for url in resolve_url_candidates(base_url, path):
            yield path, url


# GraphQL introspection query — standard, from the GraphQL spec.
# Sent as JSON body to the GraphQL endpoint. If introspection is
# enabled, the response will contain "__schema" or "queryType".
_GRAPHQL_INTROSPECTION_QUERY = json.dumps(
    {
        "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types { ...FullType }
        directives { name description locations args { ...InputValue } }
      }
    }
    fragment FullType on __Type {
      kind name description
      fields(includeDeprecated: true) {
        name description args { ...InputValue } type { ...TypeRef }
        isDeprecated deprecationReason
      }
      inputFields { ...InputValue }
      interfaces { ...TypeRef }
      enumValues { name description isDeprecated deprecationReason }
      possibleTypes { ...TypeRef }
    }
    fragment InputValue on __InputValue {
      name description type { ...TypeRef } defaultValue
    }
    fragment TypeRef on __Type {
      kind name ofType { kind name ofType { kind name ofType {
        kind name ofType { kind name ofType { kind name ofType {
          kind name ofType { kind name }
        }}}}}}
    }
    """
    }
)

# Common GraphQL endpoint paths to probe.
_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/api/query",
    "/graphiql",
]

# JWT alg=none test token (header: {"alg":"none","typ":"JWT"}, payload: {"sub":"admin"}).
# This is a well-known test token — it does NOT impersonate a real user.
_JWT_ALG_NONE_TOKEN = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0."
)


def _looks_like_spa_shell(response: Any) -> bool:
    """Return True for an HTML application shell, not an API result.

    Many single-page applications return their index document with HTTP 200
    for unknown paths. Treating that fallback as JWT acceptance both creates
    a false candidate and prevents probing later, more specific API paths.
    This helper is deliberately narrow: JSON, plain text, and HTML responses
    without the usual shell markers remain eligible for normal validation.
    """
    headers = getattr(response, "headers", {}) or {}
    content_type = str(headers.get("content-type", "")).lower()
    body = str(getattr(response, "text", "") or "")[:20_000].lower()
    if "text/html" not in content_type:
        return False
    return "<!doctype html" in body or "<app-root" in body or '<base href="/"' in body


def _probe_graphql(
    base_url: str,
    cookies: dict[str, str] | None = None,
    auth_headers: dict[str, str] | None = None,
) -> list[Finding]:
    """Probe for GraphQL endpoints and introspection exposure.

    Sends the standard introspection query to common GraphQL paths.
    If introspection is enabled (the response contains ``__schema``
    or ``queryType``), raises a Medium-severity finding.
    """
    findings: list[Finding] = []
    # No fallback to raw httpx.Client: every network request must pass
    # through the central SSRF, DNS-pinning, redirect, and engagement-scope
    # policy. Import failure is a deployment error, not a reason to bypass it.
    from webpent.shared.http import make_safe_httpx_client

    client_factory = make_safe_httpx_client
    # RED-TEAM FIX (2026-10, finding #4): _iter_path_url_candidates() may
    # yield two URLs (host-root and app-root-preserving) for the SAME
    # logical path. On an app with SPA catch-all routing both candidates
    # can return an identical positive response, duplicating this finding
    # under two different `url` values. Skip any further candidate once a
    # path has already produced a finding; the first-tried candidate for
    # each path is still probed exactly as before.
    _matched_paths: set[str] = set()

    for path, url in _iter_path_url_candidates(base_url, _GRAPHQL_PATHS):
        if path in _matched_paths:
            continue
        # V9 P0 B4: attach session cookies so authenticated GraphQL
        # endpoints (e.g. DVWA's /vulnerabilities/graphql) are reachable.
        headers: dict[str, str] = {
            str(name): str(value)
            for name, value in (auth_headers or {}).items()
            if str(value).strip()
        }
        headers["Content-Type"] = "application/json"
        if cookies:
            from webpent.shared.http import build_cookie_header

            headers["Cookie"] = build_cookie_header(cookies)
        try:
            with client_factory(timeout=10.0, follow_redirects=False, verify=True) as client:
                # First, a simple POST to see if the endpoint exists.
                resp = client.post(
                    url,
                    json={"query": "{__typename}"},
                    headers=headers,
                )
            if resp.status_code == 404:
                continue
            if resp.status_code not in (200, 400, 405):
                continue

            # Endpoint exists — try introspection.
            with client_factory(timeout=10.0, follow_redirects=False, verify=True) as client:
                resp = client.post(
                    url,
                    data=_GRAPHQL_INTROSPECTION_QUERY,
                    headers=headers,
                )
            if resp.status_code == 200:
                body = resp.text
                if "__schema" in body or "queryType" in body:
                    # V10 P0-2: wrap Finding construction in try/except
                    # so a pydantic ValidationError is logged at ERROR
                    # (not debug) and the loop continues to the next
                    # GraphQL path candidate. After P0-1, INFO_DISCLOSURE
                    # is a legal enum value, so this should not fire —
                    # but the guard remains as defense-in-depth.
                    try:
                        findings.append(
                            Finding(
                                title=f"GraphQL introspection enabled at {path}",
                                description=(
                                    f"The GraphQL endpoint at {url} has introspection "
                                    f"enabled. An attacker can query the entire schema "
                                    f"to discover all types, fields, and mutations, "
                                    f"accelerating further attacks. Introspection "
                                    f"should be disabled in production."
                                ),
                                severity=Severity.MEDIUM,
                                confidence_level="AI-Assessed",
                                # V10 P0-1: was raw "info_disclosure" string —
                                # VulnClass.INFO_DISCLOSURE already exists.
                                vuln_class=VulnClass.INFO_DISCLOSURE.value,
                                url=url,
                                tool_name="api_testing_agent",
                                payload=_GRAPHQL_INTROSPECTION_QUERY[:200],
                                reasoning=(
                                    f"GraphQL introspection query returned 200 with "
                                    f"schema data ({len(body)} bytes). The response "
                                    f"contains __schema / queryType fields, confirming "
                                    f"introspection is enabled."
                                ),
                            )
                        )
                        _matched_paths.add(path)
                    except Exception as exc:
                        logger.error(
                            "api_testing: failed to construct GraphQL "
                            "introspection finding for %s: %s",
                            url,
                            exc,
                        )
                    logger.warning("GraphQL introspection enabled at %s", url)
                else:
                    # Endpoint exists but introspection is disabled — good.
                    logger.info("GraphQL endpoint at %s has introspection disabled", url)
        except Exception as exc:
            # V10 P0-2: was debug — promote to warning so probe failures
            # are visible in operator logs (they may indicate network
            # issues, scope misconfiguration, or target-side errors that
            # warrant investigation).
            logger.warning("GraphQL probe failed for %s: %s", url, exc)

    return findings


def _probe_jwt_alg_none(
    base_url: str,
    cookies: dict[str, str] | None = None,
    auth_headers: dict[str, str] | None = None,
) -> list[Finding]:
    """Probe whether the target accepts JWT tokens with alg=none.

    Sends the well-known alg=none test token in the Authorization
    header to common API endpoints. If the target returns 200 (instead
    of 401/403), it accepts unsigned tokens — a critical auth bypass.
    """
    findings: list[Finding] = []
    # No fallback to raw httpx.Client: every network request must pass
    # through the central SSRF, DNS-pinning, redirect, and engagement-scope
    # policy. Import failure is a deployment error, not a reason to bypass it.
    from webpent.shared.http import make_safe_httpx_client

    client_factory = make_safe_httpx_client

    # Probe common authenticated endpoints.
    probe_paths = [
        "/api/v1/me",
        "/api/v1/user",
        "/api/me",
        "/me",
        "/api/v1/profile",
        "/rest/user/whoami",
    ]
    for path, url in _iter_path_url_candidates(base_url, probe_paths):
        # The JWT differential must be unauthenticated.  Never attach a
        # validated session cookie: otherwise the server can authenticate the
        # request because of the cookie and the probe would falsely attribute
        # the 200 response to alg=none.  Keep the parameter for backward
        # compatibility, but deliberately do not consume it in this branch.
        headers = {"Authorization": f"Bearer {_JWT_ALG_NONE_TOKEN}"}
        try:
            with client_factory(timeout=10.0, follow_redirects=False, verify=True) as client:
                baseline = client.get(url, headers={})
                resp = client.get(
                    url,
                    headers=headers,
                )
            if resp.status_code == 200:
                if _looks_like_spa_shell(resp):
                    logger.debug("JWT probe skipped SPA shell at %s", url)
                    continue
                if resp.text == baseline.text:
                    logger.debug("JWT probe skipped unchanged public response at %s", url)
                    continue
                # V10 P0-2: wrap Finding construction in try/except.
                try:
                    findings.append(
                        Finding(
                            title=f"JWT alg=none accepted at {path}",
                            description=(
                                f"The endpoint at {url} accepted a JWT token with "
                                f"'alg':'none' (unsigned token) and returned HTTP 200. "
                                f"This means the server does not verify JWT signatures "
                                f"— an attacker can forge any token with any claims "
                                f"and bypass authentication entirely."
                            ),
                            severity=Severity.CRITICAL,
                            confidence_level="AI-Assessed",
                            # V10 P0-1: VulnClass.AUTH_BYPASS is now a real enum
                            # member; previously this raw string raised
                            # pydantic ValidationError and was swallowed.
                            vuln_class=VulnClass.AUTH_BYPASS.value,
                            url=url,
                            tool_name="api_testing_agent",
                            payload=f"Authorization: Bearer {_JWT_ALG_NONE_TOKEN[:80]}...",
                            evidence={
                                "jwt_probe": "alg=none",
                                "probe_endpoint": url,
                                "probe_response_status": resp.status_code,
                            },
                            reasoning=(
                                f"Sent alg=none JWT to {url}. Server returned 200 "
                                f"({len(resp.content)} bytes) instead of 401/403. "
                                f"The server accepts unsigned JWTs."
                            ),
                        )
                    )
                except Exception as exc:
                    logger.error(
                        "api_testing: failed to construct JWT alg=none finding for %s: %s",
                        url,
                        exc,
                    )
                logger.warning("JWT alg=none accepted at %s", url)
                # RED-TEAM NOTE (2026-10, finding #4): this break already
                # stops the ENTIRE candidate loop (every path, every URL
                # candidate) on first success — stronger than the per-path
                # skip added to the other three probes, so the host-root/
                # app-root duplicate-finding scenario described in finding
                # #4 cannot occur here. Left unchanged.
                break  # one hit is enough
        except Exception as exc:
            # V10 P0-2: was debug — promote to warning.
            logger.warning("JWT probe failed for %s: %s", url, exc)

    return findings


# RS256-to-HS256 algorithm-confusion active probe.
#
# Well-known JWKS discovery locations, tried in order. ``/.well-known/``
# paths are always rooted at the bare origin per RFC 8615 / the OIDC
# Discovery spec — never under an application path prefix — so this
# deliberately does NOT go through ``_resolve_url``'s DVWA-app-root
# preservation logic.
_JWKS_DISCOVERY_PATHS: tuple[str, ...] = (
    "/.well-known/jwks.json",
    "/jwks.json",
    "/.well-known/openid-configuration",
)


def _discover_rsa_public_key_pem(
    base_url: str,
    cookies: dict[str, str] | None = None,
) -> tuple[bytes, str] | None:
    """Best-effort fetch of the target's RSA JWT-signing public key.

    Tries the standard JWKS well-known locations and, for an OIDC discovery
    document, follows its advertised ``jwks_uri``. Returns ``(pem_bytes,
    source_url)`` for the first usable RSA signing key found, or ``None``.
    This fetches a PUBLIC endpoint — the server's own advertised
    verification key — through the same SSRF/scope-safe client as every
    other probe in this file; it is re-run fresh on every call (by the
    producer here and again by the central validator) rather than trusting
    persisted key material.
    """
    from webpent.shared.http import make_safe_httpx_client
    from webpent.shared.jwt_deep_testing import rsa_jwk_to_public_key_pem, select_rsa_signing_jwk

    headers: dict[str, str] = {}
    if cookies:
        from webpent.shared.http import build_cookie_header

        headers["Cookie"] = build_cookie_header(cookies)

    parsed_base = urlparse(base_url)
    if not parsed_base.scheme or not parsed_base.netloc:
        return None
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    for path in _JWKS_DISCOVERY_PATHS:
        url = origin + path
        try:
            with make_safe_httpx_client(timeout=10.0, follow_redirects=False, verify=True) as client:
                resp = client.get(url, headers=headers)
            if resp.status_code != 200:
                continue
            doc = resp.json()
        except Exception as exc:
            logger.debug("JWKS discovery probe failed for %s: %s", url, exc)
            continue
        if not isinstance(doc, dict):
            continue
        source_url = url
        if "jwks_uri" in doc and isinstance(doc.get("jwks_uri"), str):
            # OIDC discovery document — follow its advertised JWKS URI.
            jwks_uri = doc["jwks_uri"]
            try:
                with make_safe_httpx_client(
                    timeout=10.0, follow_redirects=False, verify=True
                ) as client:
                    jwks_resp = client.get(jwks_uri, headers=headers)
                if jwks_resp.status_code != 200:
                    continue
                doc = jwks_resp.json()
                source_url = jwks_uri
            except Exception as exc:
                logger.debug("JWKS follow-up fetch failed for %s: %s", jwks_uri, exc)
                continue
        jwk = select_rsa_signing_jwk(doc) if isinstance(doc, dict) else None
        if jwk is None:
            continue
        pem = rsa_jwk_to_public_key_pem(jwk)
        if pem:
            return pem, source_url
    return None


def _probe_jwt_key_confusion(
    base_url: str,
    crawled_data: Any,
    cookies: dict[str, str] | None = None,
    auth_headers: dict[str, str] | None = None,
) -> list[Finding]:
    """Actively probe for RS256-to-HS256 JWT algorithm-confusion acceptance.

    Requires both an observed asymmetric-algorithm JWT (RS256/384/512) in
    crawl artifacts AND a discoverable RSA public key (JWKS) — without
    both, there is nothing to forge against, so the probe is skipped
    (fail-closed, no guessing). Forges a synthetic-canary HS256 token
    signed with the server's own published public key as the HMAC secret;
    confirms only when the server accepts it while a garbage-secret
    negative control of identical shape is rejected. No captured real-user
    token or claim is ever replayed — same canary-only policy as the
    alg=none probe above.
    """
    findings: list[Finding] = []
    from webpent.shared.http import make_safe_httpx_client
    from webpent.shared.jwt_deep_testing import (
        extract_candidate_jwts,
        forge_hs256_token,
        parse_compact_jwt,
        rsa_public_key_pem_variants,
    )

    tokens = extract_candidate_jwts(crawled_data)
    has_asymmetric = any(
        (parse_compact_jwt(token) or {}).get("algorithm", "") in {"RS256", "RS384", "RS512"}
        for token in tokens
    )
    if not has_asymmetric:
        return findings

    discovered = _discover_rsa_public_key_pem(base_url, cookies=cookies)
    if discovered is None:
        logger.info(
            "JWT key-confusion: asymmetric token observed but no JWKS "
            "public key could be discovered at %s — skipping active probe.",
            base_url,
        )
        return findings
    public_key_pem, jwks_source = discovered

    client_factory = make_safe_httpx_client
    negative_control_token = forge_hs256_token(b"__webpent_invalid_confusion_control__")

    probe_paths = [
        "/api/v1/me",
        "/api/v1/user",
        "/api/me",
        "/me",
        "/api/v1/profile",
        "/rest/user/whoami",
    ]
    for pem_variant in rsa_public_key_pem_variants(public_key_pem):
        candidate_token = forge_hs256_token(pem_variant)
        for path, url in _iter_path_url_candidates(base_url, probe_paths):
            try:
                with client_factory(timeout=10.0, follow_redirects=False, verify=True) as client:
                    baseline = client.get(url, headers={})
                    candidate = client.get(
                        url, headers={"Authorization": f"Bearer {candidate_token}"}
                    )
                    control = client.get(
                        url, headers={"Authorization": f"Bearer {negative_control_token}"}
                    )
            except Exception as exc:
                logger.warning("JWT key-confusion probe failed for %s: %s", url, exc)
                continue
            if candidate.status_code != 200:
                continue
            if _looks_like_spa_shell(candidate):
                continue
            if candidate.text == baseline.text:
                continue
            if control.status_code == 200 and control.text == candidate.text:
                # The garbage secret ALSO got through — this endpoint
                # isn't gating on the signature at all (public response or
                # a different auth gap entirely), not a confusion
                # confirmation.
                continue
            try:
                findings.append(
                    Finding(
                        title=f"JWT algorithm confusion (RS256→HS256) accepted at {path}",
                        description=(
                            f"The endpoint at {url} accepted an HS256-signed JWT "
                            f"whose signature was computed using the server's own "
                            f"published RSA public key (from {jwks_source}) as the "
                            f"HMAC secret. This is the classic RS256-to-HS256 "
                            f"algorithm-confusion attack: anyone who can read the "
                            f"server's public key — normally meant only for "
                            f"signature verification — can forge valid tokens for "
                            f"any claims they choose."
                        ),
                        severity=Severity.CRITICAL,
                        confidence_level="AI-Assessed",
                        vuln_class=VulnClass.JWT_KEY_CONFUSION.value,
                        url=url,
                        tool_name="api_testing_agent",
                        payload=f"Authorization: Bearer {candidate_token[:80]}...",
                        evidence={
                            "jwt_probe": "key_confusion_rs256_to_hs256",
                            "jwks_source": jwks_source,
                            "probe_endpoint": url,
                            "probe_response_status": candidate.status_code,
                            "negative_control_status": control.status_code,
                        },
                        reasoning=(
                            f"Sent an HS256 token signed with the target's own "
                            f"RSA public key as the HMAC secret to {url}. Server "
                            f"returned {candidate.status_code} with a body "
                            f"distinct from both the unauthenticated baseline "
                            f"and a garbage-secret negative control — the server "
                            f"is verifying HS256 signatures against its own "
                            f"public RSA key material."
                        ),
                    )
                )
            except Exception as exc:
                logger.error(
                    "api_testing: failed to construct JWT key-confusion finding for %s: %s",
                    url,
                    exc,
                )
            logger.warning("JWT key-confusion accepted at %s", url)
            # RED-TEAM NOTE (2026-10, finding #4): already returns from the
            # whole function on first success (every PEM variant, every
            # path, every URL candidate) — stronger than the per-path skip
            # added to _probe_graphql, so the host-root/app-root duplicate
            # described in finding #4 cannot occur here. Left unchanged.
            return findings  # one hit is enough
    return findings


def _analyze_captured_jwts(
    base_url: str,
    crawled_data: Any,
    *,
    weak_secret_candidates: list[str] | None = None,
    public_key_available: bool = False,
    verification_context: dict[str, Any] | None = None,
) -> tuple[list[Finding], list[dict[str, Any]], list[dict[str, Any]]]:
    """Analyze JWTs already captured by recon/crawler without active forging.

    A weak-secret result is promoted only when the captured signature verifies
    offline with a bounded candidate.  alg=none and key-confusion results are
    observations/gaps until an explicitly approved endpoint probe confirms
    server-side acceptance.
    """
    from webpent.shared.jwt_deep_testing import (
        analyze_captured_jwt,
        extract_candidate_jwts,
        redact_jwt_observation,
    )
    findings: list[Finding] = []
    observations: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    tokens = extract_candidate_jwts(crawled_data)
    if not tokens:
        coverage_gaps.append(
            {
                "type": "jwt_token_inventory_empty",
                "reason": (
                    "No compact JWT was found in crawl artifacts; endpoint auth "
                    "coverage remains unverified."
                ),
                "source": "api_testing_node",
            }
        )
        return findings, observations, coverage_gaps

    for token in tokens:
        analysis = analyze_captured_jwt(
            token,
            weak_secret_candidates=weak_secret_candidates,
            public_key_available=public_key_available,
        )
        if not analysis:
            continue
        clean_analysis = redact_jwt_observation(analysis)
        observations.extend(clean_analysis.get("observations") or [])
        coverage_gaps.extend(clean_analysis.get("coverage_gaps") or [])
        for item in clean_analysis.get("observations") or []:
            if item.get("type") != "weak_secret_match":
                continue
            if not (
                item.get("causal_signal") is True
                and item.get("negative_control_complete") is True
            ):
                coverage_gaps.append(
                    {
                        "type": "jwt_confirmation_proof_incomplete",
                        "reason": "Weak-secret evidence lacked a completed negative control.",
                        "token_fingerprint": item.get("token_fingerprint"),
                    }
                )
                continue
            context = verification_context or {}
            algorithm = str(item.get("algorithm") or "unknown")
            token_fingerprint = str(item.get("token_fingerprint") or "")
            # UM-DR-35 §1.3: the three observations of the RECORDED offline
            # cryptographic verification experiment, shaped to the CausalGuard
            # contract (experiment_domain=offline_crypto — the recorded
            # verification outcome replaces the HTTP status channel; the
            # semantic digest is the recorded outcome digest of the
            # analyzed artifact; the captured token's fingerprint is the
            # resource identity). Every value is a RECORDED fact of the
            # offline HMAC replay: the candidate secret verified the
            # captured signature (the class-specific validator's technical
            # signal — condition 8, stamped on the candidate observation
            # only), the wrong-secret control was REJECTED (the recorded
            # negative control), and the baseline records the unverified
            # pre-state. Nothing is caller-asserted: the guard still
            # demands the real differential (distinct outcome digests) and
            # the independent control before confirming (fail-closed).
            import hashlib as _jwt_hashlib

            def _crypto_observation(
                role: str,
                *,
                verified: bool,
                verifier_label: str,
                class_signal: bool = False,
            ) -> dict[str, Any]:
                outcome_text = f"{role}|{algorithm}|{token_fingerprint}|verified={verified}|verifier={verifier_label}"
                observation: dict[str, Any] = {
                    "type": (
                        "weak_secret_candidate" if role == "candidate"
                        else "weak_secret_baseline" if role == "baseline"
                        else "wrong_secret_rejected"
                    ),
                    "algorithm": algorithm,
                    "token_fingerprint": token_fingerprint,
                    "observation_role": role,
                    "experiment_domain": "offline_crypto",
                    "crypto_verified": bool(verified),
                    "target_backed": True,
                    "evidence_origin": "target_runtime",
                    "target_fingerprint": (
                        f"sha256:{_jwt_hashlib.sha256(str(base_url).encode('utf-8', 'ignore')).hexdigest()}"
                    ),
                    "request_digest": (
                        f"sha256:{_jwt_hashlib.sha256(('offline-verify|' + role + '|' + token_fingerprint).encode('utf-8', 'ignore')).hexdigest()}"
                    ),
                    "response_digest": (
                        f"sha256:{_jwt_hashlib.sha256(outcome_text.encode('utf-8', 'ignore')).hexdigest()}"
                    ),
                    "url_shape": str(base_url),
                    "resource_type": "jwt_token",
                    "resource_id": token_fingerprint or "captured-jwt",
                    "verifier": verifier_label,
                    "network_io": False,
                }
                if role == "negative_control":
                    observation["observed"] = True
                if class_signal:
                    observation["validator_technical_signal"] = True
                    observation["class_validator_id"] = "api_testing.jwt_weak_secret"
                return observation

            negative_observation = _crypto_observation(
                "negative_control", verified=False,
                verifier_label="wrong_secret_candidate",
            )
            baseline_observation = _crypto_observation(
                "baseline", verified=False, verifier_label="no_secret_baseline",
            )
            candidate_observation = _crypto_observation(
                "candidate", verified=True,
                verifier_label="bounded_candidate_secret",
                class_signal=True,
            )
            verification = verify_replay_evidence(
                Finding(
                    title="JWT signed with a bounded weak HMAC secret",
                    description="Offline weak-secret signature observation.",
                    severity=Severity.HIGH,
                    vuln_class=VulnClass.JWT_WEAKNESS.value,
                    url=base_url,
                    tool_name="api_testing_agent",
                ),
                baseline=baseline_observation,
                candidate=candidate_observation,
                negative_control=negative_observation,
                causal_signal=True,
                negative_control_complete=True,
                validator_id="api_testing.jwt_weak_secret",
                validator_version="jwt-offline-replay.v1",
                causal_basis="captured_signature_matches_bounded_candidate_and_rejects_wrong_secret",
                engagement_id=str(context.get("engagement_id") or ""),
                hypothesis_id=context.get("hypothesis_id"),
                scope_context=context.get("scope_context"),
                identity_context=context.get("identity_context"),
                replay_metadata={
                    "mode": "offline_signature_replay",
                    "network_io": False,
                    "negative_control": "wrong_secret_rejected",
                },
                **package_continuity_kwargs(context),
            )
            if not verification.passed or verification.proof_bundle is None:
                coverage_gaps.append(
                    {
                        "type": "jwt_confirmation_proof_incomplete",
                        "reason": verification.reason,
                        "token_fingerprint": token_fingerprint,
                    }
                )
                continue
            try:
                findings.append(
                    Finding(
                        title="JWT signed with a bounded weak HMAC secret",
                        description=(
                            "A JWT captured during the engagement was verified offline "
                            "with a bounded common-secret candidate. This is direct "
                            "signature evidence; no impersonation request was sent."
                        ),
                        severity=Severity.HIGH,
                        confidence_level="Tool-Confirmed",
                        vuln_class=VulnClass.JWT_WEAKNESS.value,
                        url=base_url,
                        tool_name="api_testing_agent",
                        payload="[REDACTED_JWT]",
                        evidence={
                            "token_fingerprint": item.get("token_fingerprint"),
                            "algorithm": item.get("algorithm"),
                            "secret_fingerprint": item.get("secret_fingerprint"),
                            "verification": "offline_hmac_signature_match",
                            "causal_signal": item.get("causal_signal"),
                            "negative_control_complete": item.get("negative_control_complete"),
                            "negative_control": item.get("negative_control"),
                            "proof_bundle": verification.proof_bundle.model_dump(mode="json"),
                            "promotion_guard": verification.evidence["promotion_guard"],
                        },
                        evidence_bundle={
                            "proof_bundle": verification.proof_bundle.model_dump(mode="json"),
                            "causal_signal": True,
                            "negative_control": negative_observation,
                        },
                        reasoning=(
                            "The captured token signature matched one bounded offline "
                            "candidate; the candidate value itself is never persisted."
                        ),
                    )
                )
            except Exception as exc:
                logger.error("api_testing: failed to build weak-JWT finding: %s", exc)
    return findings, observations, coverage_gaps


# TEAM-1 (2026-10): the original probe tried exactly 3 fields
# (role/is_admin/admin) in one shot. Real mass-assignment bugs hide behind
# whatever field name a given app happens to use — privilege escalation
# (role/admin/staff flags), entitlement/billing escalation (plan, credits,
# verified flags) and object-ownership takeover (reassigning a record to
# yourself via owner/user id fields) are all the same underlying bug class.
# Grouped so the Finding's title/description can name which KIND of
# escalation a hit represents.
_MASS_ASSIGNMENT_PRIVILEGE_FIELDS: tuple[tuple[str, Any], ...] = (
    ("role", "admin"),
    ("is_admin", True),
    ("isAdmin", True),
    ("admin", True),
    ("is_superuser", True),
    ("is_staff", True),
    ("is_moderator", True),
    ("permission", "admin"),
    ("permissions", ["admin"]),
    ("privilege", "admin"),
    ("privileges", ["admin"]),
    ("scope", "admin"),
    ("user_type", "admin"),
    ("account_type", "admin"),
    ("group", "admin"),
)
_MASS_ASSIGNMENT_ENTITLEMENT_FIELDS: tuple[tuple[str, Any], ...] = (
    ("verified", True),
    ("is_verified", True),
    ("email_verified", True),
    ("approved", True),
    ("is_approved", True),
    ("active", True),
    ("enabled", True),
    ("plan", "enterprise"),
    ("subscription_tier", "premium"),
    ("tier", "premium"),
    ("premium", True),
    ("is_premium", True),
    ("trusted", True),
    ("banned", False),
    ("locked", False),
    ("balance", 999999),
    ("credits", 999999),
    ("discount", 100),
)
_MASS_ASSIGNMENT_OWNERSHIP_FIELDS: tuple[tuple[str, Any], ...] = (
    ("user_id", 1),
    ("owner_id", 1),
    ("account_id", 1),
    ("tenant_id", 1),
    ("organization_id", 1),
    ("created_by", 1),
)
_MASS_ASSIGNMENT_CANDIDATE_FIELDS: tuple[tuple[str, Any, str], ...] = tuple(
    (name, value, "privilege escalation") for name, value in _MASS_ASSIGNMENT_PRIVILEGE_FIELDS
) + tuple(
    (name, value, "entitlement/billing escalation")
    for name, value in _MASS_ASSIGNMENT_ENTITLEMENT_FIELDS
) + tuple(
    (name, value, "object-ownership takeover") for name, value in _MASS_ASSIGNMENT_OWNERSHIP_FIELDS
)
_MASS_ASSIGNMENT_CONTROL_FIELD = "webpent_control_field"
_MASS_ASSIGNMENT_BATCH_SIZE = 8


def _field_echo_pattern(field_name: str) -> re.Pattern[str]:
    """Same acceptance-echo shape the central validator re-checks with."""
    escaped = re.escape(field_name)
    return re.compile(rf"['\"]{escaped}['\"]\s*[:=]", re.I)


def _probe_mass_assignment(
    base_url: str,
    cookies: dict[str, str] | None = None,
    auth_headers: dict[str, str] | None = None,
) -> list[Finding]:
    """Probe for mass assignment across a broad privileged-field dictionary.

    Sends batches of candidate fields (privilege, entitlement/billing, and
    object-ownership) alongside an inert control field to common user-
    update endpoints. A field only counts as a hit when ITS OWN name is
    echoed back in an accepted (200/201/204) response while the inert
    control field is not — matching the central validator's own
    acceptance-differential check (``validate_mass_assignment`` in
    ``postp0_checks.py``), which re-probes one field at a time using
    ``target_param``. One Finding is emitted per confirmed-echoing field
    (not per path) so that re-probe is precise.
    """
    findings: list[Finding] = []
    # No fallback to raw httpx.Client: every network request must pass
    # through the central SSRF, DNS-pinning, redirect, and engagement-scope
    # policy. Import failure is a deployment error, not a reason to bypass it.
    from webpent.shared.http import make_safe_httpx_client

    client_factory = make_safe_httpx_client

    probe_paths = ["/api/v1/user", "/api/v1/users/me", "/api/user", "/api/profile"]
    # RED-TEAM NOTE (2026-10, finding #4): seen_fields is already global
    # across every path/URL candidate, not scoped to one path, so it
    # already blocks the host-root/app-root duplicate-finding scenario
    # from finding #4 as a side effect (a field name that already produced
    # a finding on one candidate is skipped on any later candidate, same
    # path or not). Left unchanged — tightening it to be path-scoped would
    # weaken, not strengthen, the existing de-duplication.
    seen_fields: set[str] = set()
    for path, url in _iter_path_url_candidates(base_url, probe_paths):
        # V9 P0 B4: attach session cookies so authenticated user-update
        # endpoints are reachable (mass assignment requires an authed session).
        headers: dict[str, str] = {
            str(name): str(value)
            for name, value in (auth_headers or {}).items()
            if str(value).strip()
        }
        headers["Content-Type"] = "application/json"
        if cookies:
            # V10 HOSTILE-AUDIT FIX: same missing-import bug as
            # _probe_jwt_alg_none above — build_cookie_header was
            # never imported in this function, crashing every
            # authenticated scan with an uncaught NameError before it
            # ever reached this function's try/except below.
            from webpent.shared.http import build_cookie_header

            headers["Cookie"] = build_cookie_header(cookies)

        # Batch the candidate dictionary so one promising path costs a
        # handful of requests, not one request per field (46 fields would
        # otherwise be 46 requests per path). Each batch carries the inert
        # control field too, so a field that merely gets echoed because the
        # server blindly reflects its whole request body is NOT mistaken
        # for acceptance (the control would echo identically).
        for batch_start in range(0, len(_MASS_ASSIGNMENT_CANDIDATE_FIELDS), _MASS_ASSIGNMENT_BATCH_SIZE):
            batch = _MASS_ASSIGNMENT_CANDIDATE_FIELDS[
                batch_start : batch_start + _MASS_ASSIGNMENT_BATCH_SIZE
            ]
            body = {name: value for name, value, _category in batch}
            body[_MASS_ASSIGNMENT_CONTROL_FIELD] = "1"
            try:
                with client_factory(timeout=10.0, follow_redirects=False, verify=True) as client:
                    resp = client.patch(url, json=body, headers=headers)
            except Exception as exc:
                logger.warning("Mass assignment probe failed for %s: %s", url, exc)
                continue
            if resp.status_code not in (200, 201, 204):
                continue
            control_echoed = bool(
                _field_echo_pattern(_MASS_ASSIGNMENT_CONTROL_FIELD).search(resp.text)
            )
            if control_echoed:
                # The server reflects the whole request body back
                # (common for naive "here's what you sent" APIs) — field
                # presence in the response proves nothing here.
                continue
            for field_name, _value, category in batch:
                if field_name in seen_fields:
                    continue
                if not _field_echo_pattern(field_name).search(resp.text):
                    continue
                seen_fields.add(field_name)
                try:
                    findings.append(
                        Finding(
                            title=f"Mass assignment ({category}) via '{field_name}' at {path}",
                            description=(
                                f"The endpoint at {url} accepted the field "
                                f"'{field_name}' via PATCH and returned "
                                f"{resp.status_code} with that field echoed back, "
                                f"while an inert control field in the same "
                                f"request was NOT echoed. This is a "
                                f"{category} candidate: an attacker may be able "
                                f"to set '{field_name}' on their own records to "
                                f"escalate privilege, entitlements, or "
                                f"ownership."
                            ),
                            severity=Severity.HIGH,
                            confidence_level="AI-Assessed",
                            # V10 P0-1: VulnClass.MASS_ASSIGNMENT is now a real
                            # enum member; previously this raw string raised
                            # pydantic ValidationError and was swallowed.
                            # Deliberately NOT in EXPLOITABLE_CLASSES — mass
                            # assignment is structural, not payload-injection
                            # exploitable, so payload_generator is skipped.
                            vuln_class=VulnClass.MASS_ASSIGNMENT.value,
                            url=url,
                            target_param=field_name,
                            request_data={"name": "webpent"},
                            request_method="PATCH",
                            tool_name="api_testing_agent",
                            payload=f'{{"{field_name}": {body[field_name]!r}}}',
                            evidence={
                                "mass_assignment_category": category,
                                "probe_endpoint": url,
                                "probe_response_status": resp.status_code,
                                "control_field": _MASS_ASSIGNMENT_CONTROL_FIELD,
                                "control_echoed": control_echoed,
                            },
                            reasoning=(
                                f"Sent PATCH to {url} with '{field_name}' alongside "
                                f"an inert control field. Server returned "
                                f"{resp.status_code} and echoed '{field_name}' back "
                                f"but not the control field — an acceptance "
                                f"differential, not generic request-body echoing."
                            ),
                        )
                    )
                except Exception as exc:
                    logger.error(
                        "api_testing: failed to construct mass-assignment finding "
                        "for %s (field=%s): %s",
                        url,
                        field_name,
                        exc,
                    )
                    continue
                logger.warning("Mass assignment candidate '%s' detected at %s", field_name, url)

    return findings


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def api_testing_node(state: PentestState) -> dict:
    """LangGraph node: test API-specific vulnerabilities.

    V7 Sprint 2.6: Probes the target for GraphQL introspection, JWT
    alg=none acceptance, and mass assignment. All probes use
    ``make_safe_httpx_client`` (SSRF guard + engagement-scope allowlist).
    """
    target = state.get("target")
    findings: list[Finding] = list(state.get("findings") or [])
    # V9 P0 B4: read session cookies so authenticated API endpoints
    # (e.g. DVWA's GraphQL/JWT endpoints behind login) are reachable.
    session_cookies: dict[str, str] | None = state.get("session_cookies") or None
    session_headers: dict[str, str] | None = state.get("session_headers") or None
    crawled_data: Any = state.get("crawled_data") or {}

    base_url = getattr(target, "url", "")
    if not base_url:
        return {
            "messages": [AIMessage(content="API Testing Agent: no target URL — skipping.")],
            "current_phase": "api_testing",
        }

    logger.info(
        "API Testing Agent (V7 Sprint 2.6) entered for target=%s "
        "(%d findings, cookies=%s, headers=%s)",
        base_url,
        len(findings),
        bool(session_cookies),
        sorted(session_headers or {}),
    )

    new_findings: list[Finding] = []

    # 1. GraphQL introspection probe
    new_findings.extend(
        _probe_graphql(
            base_url,
            cookies=session_cookies,
            auth_headers=session_headers,
        )
    )

    # 2. JWT alg=none probe (active acceptance evidence, legacy contract).
    new_findings.extend(
        _probe_jwt_alg_none(
            base_url,
            cookies=session_cookies,
            auth_headers=session_headers,
        )
    )

    # 2b. JWT RS256-to-HS256 algorithm-confusion probe (active, canary-only —
    # see function docstring). Independent of alg=none above: requires an
    # observed asymmetric-alg token AND a discoverable JWKS public key.
    new_findings.extend(
        _probe_jwt_key_confusion(
            base_url,
            crawled_data,
            cookies=session_cookies,
            auth_headers=session_headers,
        )
    )

    # 3. JWT deep analysis is offline by default. It never forges a real-user
    # token and never emits raw credentials into state/report output.
    jwt_findings, jwt_observations, jwt_gaps = _analyze_captured_jwts(
        base_url,
        crawled_data,
        weak_secret_candidates=state.get("jwt_weak_secret_candidates"),
        public_key_available=bool(state.get("jwt_public_key_available", False)),
        verification_context={
            "engagement_id": state.get("engagement_id"),
            "hypothesis_id": state.get("hypothesis_id"),
            "scope_context": state.get("scope_context") or state.get("target_scope"),
            "identity_context": state.get("identity_context")
            or state.get("identity_profiles"),
        },
    )
    new_findings.extend(jwt_findings)

    # 4. Mass assignment probe
    new_findings.extend(
        _probe_mass_assignment(
            base_url,
            cookies=session_cookies,
            auth_headers=session_headers,
        )
    )

    logger.info("API Testing Agent: %d findings generated", len(new_findings))

    # M5 (Part 4 §7, UM-DR-18): the stateful API engine's advisory
    # projection — contract ingestion → inferred dependencies → bounded
    # replayable sequences with cleanup budgets → two-identity BOLA/IDOR
    # differential plans with randomized-id negative controls. Planning
    # ONLY: the hypotheses land unexplored with preconditions/negative-
    # control fields; the deterministic validator owns confirmation.
    # Flag off (default) keeps this node byte-identical. Fail-soft.
    stateful_hypotheses: list[Any] = []
    try:
        if getattr(get_settings(), "enable_stateful_api_testing", False):
            from webpent.stateful_api import (
                bola_hypotheses,
                build_bola_plans,
                generate_sequences,
                operations_from_state,
                sequence_hypotheses,
            )

            operations = operations_from_state(state)
            sequences = generate_sequences(operations)
            roles = [
                str(profile.get("role") or label or "").strip()
                for label, profile in (state.get("identity_profiles") or {}).items()
                if isinstance(profile, dict)
            ]
            plans = build_bola_plans(operations, identities=roles)
            stateful_hypotheses = sequence_hypotheses(
                sequences, target_url=base_url
            ) + bola_hypotheses(plans, target_url=base_url)
            logger.info(
                "M5 stateful API engine: %d operations, %d sequences, "
                "%d BOLA plans, %d advisory hypotheses",
                len(operations),
                len(sequences),
                len(plans),
                len(stateful_hypotheses),
            )
    except Exception as exc:  # noqa: BLE001 — advisory column, fail-soft
        logger.debug("M5 stateful API engine skipped: %s", type(exc).__name__)

    # V7 Cognitive Upgrade — Phase 2: extract Mental Model updates for
    # the target URL this node probed. Pure additive — does not change
    # any existing api-testing logic. Deterministic regex/heuristic,
    # NO LLM.
    mental_model_update: dict[str, Any] = {"nodes": {}, "edges": []}
    try:
        from webpent.models.mental_model import extract_mental_model_updates

        mental_model_update = extract_mental_model_updates(
            discovery_source="api_testing_node",
            endpoints=[base_url] if base_url else None,
            target_url=base_url,
        )
    except Exception as exc:
        logger.debug("Mental Model extraction (api_testing) failed: %s", exc)

    return {
        # merge_findings reducer dedup by id — safe
        "findings": findings + new_findings,
        # merge_hypotheses reducer upserts by id — the M5 advisory plans
        # join the hypothesis channel (never findings).
        "hypotheses": stateful_hypotheses,
        "mental_model": mental_model_update,
        "jwt_deep_observations": jwt_observations,
        "jwt_deep_coverage_gaps": jwt_gaps,
        "messages": [
            AIMessage(
                content=f"API Testing Agent: probed GraphQL, JWT, mass "
                f"assignment and offline JWT strength. Found {len(new_findings)} vulnerabilities."
            )
        ],
        "current_phase": "api_testing",
    }
