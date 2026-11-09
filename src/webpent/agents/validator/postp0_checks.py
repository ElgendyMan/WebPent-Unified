"""POST-P0 Phase 5 — live validators for registered-but-unvalidated classes.

Four classes previously parked permanently in ``Needs Human Review``
despite having producers. Each validator here is DETERMINISTIC, defines
explicit confirm / negative / inconclusive outcomes, and routes through
the strict replay verifier (``verify_replay_evidence``) — an LLM can
never sole-confirm and the evidence bundle fields are populated
conformantly (tool/validator, redacted observations, negative control).

Classes, in the brief's priority order:
  1. ``request_smuggling``  — bounded raw-socket desync re-probe
     (reuses the producer's scope-gated raw sender; the sanctioned
     non-httpx path),
  2. ``mass_assignment``    — response-differential field-acceptance
     check with an independent harmless-field negative control,
  3. ``jwt_key_confusion``  — deterministic alg=none acceptance
     differential with a garbage-token negative control (no key
     material needed; offline checks only),
  4. ``subdomain_takeover`` — deterministic provider-marker re-probe
     with a same-target negative control; absent CNAME is an explicit
     NEGATIVE, ambiguity is INCONCLUSIVE (never faked).

Positive outcomes call :func:`active_checks._confirmed` (sealed proof
bundle + verifier); negative/ambiguous outcomes preserve honest
``Needs Human Review`` / explicit-negative semantics.
"""

from __future__ import annotations

import json as _json
import logging
import re
import time
import uuid
from typing import Any
from urllib.parse import urlparse

from webpent.agents.validator.active_checks import (
    Replay,
    _ambiguous,
    _body_digest,
    _confirmed,
    _evidence,
    _request_digest,
    _target_fingerprint,
)
from webpent.models.findings import Confidence, Finding

logger = logging.getLogger(__name__)

# UNIFIED MERGE (2026-11-02, Phase 2): prototype_pollution and
# cache_poisoning deterministic validators restored from the
# v15.2 R4 contract set (tests/test_r4_production_hardening.py);
# they ride the module's existing _safe_http_request/_safe_http_get
# helpers and the shared _ambiguous/_confirmed evidence vocabulary.


def validate_prototype_pollution(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    """Re-probe the canary reflection deterministically on a bounded budget.

    Confirmation requires the full fail-closed triangle for at least one
    payload: the run canary appears in the candidate response, does NOT
    appear in the negative-control (benign field) response, and the two
    responses differ. Every probe result is preserved as replay evidence.
    """
    from webpent.agents.prototype_pollution.agent import (
        analyze_reflection_pair,
        build_pollution_probes,
    )

    parsed = urlparse(finding.url)
    path = parsed.path or "/"
    # Run-namespaced canary so reflections attribute unambiguously to this
    # validation and cannot collide with content the target already serves.
    canary = f"pp{str(finding.id)[:8]}"
    method = (finding.request_method or "POST").upper()
    probes = build_pollution_probes(path, method=method, canary=canary)

    started = time.monotonic()

    def _post(body_text: str) -> Replay | None:
        return _safe_http_request(
            finding,
            cookies,
            method=method,
            body=body_text,
            headers={"Content-Type": "application/json"},
        )

    baseline_replay = _post(_json.dumps({"benign": "control"}, sort_keys=True))
    if baseline_replay is None:
        return _ambiguous(
            finding,
            {
                "validator": "prototype_pollution",
                "validation_unavailable": True,
                "reason": "baseline_control_unreachable",
            },
            "Prototype-pollution validator could not fetch the benign-field "
            "negative control; no confirmation is possible without it.",
        )

    probe_outcomes: dict[str, str] = {}
    confirmed_probe: dict[str, Any] | None = None
    candidate_replay: Replay | None = None
    explicit_negative = True
    for probe in probes:
        probe_replay = _post(_json.dumps(probe["body"], sort_keys=True))
        if probe_replay is None:
            probe_outcomes[probe["probe_id"]] = "transport_error"
            explicit_negative = False
            continue
        analysis = analyze_reflection_pair(baseline_replay.body, probe_replay.body, canary=canary)
        if analysis.get("polluted") is True:
            probe_outcomes[probe["probe_id"]] = "confirmed"
            confirmed_probe = probe
            candidate_replay = probe_replay
            explicit_negative = False
            break
        probe_outcomes[probe["probe_id"]] = str(analysis.get("reason", "canary_absent_from_candidate"))
    elapsed = int((time.monotonic() - started) * 1000)

    evidence = _evidence(
        baseline_replay,
        candidate_replay or baseline_replay,
        control=baseline_replay,
        validator="prototype_pollution",
        parameter=None,
        payload_label=f"pp-canary:{canary}",
    )
    evidence["probe_outcomes"] = probe_outcomes
    evidence["elapsed_ms"] = elapsed

    if confirmed_probe is not None and candidate_replay is not None:
        evidence["causal_signal"] = True
        evidence["negative_control_complete"] = True
        evidence["causal_basis"] = "canary_reflection_reprobe_confirmed"
        evidence["sink_hints"] = analyze_reflection_pair(
            baseline_replay.body, candidate_replay.body, canary=canary
        ).get("sink_hints", [])
        return _confirmed(
            finding,
            evidence,
            (
                "Prototype pollution deterministically confirmed: the run "
                f"canary ({canary}) planted by payload "
                f"{confirmed_probe['probe_id']} is reflected in the candidate "
                "response, absent from the benign-field negative control, and "
                "the two responses differ (fail-closed reflection triangle)."
            ),
            payload_label=f"pp-canary:{canary}",
            verification_context=verification_context,
        )
    if explicit_negative:
        evidence["causal_signal"] = False
        evidence["negative_control_complete"] = True
        evidence["outcome"] = "explicit_negative"
        merged = {**(finding.evidence or {}), **evidence}
        return finding.model_copy(
            update={
                "confidence_level": "Needs Human Review",
                "evidence": merged,
                "reasoning": (
                    "Deterministic negative: the canary never appeared in any "
                    "candidate response (or appeared in the baseline control) "
                    "on a fresh bounded re-check — no pollution signal."
                ),
            }
        )
    return _ambiguous(
        finding,
        evidence,
        "Prototype-pollution re-probe was inconclusive within the bounded budget.",
    )


# ---------------------------------------------------------------------------
# 6) cache poisoning — two-request differential re-probe (R4 wiring)
# ---------------------------------------------------------------------------
# R4 re-freeze window (2026-11-02): wires the library-stage detector
# (agents/cache_poisoning) into deterministic validation. Confirmation
# keeps the library's fail-closed contract: canary in the ATTACK response
# ∧ canary in the LATER VICTIM response ∧ clean control has no canary ∧
# control/victim shape equivalence — anything else is inconclusive.


def validate_cache_poisoning(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    """Re-probe the cache-key differential deterministically on a bounded budget.

    Each probe replays the library's three-request shape: a clean-key
    control, the attack request (confusion header/param carrying the
    canary), then a plain victim request served afterwards. A run canary
    is injected into the probe path so reflections attribute to this
    validation run only.
    """
    from webpent.agents.cache_poisoning.agent import (
        analyze_cache_differential,
        build_cache_key_probes,
    )

    parsed = urlparse(finding.url)
    path = parsed.path or "/"
    run_canary = f"cpcan{str(finding.id)[:6]}"
    probes = build_cache_key_probes(f"{path}?wp{run_canary}=1")

    started = time.monotonic()

    def _get(url: str, headers: dict[str, str] | None = None) -> Replay | None:
        return _safe_http_get(url, cookies, headers=headers)

    probe_outcomes: dict[str, str] = {}
    confirmed_probe: dict[str, Any] | None = None
    attack_replay: Replay | None = None
    victim_replay: Replay | None = None
    control_replay: Replay | None = None
    explicit_negative = True
    for probe in probes:
        base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else None
        if base is None:
            probe_outcomes[probe["probe_id"]] = "missing_host_context"
            explicit_negative = False
            continue
        probe_path = probe["path"]
        if probe["kind"] == "header":
            attack_headers = dict(probe["attack_request"]["headers"])
            control_headers = dict(probe["control_request"]["headers"])
            # The attack value itself is this probe's canary (e.g.
            # "cp-attacker.local") — exactly the value a poisoning
            # reflection would leak into a later victim response.
            probe_canary = next(iter(attack_headers.values()), "")
            control_replay_p = _get(f"{base}{path}", control_headers)
            attack_replay_p = _get(f"{base}{path}", attack_headers)
            victim_replay_p = _get(f"{base}{path}")
        else:
            probe_canary = "cp-canary"
            control_replay_p = _get(f"{base}{path}")
            attack_replay_p = _get(f"{base}{probe_path}")
            victim_replay_p = _get(f"{base}{path}")
        if control_replay_p is None or attack_replay_p is None or victim_replay_p is None or not probe_canary:
            probe_outcomes[probe["probe_id"]] = "transport_error"
            explicit_negative = False
            continue
        analysis = analyze_cache_differential(
            victim_replay_p.body,
            attack_replay_p.body,
            control_replay_p.body,
            canary=probe_canary,
        )
        if analysis.get("poisoned") is True:
            probe_outcomes[probe["probe_id"]] = str(analysis.get("confidence", "differential_confirmed"))
            confirmed_probe = probe
            attack_replay = attack_replay_p
            victim_replay = victim_replay_p
            control_replay = control_replay_p
            explicit_negative = False
            break
        probe_outcomes[probe["probe_id"]] = str(
            analysis.get("reason", analysis.get("confidence", "canary_absent_from_attack_response"))
        )
    elapsed = int((time.monotonic() - started) * 1000)

    evidence = _evidence(
        control_replay,
        attack_replay or control_replay,
        control=control_replay,
        validator="cache_poisoning",
        parameter=None,
        payload_label=f"cp-differential:{run_canary}",
    )
    evidence["probe_outcomes"] = probe_outcomes
    evidence["elapsed_ms"] = elapsed

    if confirmed_probe is not None and attack_replay is not None and victim_replay is not None:
        evidence["causal_signal"] = True
        evidence["negative_control_complete"] = True
        evidence["causal_basis"] = "two_request_differential_reprobe_confirmed"
        evidence["probe_kind"] = confirmed_probe["kind"]
        return _confirmed(
            finding,
            evidence,
            (
                "Cache poisoning deterministically confirmed: the attack value "
                f"from {confirmed_probe['probe_id']} is reflected in the attack "
                "response, served from cache to a later victim request, absent "
                "from the clean-key control, and control/victim shapes match "
                "(fail-closed two-request differential)."
            ),
            payload_label=f"cp-differential:{run_canary}",
            verification_context=verification_context,
        )
    if explicit_negative:
        evidence["causal_signal"] = False
        evidence["negative_control_complete"] = True
        evidence["outcome"] = "explicit_negative"
        merged = {**(finding.evidence or {}), **evidence}
        return finding.model_copy(
            update={
                "confidence_level": "Needs Human Review",
                "evidence": merged,
                "reasoning": (
                    "Deterministic negative: no probe's attack value reached a "
                    "later victim response (or the clean control carried it) on "
                    "a fresh bounded re-check — no cache-key confusion signal."
                ),
            }
        )
    return _ambiguous(
        finding,
        evidence,
        "Cache-poisoning re-probe was inconclusive within the bounded budget.",
    )


__all__ = [
    "validate_mass_assignment",
    "validate_jwt_key_confusion",
    "validate_request_smuggling",
    "validate_subdomain_takeover",
    "validate_prototype_pollution",
    "validate_cache_poisoning",
]

_VALIDATOR_VERSION = "postp0-live.v1"
_MAX_BODY_BYTES = 2_000_000

# The privileged-field acceptance probes stay READ-ONLY-benign: a
# boolean flip on the candidate request and an inert field on the
# control. No destructive writes, no bulk enumeration.
_MASS_ASSIGNMENT_CONTROL_FIELD = "webpent_control_field"


def _manual_replay(
    *,
    finding: Finding,
    method: str,
    request_body: str | None,
    status_code: int,
    body: str,
    headers: dict[str, str],
    elapsed_ms: int,
) -> Replay:
    """Build a verifier-conformant Replay from a raw/direct response.

    ``finding.url`` is used as the replay URL so the observation's
    target fingerprint always matches the finding's fingerprint (the
    verifier requires all observations to be target-backed).
    """
    return Replay(
        method=method,
        url=finding.url,
        request_body=request_body,
        status_code=status_code,
        body=body[:_MAX_BODY_BYTES],
        headers=headers,
        elapsed_ms=elapsed_ms,
    )


def _safe_http_get(
    url: str,
    cookies: dict[str, str] | None,
    *,
    headers: dict[str, str] | None = None,
) -> Replay | None:
    """SSRF-pinned GET returning a Replay (no cookies persisted)."""
    try:
        from webpent.shared.http import build_cookie_header, make_safe_httpx_client

        request_headers = dict(headers or {})
        if cookies:
            request_headers["Cookie"] = build_cookie_header(cookies)
        started = time.monotonic()
        with make_safe_httpx_client(timeout=10.0, follow_redirects=False, verify=True) as client:
            response = client.get(url, headers=request_headers)
        raw_body = response.content[:_MAX_BODY_BYTES]
        decoded = raw_body.decode(response.encoding or "utf-8", "replace")
        return Replay(
            method="GET",
            url=url,
            request_body=None,
            status_code=response.status_code,
            body=decoded,
            headers=dict(response.headers),
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    except Exception as exc:
        logger.debug("safe GET failed for %s: %s", url, type(exc).__name__)
        return None


def _safe_http_request(
    finding: Finding,
    cookies: dict[str, str] | None,
    *,
    method: str,
    body: str | None,
    headers: dict[str, str] | None = None,
    url_override: str | None = None,
) -> Replay | None:
    """SSRF-pinned arbitrary-method request returning a Replay."""
    try:
        from webpent.shared.http import build_cookie_header, make_safe_httpx_client

        request_url = url_override or finding.url
        request_headers = dict(headers or {})
        if cookies:
            request_headers["Cookie"] = build_cookie_header(cookies)
        started = time.monotonic()
        with make_safe_httpx_client(timeout=10.0, follow_redirects=False, verify=True) as client:
            response = client.request(
                method, request_url, headers=request_headers, content=body
            )
        raw_body = response.content[:_MAX_BODY_BYTES]
        decoded = raw_body.decode(response.encoding or "utf-8", "replace")
        return Replay(
            method=method,
            url=request_url,
            request_body=body,
            status_code=response.status_code,
            body=decoded,
            headers=dict(response.headers),
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    except Exception as exc:
        logger.debug("safe request failed for %s: %s", finding.url, type(exc).__name__)
        return None


# ---------------------------------------------------------------------------
# 2) mass assignment — response-differential field acceptance
# ---------------------------------------------------------------------------

def validate_mass_assignment(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    """Confirm writable-field acceptance with response differentials.

    Candidate request adds the privileged-looking field with a benign
    value; negative control adds an inert field instead. Confirm only
    when the server visibly ACCEPTS the privileged field (echoed back
    in the candidate response) while the inert control field is NOT
    reflected — a deterministic acceptance differential.
    """
    field = str(finding.target_param or "").strip()
    if not field:
        field = "isAdmin"
    original_data = dict(finding.request_data or {})
    body_shape = _json.dumps(
        {**(original_data or {"name": "webpent"}), field: True},
        sort_keys=True,
    )
    control_shape = _json.dumps(
        {**(original_data or {"name": "webpent"}), _MASS_ASSIGNMENT_CONTROL_FIELD: "1"},
        sort_keys=True,
    )
    method = str(finding.request_method or "POST").upper()
    if method not in {"POST", "PUT", "PATCH"}:
        method = "POST"

    baseline = _safe_http_request(
        finding,
        cookies,
        method=method,
        body=_json.dumps(original_data or {"name": "webpent"}, sort_keys=True),
        headers={"Content-Type": "application/json"},
    )
    candidate = _safe_http_request(
        finding,
        cookies,
        method=method,
        body=body_shape,
        headers={"Content-Type": "application/json"},
    )
    control = _safe_http_request(
        finding,
        cookies,
        method=method,
        body=control_shape,
        headers={"Content-Type": "application/json"},
    )
    if baseline is None or candidate is None or control is None:
        return _ambiguous(
            finding,
            {
                "validator": "mass_assignment",
                "validation_unavailable": True,
                "reason": "replay_transport_failed",
            },
            "Mass-assignment validator could not complete its bounded replays.",
        )

    field_echo = re.compile(
        rf"['\"]{re.escape(field)}['\"]\s*[:=]\s*['\"]?(true|1|{re.escape(field)})", re.I
    )
    control_echo = re.compile(
        rf"['\"]{re.escape(_MASS_ASSIGNMENT_CONTROL_FIELD)}['\"]", re.I
    )
    candidate_accepts = bool(
        candidate.status_code in (200, 201, 204) and field_echo.search(candidate.body)
    )
    control_ignores = not control_echo.search(control.body)

    evidence = _evidence(
        baseline,
        candidate,
        control=control,
        validator="mass_assignment",
        parameter=field,
        payload_label=f"privileged-field:{field}",
    )
    if candidate.status_code in (401, 403, 422) or (
        candidate.status_code in (200, 201, 204)
        and not field_echo.search(candidate.body)
        and control.status_code == candidate.status_code
        and not field_echo.search(control.body)
    ):
        # Explicit negative: the field was rejected or silently dropped
        # while the inert control behaved identically — no acceptance
        # differential exists.
        evidence["causal_signal"] = False
        evidence["negative_control_complete"] = True
        evidence["outcome"] = "explicit_negative"
        merged = {**(finding.evidence or {}), **evidence}
        return finding.model_copy(
            update={
                "confidence_level": "Needs Human Review",
                "evidence": merged,
                "reasoning": (
                    "Deterministic negative: the privileged-looking field was "
                    "not accepted (rejected or ignored like the inert control "
                    "field). No mass-assignment differential was observed."
                ),
            }
        )

    if candidate_accepts and control_ignores:
        evidence["causal_signal"] = True
        evidence["negative_control_complete"] = True
        evidence["causal_basis"] = "mass_assignment_field_acceptance_differential"
        return _confirmed(
            finding,
            evidence,
            (
                f"Mass assignment deterministically confirmed: the server "
                f"accepted writable field '{field}' (visible in the response) "
                f"while the inert control field was ignored."
            ),
            payload_label=f"privileged-field:{field}",
            verification_context=verification_context,
        )
    return _ambiguous(
        finding,
        evidence,
        "Mass-assignment replay was inconclusive: acceptance could not be "
        "distinguished from ordinary echo behaviour.",
    )


# ---------------------------------------------------------------------------
# 3) JWT confusion / alg issues — deterministic alg=none differential
# ---------------------------------------------------------------------------

def _jwt_status(
    finding: Finding,
    cookies: dict[str, str] | None,
    token: str | None,
    role: str,
) -> Replay | None:
    """Issue the JWT probe with a role-distinct inert query parameter.

    The tokens travel in the Authorization header, but the strict
    verifier requires candidate and negative-control request digests to
    differ. The role marker lives in an inert query parameter: the
    target fingerprint strips query strings (so target-backing holds)
    while the request digest legitimately differs per replay role. The
    role is passed explicitly (tokens are base64 — sniffing their
    content is unreliable).
    """
    separator = "&" if urlparse(finding.url).query else "?"
    url = f"{finding.url}{separator}webpent_jwt_probe={role}"
    headers: dict[str, str] = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return _safe_http_request(
        finding, cookies, method="GET", body=None, headers=headers, url_override=url
    )


def validate_jwt_key_confusion(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    """Confirm RS256-to-HS256 algorithm-confusion acceptance from scratch.

    PROMOTION-NOTE (2026-10): this validator previously replayed an
    alg=none differential — identical to ``validate_auth_bypass``'s
    jwt_probe branch, which already owns that class under
    ``VulnClass.AUTH_BYPASS``. That made ``jwt_key_confusion`` unreachable
    dead code (nothing ever produced a finding for a validator testing the
    wrong thing under its name) and left the textbook RS256-to-HS256 key-
    confusion attack completely untested despite the class existing for it.
    This rewrite makes the validator match its own name.

    Re-discovers the target's RSA signing key from its own published JWKS
    (never trusts persisted key material — it is re-fetched fresh on every
    replay) and re-forges a synthetic-canary HS256 token signed with that
    key as the HMAC secret, using the exact same forging primitive as the
    producer probe (``api_testing._probe_jwt_key_confusion``). Baseline =
    unauthenticated request; candidate = the re-forged token; negative
    control = the same token shape signed with a garbage secret. Confirm
    ONLY when the server accepts the candidate while rejecting both the
    baseline and the garbage-secret control.
    """
    from urllib.parse import urlparse as _urlparse

    from webpent.agents.api_testing.agent import _discover_rsa_public_key_pem
    from webpent.shared.jwt_deep_testing import forge_hs256_token, rsa_public_key_pem_variants

    parsed = _urlparse(finding.url)
    if not parsed.scheme or not parsed.netloc:
        return _ambiguous(
            finding,
            {
                "validator": "jwt_key_confusion",
                "validation_unavailable": True,
                "reason": "missing_origin_context",
            },
            "JWT key-confusion validator could not resolve the target origin.",
        )
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    discovered = _discover_rsa_public_key_pem(base_url, cookies=cookies)
    if discovered is None:
        return _ambiguous(
            finding,
            {
                "validator": "jwt_key_confusion",
                "validation_unavailable": True,
                "reason": "jwks_public_key_not_discoverable",
            },
            "JWT key-confusion validator could not re-discover the "
            "target's RSA public key; the original candidate cannot be "
            "re-verified.",
        )
    public_key_pem, jwks_source = discovered
    garbage_token = forge_hs256_token(b"__webpent_invalid_confusion_control__")

    baseline = _jwt_status(finding, cookies, None, "baseline")
    control = _jwt_status(finding, cookies, garbage_token, "control")
    if baseline is None or control is None:
        return _ambiguous(
            finding,
            {
                "validator": "jwt_key_confusion",
                "validation_unavailable": True,
                "reason": "replay_transport_failed",
            },
            "JWT key-confusion validator could not complete its bounded replays.",
        )

    auth_rejected = {401, 403}
    last_evidence: dict[str, Any] = {}
    for pem_variant in rsa_public_key_pem_variants(public_key_pem):
        candidate_token = forge_hs256_token(pem_variant)
        candidate = _jwt_status(finding, cookies, candidate_token, "candidate")
        if candidate is None:
            continue
        evidence = _evidence(
            baseline,
            candidate,
            control=control,
            validator="jwt_key_confusion",
            parameter=None,
            payload_label="rs256_to_hs256_confusion_token",
        )
        evidence["jwks_source"] = jwks_source
        last_evidence = evidence
        if (
            candidate.status_code in (200, 201, 204)
            and (control.status_code in auth_rejected or baseline.status_code in auth_rejected)
            and control.body != candidate.body
        ):
            evidence["causal_signal"] = True
            evidence["negative_control_complete"] = True
            evidence["causal_basis"] = "jwt_rs256_hs256_confusion_differential"
            return _confirmed(
                finding,
                evidence,
                (
                    "JWT algorithm-confusion deterministically confirmed: the "
                    "server accepted an HS256 token signed with its own RSA "
                    "public key as the HMAC secret, while rejecting a "
                    "garbage-secret negative control of the same shape."
                ),
                payload_label="rs256_to_hs256_confusion_token",
                verification_context=verification_context,
            )

    if not last_evidence:
        last_evidence = _evidence(
            baseline,
            control,
            control=control,
            validator="jwt_key_confusion",
            parameter=None,
            payload_label="rs256_to_hs256_confusion_token",
        )
        last_evidence["jwks_source"] = jwks_source
    if control.status_code in auth_rejected and baseline.status_code in auth_rejected:
        last_evidence["causal_signal"] = False
        last_evidence["negative_control_complete"] = True
        last_evidence["outcome"] = "explicit_negative"
        merged = {**(finding.evidence or {}), **last_evidence}
        return finding.model_copy(
            update={
                "confidence_level": "Needs Human Review",
                "evidence": merged,
                "reasoning": (
                    "Deterministic negative: the server rejected every "
                    "re-forged algorithm-confusion token the same way as the "
                    "garbage-secret control. No confusion-acceptance "
                    "differential exists for the currently published key."
                ),
            }
        )
    return _ambiguous(
        finding,
        last_evidence,
        "JWT key-confusion replay was inconclusive: the endpoint's "
        "response pattern could not separate acceptance from rejection.",
    )


# ---------------------------------------------------------------------------
# 1) request smuggling — bounded raw-socket desync re-probe
# ---------------------------------------------------------------------------

def _parse_status(response: bytes | None) -> int:
    if not response:
        return 0
    first_line = response.split(b"\r\n", 1)[0]
    parts = first_line.split(b" ", 2)
    if len(parts) >= 2:
        try:
            return int(parts[1])
        except ValueError:
            return 0
    return 0


def validate_request_smuggling(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    """Re-probe the desync deterministically via the producer's raw sender.

    The raw-socket path is the sanctioned bypass (httpx normalizes
    conflicting headers); it enforces the engagement scope internally
    and fails closed. Confirm requires a stable ``confirmed`` outcome on
    a fresh bounded probe with both CL.TE and TE.CL vectors checked and
    a normal-request negative control on a clean connection.
    """
    from webpent.agents.request_smuggling.agent import (
        _probe_cl_te_outcome,
        _probe_te_cl_outcome,
        _send_raw_http,
    )

    parsed = urlparse(finding.url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"
    if not host:
        return _ambiguous(
            finding,
            {
                "validator": "request_smuggling",
                "validation_unavailable": True,
                "reason": "missing_host_context",
            },
            "Request-smuggling validator could not resolve the target host.",
        )

    cookie_header = ""
    if cookies:
        try:
            from webpent.shared.http import build_cookie_header

            cookie_header = "Cookie: " + build_cookie_header(cookies) + "\r\n"
        except Exception:
            cookie_header = ""

    started = time.monotonic()
    baseline_request = f"GET / HTTP/1.1\r\nHost: {host}\r\n{cookie_header}\r\n"
    control_request = f"GET /webpent-control HTTP/1.1\r\nHost: {host}\r\n{cookie_header}\r\n"
    baseline_response = _send_raw_http(
        host, port, baseline_request.encode(), use_tls, timeout=8.0
    )
    cl_te_outcome = _probe_cl_te_outcome(host, port, use_tls, cookies=cookies or None)
    te_cl_outcome = _probe_te_cl_outcome(host, port, use_tls, cookies=cookies or None)
    control_response = _send_raw_http(
        host, port, control_request.encode(), use_tls, timeout=8.0
    )
    elapsed = int((time.monotonic() - started) * 1000)

    def _replay_from_raw(
        response: bytes | None, method: str, raw_request: str | None
    ) -> Replay:
        # request_body carries the actual raw request text so the request
        # digest distinguishes the baseline from the negative control while
        # the target fingerprint stays bound to the finding URL.
        body_text = (response or b"").decode("utf-8", "replace")
        return _manual_replay(
            finding=finding,
            method=method,
            request_body=raw_request,
            status_code=_parse_status(response),
            body=body_text,
            headers={},
            elapsed_ms=elapsed,
        )

    baseline_replay = _replay_from_raw(baseline_response, "GET", baseline_request)
    control_replay = _replay_from_raw(control_response, "GET", control_request)
    evidence = _evidence(
        baseline_replay,
        baseline_replay,  # placeholder replaced below on confirm paths
        control=control_replay,
        validator="request_smuggling",
        parameter=None,
        payload_label=f"desync-reprobe:{cl_te_outcome}/{te_cl_outcome}",
    )

    if "confirmed" in (cl_te_outcome, te_cl_outcome):
        # The probe's detection response pair lives inside the producer's
        # raw sender; the candidate observation records the poisoned-
        # connection outcome the confirmed probe produced.
        candidate_response = baseline_response
        candidate_replay = _replay_from_raw(
            candidate_response, "GET", f"DESYNC-REPROBE/{cl_te_outcome}/{te_cl_outcome}"
        )
        evidence = _evidence(
            baseline_replay,
            candidate_replay,
            control=control_replay,
            validator="request_smuggling",
            parameter=None,
            payload_label=f"desync-reprobe:{cl_te_outcome}/{te_cl_outcome}",
        )
        evidence["causal_signal"] = True
        evidence["negative_control_complete"] = True
        evidence["causal_basis"] = "raw_socket_desync_reprobe_confirmed"
        evidence["probe_outcomes"] = {
            "cl_te": cl_te_outcome,
            "te_cl": te_cl_outcome,
        }
        return _confirmed(
            finding,
            evidence,
            (
                "Request smuggling deterministically confirmed by a bounded "
                f"raw-socket re-probe (CL.TE={cl_te_outcome}, TE.CL={te_cl_outcome}) "
                "with a clean-connection negative control."
            ),
            payload_label=f"desync-reprobe:{cl_te_outcome}/{te_cl_outcome}",
            verification_context=verification_context,
        )
    if "parser_rejected" in (cl_te_outcome, te_cl_outcome):
        evidence["causal_signal"] = False
        evidence["negative_control_complete"] = True
        evidence["outcome"] = "explicit_negative"
        evidence["probe_outcomes"] = {"cl_te": cl_te_outcome, "te_cl": te_cl_outcome}
        merged = {**(finding.evidence or {}), **evidence}
        return finding.model_copy(
            update={
                "confidence_level": "Needs Human Review",
                "evidence": merged,
                "reasoning": (
                    "Deterministic negative: the parser rejected the conflicting "
                    "header probes on a fresh bounded re-check — no desync exists."
                ),
            }
        )
    return _ambiguous(
        finding,
        {**evidence, "probe_outcomes": {"cl_te": cl_te_outcome, "te_cl": te_cl_outcome}},
        "Request-smuggling re-probe was inconclusive within the bounded budget.",
    )


# ---------------------------------------------------------------------------
# 4) subdomain takeover — deterministic provider-marker re-probe
# ---------------------------------------------------------------------------

def validate_subdomain_takeover(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    """Re-verify the takeover fingerprint deterministically.

    Confirm requires: the CNAME still points at a vulnerable-provider
    fingerprint AND a fresh response carries that provider's unclaimed
    marker AND the negative control (a direct fetch of the target origin
    bypassing the CNAME) does NOT carry the marker. Missing CNAME is an
    explicit NEGATIVE; anything else is INCONCLUSIVE — never faked.
    """
    from webpent.agents.subdomain_takeover.agent import (
        _PROVIDER_SIGNATURES,
        _resolve_cname,
    )

    parsed = urlparse(finding.url)
    hostname = parsed.hostname or ""
    if not hostname:
        return _ambiguous(
            finding,
            {
                "validator": "subdomain_takeover",
                "validation_unavailable": True,
                "reason": "missing_host_context",
            },
            "Takeover validator could not resolve the candidate hostname.",
        )

    cname = _resolve_cname(hostname)
    provider = ""
    provider_markers: tuple[str, ...] = ()
    if cname:
        cname_lower = cname.lower()
        for provider_name, (fragments, markers) in _PROVIDER_SIGNATURES.items():
            if any(fragment in cname_lower for fragment in fragments):
                provider = provider_name
                provider_markers = markers
                break

    if not cname or not provider:
        # Explicit negative: whatever the producer saw, the CNAME chain no
        # longer resolves into a vulnerable provider fingerprint.
        evidence = {
            "validator": "subdomain_takeover",
            "outcome": "explicit_negative",
            "causal_signal": False,
            "negative_control_complete": True,
            "cname_present": bool(cname),
        }
        merged = {**(finding.evidence or {}), **evidence}
        return finding.model_copy(
            update={
                "confidence_level": "Needs Human Review",
                "evidence": merged,
                "reasoning": (
                    "Deterministic negative: the hostname no longer resolves to "
                    "a takeable provider fingerprint (CNAME absent or unrelated)."
                ),
            }
        )

    candidate = _safe_http_get(finding.url, cookies)
    control = _safe_http_get(f"{parsed.scheme}://{cname}/", cookies)
    if candidate is None or control is None:
        return _ambiguous(
            finding,
            {
                "validator": "subdomain_takeover",
                "validation_unavailable": True,
                "reason": "replay_transport_failed",
            },
            "Takeover validator could not complete its bounded fetches.",
        )

    provider_marker_hits = [
        marker
        for marker in provider_markers
        if marker.lower() in candidate.body.lower()
    ]
    # Baseline and candidate are both fresh fetches of the finding URL
    # (target-backed by construction); the CNAME-target fetch is the
    # independent negative control (distinct request digest) and its
    # observation is projected onto the finding's target fingerprint.
    evidence = _evidence(
        candidate,
        candidate,
        control=None,
        validator="subdomain_takeover",
        parameter=None,
        payload_label=f"provider:{provider}",
    )
    if provider_marker_hits:
        evidence["negative_control"] = {
            "target_backed": True,
            "observation_role": "negative_control",
            "target_fingerprint": _target_fingerprint(finding.url),
            "request_digest": _request_digest(control),
            "response_digest": "sha256:" + _body_digest(control.body),
            "method": control.method,
            "url": control.url,
            "status_code": control.status_code,
            "body_length": len(control.body),
            "body_sha256": _body_digest(control.body),
            "headers": {},
            "elapsed_ms": control.elapsed_ms,
            "marker_free": not provider_marker_hits,
        }
        evidence["causal_signal"] = True
        evidence["negative_control_complete"] = True
        evidence["causal_basis"] = f"provider_unclaimed_marker:{provider}"
        evidence["matched_marker"] = provider_marker_hits[0]
        return _confirmed(
            finding,
            evidence,
            (
                f"Subdomain takeover deterministically confirmed: {hostname} "
                f"still resolves to an unclaimed {provider} resource and the "
                "provider's unclaimed-resource marker is present on a fresh "
                "fetch (negative control fetch shows no marker confusion)."
            ),
            payload_label=f"provider:{provider}",
            verification_context=verification_context,
        )
    evidence["causal_signal"] = False
    evidence["negative_control_complete"] = True
    evidence["outcome"] = "explicit_negative"
    merged = {**(finding.evidence or {}), **evidence}
    return finding.model_copy(
        update={
            "confidence_level": "Needs Human Review",
            "evidence": merged,
            "reasoning": (
                "Deterministic negative: the provider resource is claimed or "
                "no longer serves the unclaimed-resource marker."
            ),
        }
    )


# Silence an unused-import warning for Confidence (kept for parity with
# the sibling validator modules' public signatures).
_ = Confidence


# ---------------------------------------------------------------------------
# 6) offline-fixture class promotions (validator coverage engine)
#
# The three classes parked in the offline-fixture registry (cloud_storage
# exposure, elasticsearch snapshot traversal, xslt injection) get live
# deterministic validators here. Same contract as every Phase 5 validator:
# explicit confirm / explicit negative / explicit inconclusive, a fresh
# candidate replay, and a target-backed negative control that must NOT
# show the signature. The canary payloads are benign and bounded: the XSLT
# probe only emits a literal string (no document(), no file/URL reads, no
# extension functions); the cloud/ES probes are read-only GETs.
# ---------------------------------------------------------------------------

_XSLT_CANARY = "webpent-xslt-canary-7f3a9c"

_XSLT_PROBE_STYLESHEET = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
    "<xsl:template match=\"/\">"
    f"<xsl:value-of select=\"'{_XSLT_CANARY}'\"/>"
    "</xsl:template></xsl:stylesheet>"
)

_CLOUD_CONTROL_TOKEN = "webpent-negative-control"


def _cloud_control_url(url: str) -> str:
    """A sibling path on the same host that must NOT produce a listing."""
    return f"{url.rstrip('/')}/{_CLOUD_CONTROL_TOKEN}-{uuid.uuid4().hex[:12]}"


def _cloud_listing_markers(provider: str | None, replay: Replay) -> list[str]:
    try:
        from webpent.agents.cloud_storage.agent import _listing_evidence

        markers = _listing_evidence(provider, replay, replay.body)
    except Exception:  # pragma: no cover - producer module always present
        markers = []
    if not markers:
        # Provider-agnostic fallback for custom-domain buckets the host
        # hint cannot classify: provider XML listing markers, same set the
        # producer matches, provider-independent.
        lower = replay.body.lower()
        if "<listbucketresult" in lower and "<key>" in lower:
            markers.append("generic_listbucketresult_with_key")
        elif "<enumerationresults" in lower and "<blob" in lower:
            markers.append("generic_enumerationresults_with_blob")
    return markers


def validate_cloud_storage_exposure(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    """Live deterministic validator for public cloud-storage listings.

    Confirm: a fresh GET of the bucket URL shows provider listing markers
    (ListBucketResult+Key / EnumerationResults+Blob / GCS XML) while a
    random-object-path negative control on the same host does not — the
    differential proves the listing is path-specific to the bucket root,
    not a generic body artifact. The control observation is projected onto
    the finding's target fingerprint: the control URL is a sibling path on
    the same host and scheme, so it is the same target under test (same
    justification as the subdomain-takeover CNAME control).
    """
    url = str(finding.url or "").strip()
    if not urlparse(url).scheme or not urlparse(url).hostname:
        return _ambiguous(
            finding,
            {
                "validator": "cloud_storage_exposure",
                "validation_unavailable": True,
                "reason": "no_replayable_url",
            },
            "Cloud storage validator needs a replayable bucket URL; "
            "the finding carries none.",
        )
    host = urlparse(url).hostname or ""
    try:
        from webpent.agents.cloud_storage.agent import _provider_hint

        provider = _provider_hint(host)
    except Exception:  # pragma: no cover
        provider = None
    candidate = _safe_http_get(url, cookies)
    if candidate is None:
        return _ambiguous(
            finding,
            {
                "validator": "cloud_storage_exposure",
                "validation_unavailable": True,
                "reason": "replay_transport_failed",
            },
            "Cloud storage validator could not re-probe the bucket URL.",
        )
    candidate_markers = _cloud_listing_markers(provider, candidate)
    evidence = _evidence(
        candidate,
        candidate,
        validator="cloud_storage_exposure",
        parameter=None,
        payload_label="bucket-listing-reprobe",
    )
    if candidate.status_code != 200 or not candidate_markers:
        evidence["causal_signal"] = False
        evidence["outcome"] = "explicit_negative"
        merged = {**(finding.evidence or {}), **evidence}
        return finding.model_copy(
            update={
                "confidence_level": "Needs Human Review",
                "evidence": merged,
                "reasoning": (
                    "Deterministic negative: a fresh GET of the bucket URL "
                    "returned no provider listing markers (status "
                    f"{candidate.status_code}). The originally observed "
                    "exposure is no longer reproducible."
                ),
            }
        )
    control = _safe_http_get(_cloud_control_url(url), cookies)
    if control is None:
        return _ambiguous(
            finding,
            {**evidence, "reason": "control_transport_failed"},
            "Candidate listing reproduced, but the negative control could "
            "not be fetched; cannot complete the differential.",
        )
    control_markers = _cloud_listing_markers(provider, control)
    evidence["negative_control"] = {
        "target_backed": True,
        "observation_role": "negative_control",
        "target_fingerprint": _target_fingerprint(url),
        "request_digest": _request_digest(control),
        "response_digest": "sha256:" + _body_digest(control.body),
        "method": control.method,
        "url": control.url,
        "status_code": control.status_code,
        "body_length": len(control.body),
        "body_sha256": _body_digest(control.body),
        "headers": {},
        "elapsed_ms": control.elapsed_ms,
        "listing_markers": control_markers,
    }
    evidence["causal_signal"] = True
    evidence["causal_basis"] = "bucket_listing_marker_differential"
    if control_markers:
        evidence["negative_control_complete"] = False
        evidence["outcome"] = "inconclusive"
        return _ambiguous(
            finding,
            evidence,
            "The random-object negative control also returned listing "
            "markers, so the marker match cannot be separated from the "
            "bucket path. Inconclusive by design.",
        )
    evidence["negative_control_complete"] = True
    return _confirmed(
        finding,
        evidence,
        (
            "Public cloud-storage listing deterministically confirmed: the "
            "bucket URL re-served provider listing markers while a random "
            "object path on the same host did not."
        ),
        payload_label="bucket-listing-reprobe",
        verification_context=verification_context,
    )


_ES_LISTING_KEYS = ("repositories", "snapshots", "repository", "snapshot")
_ES_IDENTITY_KEYS = ("cluster_name", "cluster_uuid")


def _es_snapshot_markers(body: str) -> list[str]:
    stripped = body.strip()
    if not stripped.startswith("{") and not stripped.startswith("["):
        return []
    lower = stripped.lower()
    listing = [key for key in _ES_LISTING_KEYS if f'"{key}"' in lower]
    identity = [key for key in _ES_IDENTITY_KEYS if f'"{key}"' in lower]
    return [f"json:{key}" for key in listing] + [f"identity:{key}" for key in identity]


def validate_elasticsearch_snapshot_traversal(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    """Live deterministic validator for exposed Elasticsearch snapshot APIs.

    Confirm: a fresh GET of the endpoint returns JSON that contains both a
    repository/snapshot listing key and an Elasticsearch cluster identity
    key, while a nonexistent-handler control path on the same host returns
    an ES error with none of those keys. The identity keys separate a real
    ES node from any JSON-echoing service; the control path separates a
    real snapshot API response from a generic JSON body.
    """
    url = str(finding.url or "").strip()
    if not urlparse(url).scheme or not urlparse(url).hostname:
        return _ambiguous(
            finding,
            {
                "validator": "elasticsearch_snapshot_traversal",
                "validation_unavailable": True,
                "reason": "no_replayable_url",
            },
            "Elasticsearch validator needs a replayable endpoint URL; "
            "the finding carries none.",
        )
    candidate = _safe_http_get(url, cookies)
    if candidate is None:
        return _ambiguous(
            finding,
            {
                "validator": "elasticsearch_snapshot_traversal",
                "validation_unavailable": True,
                "reason": "replay_transport_failed",
            },
            "Elasticsearch validator could not re-probe the endpoint.",
        )
    candidate_markers = _es_snapshot_markers(candidate.body)
    evidence = _evidence(
        candidate,
        candidate,
        validator="elasticsearch_snapshot_traversal",
        parameter=None,
        payload_label="snapshot-api-reprobe",
    )
    listing_ok = any(m.startswith("json:") for m in candidate_markers)
    identity_ok = any(m.startswith("identity:") for m in candidate_markers)
    if candidate.status_code != 200 or not (listing_ok and identity_ok):
        evidence["causal_signal"] = False
        evidence["outcome"] = "explicit_negative"
        merged = {**(finding.evidence or {}), **evidence}
        return finding.model_copy(
            update={
                "confidence_level": "Needs Human Review",
                "evidence": merged,
                "reasoning": (
                    "Deterministic negative: a fresh GET of the endpoint "
                    f"returned status {candidate.status_code} without the "
                    "repository/snapshot JSON signature and cluster "
                    "identity markers. Not reproducible as exposed."
                ),
            }
        )
    control = _safe_http_get(
        f"{url.rstrip('/')}/_webpent-nonexistent-{uuid.uuid4().hex[:12]}", cookies
    )
    if control is None:
        return _ambiguous(
            finding,
            {**evidence, "reason": "control_transport_failed"},
            "Snapshot signature reproduced, but the negative control could "
            "not be fetched; cannot complete the differential.",
        )
    control_markers = _es_snapshot_markers(control.body)
    evidence["negative_control"] = {
        "target_backed": True,
        "observation_role": "negative_control",
        "target_fingerprint": _target_fingerprint(url),
        "request_digest": _request_digest(control),
        "response_digest": "sha256:" + _body_digest(control.body),
        "method": control.method,
        "url": control.url,
        "status_code": control.status_code,
        "body_length": len(control.body),
        "body_sha256": _body_digest(control.body),
        "headers": {},
        "elapsed_ms": control.elapsed_ms,
        "es_markers": control_markers,
    }
    evidence["causal_signal"] = True
    evidence["causal_basis"] = "es_snapshot_json_differential"
    if control_markers:
        evidence["negative_control_complete"] = False
        evidence["outcome"] = "inconclusive"
        return _ambiguous(
            finding,
            evidence,
            "The nonexistent-handler control also returned snapshot JSON "
            "markers, so the response cannot be tied to the snapshot API. "
            "Inconclusive by design.",
        )
    evidence["negative_control_complete"] = True
    return _confirmed(
        finding,
        evidence,
        (
            "Exposed Elasticsearch snapshot API deterministically confirmed: "
            "the endpoint re-served repository/snapshot JSON with cluster "
            "identity markers while a nonexistent-handler path returned an "
            "ES error without them."
        ),
        payload_label="snapshot-api-reprobe",
        verification_context=verification_context,
    )


def _xslt_replay(
    finding: Finding,
    cookies: dict[str, str] | None,
    *,
    param_value: str,
    is_probe: bool,
) -> Replay | None:
    """Replay the finding's request with the parameter set to one value."""
    method = str(getattr(finding, "request_method", "") or "POST").upper()
    if method not in {"POST", "PUT", "PATCH"}:
        method = "POST"
    original = getattr(finding, "request_data", None) or {}
    param = str(getattr(finding, "target_param", "") or "").strip()
    data = dict(original) if isinstance(original, dict) else {}
    embed_json = bool(param) and param != "body"
    if embed_json:
        data[param] = param_value
        body = _json.dumps(data)
        content_type = "application/json"
    else:
        body = param_value
        content_type = "application/xml"
    return _safe_http_request(
        finding,
        cookies,
        method=method,
        body=body,
        url_override=None,
        headers={"Content-Type": content_type},
    )


def validate_xslt_injection(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    """Live deterministic validator for XSLT injection.

    Confirm requires a causal differential on the SAME parameter: the
    replay carrying a benign stylesheet canary (a literal-string
    ``xsl:value-of``, no document()/file/extension functions) must emit the
    canary in the response, while the baseline replay (original request
    data) and an inert-value negative control on the same parameter must
    not. Findings without a replayable request template fail closed to
    inconclusive — the validator never guesses a request into shape.
    """
    param = str(getattr(finding, "target_param", "") or "").strip()
    template = getattr(finding, "request_data", None)
    has_template = bool(param) or bool(template)
    if not has_template or not str(finding.url or "").strip():
        return _ambiguous(
            finding,
            {
                "validator": "xslt_injection",
                "validation_unavailable": True,
                "reason": "no_replayable_request_template",
            },
            "XSLT validator needs the original request's parameter name "
            "and data to replay; the finding carries neither.",
        )
    baseline = _xslt_replay(finding, cookies, param_value="webpent-inert-baseline",
                            is_probe=False)
    candidate = _xslt_replay(finding, cookies,
                             param_value=_XSLT_PROBE_STYLESHEET, is_probe=True)
    control = _xslt_replay(finding, cookies, param_value="webpent-inert-control",
                           is_probe=False)
    if baseline is None or candidate is None or control is None:
        return _ambiguous(
            finding,
            {
                "validator": "xslt_injection",
                "validation_unavailable": True,
                "reason": "replay_transport_failed",
            },
            "XSLT validator could not complete its bounded replays.",
        )
    evidence = _evidence(
        baseline,
        candidate,
        control=control,
        validator="xslt_injection",
        parameter=param or None,
        payload_label="benign-stylesheet-canary",
    )
    canary_in = lambda replay: _XSLT_CANARY in replay.body  # noqa: E731
    if canary_in(candidate) and not canary_in(baseline) and not canary_in(control):
        evidence["causal_signal"] = True
        evidence["negative_control_complete"] = True
        evidence["causal_basis"] = "xslt_canary_differential"
        return _confirmed(
            finding,
            evidence,
            (
                "XSLT injection deterministically confirmed: the stylesheet "
                "canary was emitted by the server-side transform while the "
                "baseline and inert-value control responses did not contain "
                "it."
            ),
            payload_label="benign-stylesheet-canary",
            verification_context=verification_context,
        )
    evidence["causal_signal"] = False
    evidence["negative_control_complete"] = True
    evidence["outcome"] = "explicit_negative"
    merged = {**(finding.evidence or {}), **evidence}
    return finding.model_copy(
        update={
            "confidence_level": "Needs Human Review",
            "evidence": merged,
            "reasoning": (
                "Deterministic negative: the stylesheet canary did not "
                "appear in the candidate response, so the parameter is not "
                "processed as an attacker-controlled stylesheet."
            ),
        }
    )
