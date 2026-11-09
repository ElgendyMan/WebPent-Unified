"""Target-local safety primitives for the approved Option B causal lab.

This module is deliberately separate from the generic orchestrator.  It does
not authorize credentials, sessions, mutations, redirects, or external I/O.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from re import Pattern
from typing import Literal
from urllib.parse import parse_qs, unquote, urlsplit

PreconditionStatus = Literal["ready", "blocked"]


@dataclass(frozen=True)
class TargetEvidenceReadiness:
    """Fail-closed capabilities required before target evidence acquisition."""

    identity_model_available: bool
    ownership_model_available: bool
    reset_available: bool
    oracle_signal_available: bool
    observable_security_invariant: bool
    replayable_state_transition: bool

    def validate(self) -> tuple[str, ...]:
        checks = (
            ("identity_model_available", self.identity_model_available),
            ("ownership_model_available", self.ownership_model_available),
            ("reset_available", self.reset_available),
            ("oracle_signal_available", self.oracle_signal_available),
            ("observable_security_invariant", self.observable_security_invariant),
            ("replayable_state_transition", self.replayable_state_transition),
        )
        return tuple(name for name, available in checks if not available)

    @property
    def ready(self) -> bool:
        return not self.validate()


def validate_target_evidence_readiness(
    readiness: TargetEvidenceReadiness | Mapping[str, object],
) -> dict[str, object]:
    """Return a stable pre-request readiness decision for target evidence."""
    parsed = (
        readiness
        if isinstance(readiness, TargetEvidenceReadiness)
        else TargetEvidenceReadiness(**readiness)
    )
    missing = parsed.validate()
    return {
        "status": "ready" if parsed.ready else "blocked",
        "runnable": parsed.ready,
        "network_allowed": parsed.ready,
        "identity_model_available": parsed.identity_model_available,
        "ownership_model_available": parsed.ownership_model_available,
        "reset_available": parsed.reset_available,
        "oracle_signal_available": parsed.oracle_signal_available,
        "observable_security_invariant": parsed.observable_security_invariant,
        "replayable_state_transition": parsed.replayable_state_transition,
        "missing_capabilities": missing,
        "network_attempted": False,
    }


@dataclass(frozen=True)
class OptionBCase:
    case_id: str
    target_id: str
    origin: str
    route_pattern: Pattern[str]
    approved_methods: tuple[str, ...]
    approved_query_keys: tuple[str, ...]
    track: str
    requires_auth: bool
    requires_target_fixture_injection: bool
    precondition_status: PreconditionStatus
    precondition_reason: str
    baseline_role: str
    candidate_role: str
    negative_control_roles: tuple[str, ...]

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.case_id or not self.target_id or not self.origin:
            errors.append("case_identity_required")
        if self.approved_methods != ("GET",):
            errors.append("option_b_case_must_be_get_only")
        if any("token" in key.lower() for key in self.approved_query_keys):
            errors.append("query_allowlist_invalid")
        if self.requires_auth and self.precondition_status == "ready":
            errors.append("auth_case_cannot_be_ready_without_approved_session_fixture")
        if self.precondition_status == "ready" and not self.baseline_role:
            errors.append("ready_case_baseline_required")
        if not self.negative_control_roles:
            errors.append("independent_negative_control_required")
        if self.precondition_status == "blocked" and not self.precondition_reason:
            errors.append("blocked_case_reason_required")
        return tuple(errors)


@dataclass(frozen=True)
class RedactedObservation:
    """Only typed metadata may leave the bounded GET client."""

    status_family: str
    content_type_family: str
    length_bucket: str
    body_sha256: str | None
    canary_present: bool | None
    raw_body_retained: bool = False
    raw_headers_retained: bool = False
    cookies_retained: bool = False

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if self.raw_body_retained or self.raw_headers_retained or self.cookies_retained:
            errors.append("raw_response_material_must_not_be_retained")
        if self.body_sha256 is not None and len(self.body_sha256) != 64:
            errors.append("body_hash_must_be_sha256")
        return tuple(errors)


def validate_loopback_get(
    *,
    case: OptionBCase,
    method: str,
    url: str,
    expected_origin: str,
    followed_redirect: bool = False,
) -> tuple[str, ...]:
    """Validate a request before any socket operation occurs."""
    errors: list[str] = []
    if method.upper() != "GET":
        errors.append("method_not_approved_get_only")
    if expected_origin != case.origin:
        errors.append("expected_origin_case_mismatch")
    parsed = urlsplit(url)
    expected = urlsplit(expected_origin)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        errors.append("host_must_be_http_loopback_127001")
    if parsed.port != expected.port or parsed.scheme != expected.scheme:
        errors.append("origin_port_or_scheme_mismatch")
    if parsed.username or parsed.password or parsed.fragment:
        errors.append("userinfo_or_fragment_forbidden")
    if not case.route_pattern.fullmatch(parsed.path):
        errors.append("route_not_in_case_allowlist")
    query = parse_qs(parsed.query, keep_blank_values=True)
    if set(query) - set(case.approved_query_keys):
        errors.append("query_key_not_in_case_allowlist")
    decoded_query = unquote(parsed.query)
    if any(marker in decoded_query for marker in ("..", "/", "\\\\")):
        errors.append("traversal_marker_forbidden")
    if followed_redirect:
        errors.append("redirect_following_forbidden")
    return tuple(errors)


def redact_body(body: bytes, *, canary_digest: str | None = None) -> RedactedObservation:
    """Classify a bounded in-memory body and discard its raw bytes at return."""
    content_type_family = "unknown"
    length = len(body)
    if body.startswith(b"<"):
        content_type_family = "html_or_xml"
    elif body.startswith(b"{") or body.startswith(b"["):
        content_type_family = "json_like"
    elif body.startswith(b"\xff\xd8"):
        content_type_family = "image_jpeg"
    if length == 0:
        bucket = "zero"
    elif length <= 256:
        bucket = "small"
    elif length <= 4096:
        bucket = "medium"
    else:
        bucket = "large"
    digest = sha256(body).hexdigest()
    return RedactedObservation(
        status_family="unknown",
        content_type_family=content_type_family,
        length_bucket=bucket,
        body_sha256=digest,
        canary_present=(digest == canary_digest) if canary_digest else None,
    )


def blocked_precondition(case: OptionBCase) -> dict[str, object]:
    """Return a stable redacted precondition record without network I/O."""
    return {
        "status": "blocked",
        "approved_track": True,
        "runnable": False,
        "reason": case.precondition_reason,
        "requires_auth": case.requires_auth,
        "requires_target_fixture_injection": case.requires_target_fixture_injection,
        "network_attempted": False,
    }


def validate_option_b_preconditions(
    *,
    case: OptionBCase,
    method: str,
    url: str,
    expected_origin: str,
    readiness_status: str,
    fixture_snapshot_status: str,
    target_fixture_injected: bool = False,
    followed_redirect: bool = False,
    target_evidence_readiness: TargetEvidenceReadiness | Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Return a fail-closed preflight decision before any network operation."""
    errors = list(case.validate())
    errors.extend(
        validate_loopback_get(
            case=case,
            method=method,
            url=url,
            expected_origin=expected_origin,
            followed_redirect=followed_redirect,
        )
    )
    if case.precondition_status != "ready":
        errors.append("case_precondition_declared_blocked")
    if case.requires_auth:
        errors.append("approved_boundary_forbids_auth_session_material")
    if case.requires_target_fixture_injection and not target_fixture_injected:
        errors.append("target_fixture_injection_not_attested")
    if readiness_status != "ready":
        errors.append("lab_runtime_readiness_not_ready")
    if fixture_snapshot_status != "verified":
        errors.append("offline_fixture_snapshot_restore_not_verified")
    if not case.negative_control_roles:
        errors.append("independent_negative_control_required")
    if target_evidence_readiness is not None:
        readiness = validate_target_evidence_readiness(target_evidence_readiness)
        if readiness["status"] != "ready":
            errors.extend(
                f"target_evidence_{name}_unavailable"
                for name in readiness["missing_capabilities"]
            )
    unique_errors = tuple(dict.fromkeys(errors))
    return {
        "status": "ready" if not unique_errors else "blocked",
        "runnable": not unique_errors,
        "network_allowed": not unique_errors,
        "errors": unique_errors,
        "network_attempted": False,
    }
