"""Typed, fail-closed control-plane contracts for browser-assisted workflows.

This module is deliberately transport-free.  It provides immutable contracts and
pure policy/lifecycle helpers; real browser, Gmail, DNS, and network I/O remain
injected adapters executed by the existing runtime/action plane.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Any
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from webpent.models.evidence import redact_sensitive

_SECRET_NAMES = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "cookies",
        "otp",
        "raw_otp",
        "message_body",
        "raw_body",
    }
)
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ControlPlaneValidationError(ValueError):
    """Raised when a control-plane contract cannot be safely constructed."""


def _secret_key_present(value: Any) -> str | None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in _SECRET_NAMES:
                return normalized
            found = _secret_key_present(child)
            if found:
                return found
    elif isinstance(value, (list, tuple)):
        for child in value:
            found = _secret_key_present(child)
            if found:
                return found
    return None


def _clean_text(value: Any, *, field_name: str, max_length: int = 240) -> str:
    text = str(value or "").strip()
    if not text:
        raise ControlPlaneValidationError(f"{field_name}_required")
    clean, _ = redact_sensitive(text)
    return str(clean)[:max_length]


def _hash(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8', 'ignore')).hexdigest()}"


def normalize_hostname(value: str) -> str:
    """Normalize a DNS name or IP literal without performing resolution."""
    raw = str(value or "").strip()
    if not raw or "%" in raw or "/" in raw or "@" in raw:
        raise ControlPlaneValidationError("hostname_ambiguous")
    raw = raw.strip("[]").rstrip(".")
    try:
        return ipaddress.ip_address(raw).compressed.lower()
    except ValueError:
        try:
            ascii_name = raw.encode("idna").decode("ascii").lower().rstrip(".")
        except (UnicodeError, ValueError) as exc:
            raise ControlPlaneValidationError("hostname_invalid") from exc
        labels = ascii_name.split(".")
        if not labels or any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
            raise ControlPlaneValidationError("hostname_invalid") from None
        return ascii_name


class ScopeDecisionType(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    AMBIGUOUS = "scope_ambiguous"
    BLOCKED = "blocked_by_precondition"


class IdentityStatus(str, Enum):
    CREATED = "created"
    SIGNUP_PENDING = "signup_pending"
    EMAIL_PENDING = "email_pending"
    VERIFIED = "verified"
    LOGIN_READY = "login_ready"
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"
    DESTROYED = "destroyed"


class WorkflowStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    BLOCKED = "blocked_by_precondition"
    NEEDS_USER_TAKEOVER = "needs_user_takeover"
    FAILED = "failed"


class ScopeRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    scheme: str = Field(min_length=1, max_length=8)
    hostname: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    wildcard: bool = False
    apex_allowed: bool = False
    path_prefix: str = Field(default="/", min_length=1, max_length=512)
    attack_surface: bool = True
    control_plane: bool = False

    @field_validator("scheme", mode="before")
    @classmethod
    def _scheme(cls, value: Any) -> str:
        scheme = str(value or "").lower()
        if scheme not in {"http", "https"}:
            raise ValueError("unsupported_scope_scheme")
        return scheme

    @field_validator("hostname", mode="before")
    @classmethod
    def _hostname(cls, value: Any) -> str:
        return normalize_hostname(str(value or ""))

    @field_validator("path_prefix", mode="before")
    @classmethod
    def _path(cls, value: Any) -> str:
        path = str(value or "/").strip()
        if "%" in path or not path.startswith("/"):
            raise ValueError("ambiguous_path_rule")
        return path.rstrip("/") or "/"


class EngagementScope(BaseModel):
    """Immutable, auditable engagement scope compiled from operator input."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    engagement_id: str = Field(min_length=1, max_length=160)
    root_domains: tuple[str, ...] = Field(min_length=1, max_length=64)
    allowed_schemes: tuple[str, ...] = ("https",)
    allowed_ports: tuple[int, ...] = (443,)
    path_rules: tuple[str, ...] = ("/",)
    dns_policy: str = "deny_on_error"
    redirect_policy: str = "same_scope_only"
    email_domains: tuple[str, ...] = ()
    third_party_exceptions: tuple[ScopeRule, ...] = ()
    created_by: str = Field(min_length=1, max_length=160)
    expires_at: datetime
    wildcard_interpretation: str = Field(min_length=1, max_length=500)
    approval_source: str = Field(min_length=1, max_length=240)
    rules: tuple[ScopeRule, ...] = Field(min_length=1, max_length=96)

    @field_validator("allowed_schemes", mode="before")
    @classmethod
    def _schemes(cls, value: Any) -> tuple[str, ...]:
        values = tuple(dict.fromkeys(str(item).lower() for item in (value or ())))
        if not values or any(item not in {"http", "https"} for item in values):
            raise ValueError("allowed_schemes_must_be_http_or_https")
        return values

    @field_validator("allowed_ports", mode="before")
    @classmethod
    def _ports(cls, value: Any) -> tuple[int, ...]:
        values = tuple(dict.fromkeys(int(item) for item in (value or ())))
        if not values or any(item < 1 or item > 65535 for item in values):
            raise ValueError("allowed_ports_invalid")
        return values

    @field_validator("email_domains", mode="before")
    @classmethod
    def _email_domains(cls, value: Any) -> tuple[str, ...]:
        return tuple(dict.fromkeys(normalize_hostname(str(item)) for item in (value or ())))

    @model_validator(mode="after")
    def _valid_expiry(self) -> EngagementScope:
        if self.expires_at.tzinfo is None:
            raise ValueError("expires_at_must_be_timezone_aware")
        if self.expires_at <= datetime.now(timezone.utc):
            raise ValueError("scope_expired")
        return self

    def is_expired(self, *, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        return current >= self.expires_at


class ScopeDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    decision: ScopeDecisionType
    input_url: str = Field(max_length=2048)
    normalized_url: str = ""
    matched_rule: str = ""
    reason: str = Field(min_length=1, max_length=300)
    attack_surface: bool = False
    control_plane: bool = False
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def allowed(self) -> bool:
        return self.decision == ScopeDecisionType.ALLOWED


class DNSResolutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    hostname: str = Field(min_length=1, max_length=253)
    addresses: tuple[str, ...] = ()
    error: str = ""
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rebound: bool = False

    @field_validator("hostname", mode="before")
    @classmethod
    def _host(cls, value: Any) -> str:
        return normalize_hostname(str(value or ""))

    @field_validator("addresses", mode="before")
    @classmethod
    def _addresses(cls, value: Any) -> tuple[str, ...]:
        result: list[str] = []
        for item in value or ():
            try:
                result.append(ipaddress.ip_address(str(item).strip()).compressed)
            except ValueError as exc:
                raise ValueError("dns_address_invalid") from exc
        return tuple(dict.fromkeys(result))


def _ip_is_unsafe(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return bool(
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def evaluate_dns(scope: EngagementScope, result: DNSResolutionResult) -> ScopeDecision:
    """Evaluate an injected DNS observation; never performs DNS itself."""
    if scope.is_expired():
        return ScopeDecision(
            decision=ScopeDecisionType.BLOCKED,
            input_url=result.hostname,
            reason="scope_expired",
        )
    if result.error or result.rebound:
        return ScopeDecision(
            decision=ScopeDecisionType.DENIED,
            input_url=result.hostname,
            reason="dns_error_or_rebinding",
        )
    if not result.addresses:
        return ScopeDecision(
            decision=ScopeDecisionType.DENIED,
            input_url=result.hostname,
            reason="dns_empty_result",
        )
    if any(_ip_is_unsafe(address) for address in result.addresses):
        return ScopeDecision(
            decision=ScopeDecisionType.DENIED,
            input_url=result.hostname,
            reason="dns_private_or_reserved_address",
        )
    return ScopeDecision(
        decision=ScopeDecisionType.ALLOWED,
        input_url=result.hostname,
        normalized_url=result.hostname,
        matched_rule="dns_policy",
        reason="dns_resolution_accepted",
        attack_surface=True,
    )


def _parse_root(
    raw: str,
    *,
    allowed_schemes: tuple[str, ...],
    allowed_ports: tuple[int, ...],
    path_rules: tuple[str, ...],
) -> ScopeRule:
    value = str(raw or "").strip()
    if not value or "@" in value or "%" in value:
        raise ControlPlaneValidationError("scope_root_ambiguous")
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    scheme = parsed.scheme.lower()
    if scheme not in allowed_schemes or parsed.username is not None or parsed.password is not None:
        raise ControlPlaneValidationError("scope_root_scheme_or_userinfo_denied")
    if parsed.query or parsed.fragment or not parsed.hostname:
        raise ControlPlaneValidationError("scope_root_url_ambiguous")
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise ControlPlaneValidationError("scope_root_port_invalid") from exc
    if port not in allowed_ports:
        raise ControlPlaneValidationError("scope_root_port_not_allowed")
    hostname = parsed.hostname
    wildcard = hostname.startswith("*.")
    if wildcard:
        hostname = hostname[2:]
    normalized = normalize_hostname(hostname)
    return ScopeRule(
        scheme=scheme,
        hostname=normalized,
        port=port,
        wildcard=wildcard,
        apex_allowed=not wildcard,
        path_prefix=parsed.path or path_rules[0],
    )


def compile_scope(
    *,
    engagement_id: str,
    root_domains: Iterable[str],
    created_by: str,
    approval_source: str,
    expires_at: datetime,
    allowed_schemes: Iterable[str] = ("https",),
    allowed_ports: Iterable[int] = (443,),
    path_rules: Iterable[str] = ("/",),
    email_domains: Iterable[str] = (),
    third_party_exceptions: Iterable[str] = (),
) -> EngagementScope:
    """Compile explicit operator scope; wildcard ambiguity is never guessed."""
    schemes = tuple(dict.fromkeys(str(item).lower() for item in allowed_schemes))
    ports = tuple(dict.fromkeys(int(item) for item in allowed_ports))
    paths = tuple(dict.fromkeys(str(item) for item in path_rules)) or ("/",)
    raw_roots = tuple(str(item).strip() for item in root_domains)
    if not raw_roots:
        raise ControlPlaneValidationError("root_domains_required")
    rules = tuple(
        _parse_root(item, allowed_schemes=schemes, allowed_ports=ports, path_rules=paths)
        for item in raw_roots
    )
    exceptions = tuple(
        _parse_root(
            item,
            allowed_schemes=("http", "https"),
            allowed_ports=(80, 443),
            path_rules=("/",),
        ).model_copy(update={"attack_surface": False, "control_plane": True})
        for item in third_party_exceptions
    )
    normalized_roots = tuple(
        (
            f"{rule.scheme}://{'*.' if rule.wildcard else ''}"
            f"{rule.hostname}:{rule.port}{rule.path_prefix}"
        )
        for rule in rules
    )
    interpretation = (
        "Wildcard allows one or more labels below the listed registrable hostname; "
        "apex is denied unless explicitly listed; exact scheme, port, and path apply."
    )
    return EngagementScope(
        engagement_id=_clean_text(engagement_id, field_name="engagement_id", max_length=160),
        root_domains=normalized_roots,
        allowed_schemes=schemes,
        allowed_ports=ports,
        path_rules=paths,
        email_domains=tuple(email_domains),
        third_party_exceptions=exceptions,
        created_by=_clean_text(created_by, field_name="created_by", max_length=160),
        expires_at=expires_at,
        wildcard_interpretation=interpretation,
        approval_source=_clean_text(approval_source, field_name="approval_source"),
        rules=rules + exceptions,
    )


def evaluate_scope(scope: EngagementScope, url: str, *, method: str = "GET") -> ScopeDecision:
    """Pure URL decision function for navigation, redirects, popups, and actions."""
    raw = str(url or "").strip()
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ControlPlaneValidationError("url_scheme_or_host_invalid")
        if parsed.username is not None or parsed.password is not None or "%" in parsed.netloc:
            raise ControlPlaneValidationError("url_userinfo_or_encoded_host_denied")
        if parsed.fragment:
            raise ControlPlaneValidationError("url_fragment_denied")
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        host = normalize_hostname(parsed.hostname)
        path = parsed.path or "/"
        if (
            "\\" in raw
            or unquote(host) != host
            or "%" in parsed.path
            or "%" in parsed.netloc
        ):
            raise ControlPlaneValidationError("url_ambiguous_encoding")
    except (TypeError, ValueError, ControlPlaneValidationError) as exc:
        reason = str(exc) or "url_parse_failed"
        decision = (
            ScopeDecisionType.AMBIGUOUS
            if "ambiguous" in reason or reason == "url_ambiguous_encoding"
            else ScopeDecisionType.DENIED
        )
        return ScopeDecision(decision=decision, input_url=raw, reason=reason)

    if scope.is_expired():
        return ScopeDecision(
            decision=ScopeDecisionType.BLOCKED,
            input_url=raw,
            reason="scope_expired",
        )
    for rule in scope.rules:
        if parsed.scheme.lower() != rule.scheme or port != rule.port:
            continue
        host_matches = (
            host == rule.hostname
            if not rule.wildcard
            else host.endswith(f".{rule.hostname}") and host != rule.hostname
        )
        path_matches = (
            rule.path_prefix == "/"
            or path == rule.path_prefix
            or path.startswith(f"{rule.path_prefix}/")
        )
        if host_matches and path_matches:
            return ScopeDecision(
                decision=ScopeDecisionType.ALLOWED,
                input_url=raw,
                normalized_url=f"{parsed.scheme.lower()}://{host}:{port}{path}",
                matched_rule=rule.hostname,
                reason="scope_rule_match",
                attack_surface=rule.attack_surface,
                control_plane=rule.control_plane,
            )
    return ScopeDecision(
        decision=ScopeDecisionType.DENIED,
        input_url=raw,
        reason="outside_declared_scope",
    )


class IdentityProfileRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    identity_id: str = Field(min_length=1, max_length=160)
    engagement_id: str = Field(min_length=1, max_length=160)
    email_ref: str = Field(min_length=1, max_length=240)
    username_ref: str = Field(min_length=1, max_length=240)
    role: str = Field(default="unknown", max_length=120)
    tenant_ref: str = Field(default="", max_length=160)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: IdentityStatus = IdentityStatus.CREATED
    provenance: str = Field(min_length=1, max_length=240)

    @model_validator(mode="before")
    @classmethod
    def _no_raw_secrets(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            found = _secret_key_present(value)
            if found:
                raise ValueError(f"raw_secret_field_rejected:{found}")
        return value


class BrowserSessionRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    session_id: str = Field(min_length=1, max_length=160)
    engagement_id: str = Field(min_length=1, max_length=160)
    profile_ref: str = Field(min_length=1, max_length=240)
    browser_type: str = Field(min_length=1, max_length=80)
    context_id: str = Field(min_length=1, max_length=160)
    authenticated_origins: tuple[str, ...] = ()
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    cookie_fingerprint: str = Field(min_length=1, max_length=80)

    @model_validator(mode="before")
    @classmethod
    def _no_raw_cookies(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            found = _secret_key_present(value)
            if found:
                raise ValueError(f"raw_secret_field_rejected:{found}")
        return value

    @field_validator("cookie_fingerprint", mode="before")
    @classmethod
    def _fingerprint(cls, value: Any) -> str:
        text = str(value or "")
        if not text.startswith("sha256:") or len(text) != 71:
            raise ValueError("cookie_fingerprint_must_be_digest")
        return text


class WorkflowStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    workflow_id: str = Field(min_length=1, max_length=160)
    step_id: str = Field(min_length=1, max_length=160)
    preconditions: tuple[str, ...] = ()
    action_id: str = Field(min_length=1, max_length=160)
    expected_state_transition: str = Field(min_length=1, max_length=240)
    observations: Mapping[str, Any] = Field(default_factory=dict)
    rollback_action: str = Field(default="", max_length=160)
    proof_refs: tuple[str, ...] = ()
    status: WorkflowStatus = WorkflowStatus.PENDING

    @model_validator(mode="before")
    @classmethod
    def _redact_and_reject_secrets(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            if _secret_key_present(value):
                raise ValueError("raw_secret_field_rejected")
            clean, _ = redact_sensitive(dict(value))
            return clean
        return value


class EmailEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    message_id_hash: str = Field(min_length=71, max_length=71)
    mailbox_ref: str = Field(min_length=1, max_length=240)
    sender_domain: str = Field(min_length=1, max_length=253)
    subject_hash: str = Field(min_length=71, max_length=71)
    received_at: datetime
    correlation_nonce: str = Field(min_length=16, max_length=160)
    target_origin: str = Field(min_length=1, max_length=2048)
    artifact_ref: str = Field(default="", max_length=240)
    confidence: float = Field(ge=0.0, le=1.0)
    status: str = Field(min_length=1, max_length=80)
    quarantined: bool = False
    prompt_injection_detected: bool = False

    @field_validator("sender_domain", mode="before")
    @classmethod
    def _sender(cls, value: Any) -> str:
        return normalize_hostname(str(value or ""))

    @model_validator(mode="before")
    @classmethod
    def _no_body_or_otp(cls, value: Any) -> Any:
        if isinstance(value, Mapping) and _secret_key_present(value):
            raise ValueError("raw_email_secret_rejected")
        return value


class BrowserActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    action_id: str = Field(min_length=1, max_length=160)
    engagement_id: str = Field(min_length=1, max_length=160)
    session_id: str = Field(min_length=1, max_length=160)
    operation: str = Field(min_length=1, max_length=80)
    url: str = Field(min_length=1, max_length=2048)
    scope_decision: ScopeDecision
    timeout_ms: int = Field(default=10000, ge=100, le=120000)
    idempotency_key: str = Field(min_length=1, max_length=200)
    user_takeover_required: bool = False
    observation_role: str = Field(default="observation", min_length=1, max_length=40)
    # Ephemeral validator metadata only; the payload value never crosses this
    # transport contract or enters checkpoints/records.
    probe_ref: str | None = Field(default=None, max_length=240)
    probe_digest: str | None = Field(default=None, min_length=71, max_length=71)
    # Explicit workflow selector for narrowly typed SPA operations.  It is
    # metadata only; the ephemeral probe value never crosses this contract.
    workflow_id: str | None = Field(default=None, max_length=120)
    # Target-adapter semantic selector.  It names a reviewed, read-only
    # redaction profile; it never carries a body, header, payload, or secret.
    semantic_profile: str | None = Field(default=None, max_length=160)

    @model_validator(mode="after")
    def _validate_probe_metadata(self) -> BrowserActionRequest:
        if self.operation in {"validate_input", "typed_search"}:
            if not self.probe_ref or not self.probe_digest:
                raise ValueError("validator_probe_reference_and_digest_required")
            if not self.probe_ref.startswith("probe://"):
                raise ValueError("validator_probe_reference_invalid")
            if not self.probe_digest.startswith("sha256:"):
                raise ValueError("validator_probe_digest_invalid")
        elif self.probe_ref is not None or self.probe_digest is not None:
            raise ValueError("probe_metadata_not_allowed_for_operation")
        if self.operation == "typed_search" and not self.workflow_id:
            raise ValueError("typed_search_workflow_required")
        if self.operation != "typed_search" and self.workflow_id is not None:
            raise ValueError("workflow_metadata_not_allowed_for_operation")
        if self.semantic_profile is not None:
            if self.operation != "navigate":
                raise ValueError("semantic_profile_requires_navigate")
            profile = str(self.semantic_profile).strip()
            if not profile or "/" in profile or "\\\\" in profile:
                raise ValueError("semantic_profile_invalid")
        return self


class ActionOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    action_id: str = Field(min_length=1, max_length=160)
    status: str = Field(min_length=1, max_length=80)
    observation_refs: tuple[str, ...] = ()
    proof_refs: tuple[str, ...] = ()
    reason: str = Field(default="", max_length=300)
    clean: bool = False
    redacted: bool = True
    observation: dict[str, Any] = Field(default_factory=dict)


_ALLOWED_TRANSITIONS: dict[IdentityStatus, frozenset[IdentityStatus]] = {
    IdentityStatus.CREATED: frozenset(
        {IdentityStatus.SIGNUP_PENDING, IdentityStatus.REVOKED, IdentityStatus.DESTROYED}
    ),
    IdentityStatus.SIGNUP_PENDING: frozenset(
        {IdentityStatus.EMAIL_PENDING, IdentityStatus.QUARANTINED, IdentityStatus.REVOKED}
    ),
    IdentityStatus.EMAIL_PENDING: frozenset(
        {IdentityStatus.VERIFIED, IdentityStatus.QUARANTINED, IdentityStatus.REVOKED}
    ),
    IdentityStatus.VERIFIED: frozenset(
        {IdentityStatus.LOGIN_READY, IdentityStatus.REVOKED, IdentityStatus.DESTROYED}
    ),
    IdentityStatus.LOGIN_READY: frozenset(
        {IdentityStatus.ACTIVE, IdentityStatus.QUARANTINED, IdentityStatus.REVOKED}
    ),
    IdentityStatus.ACTIVE: frozenset(
        {IdentityStatus.QUARANTINED, IdentityStatus.REVOKED, IdentityStatus.DESTROYED}
    ),
    IdentityStatus.QUARANTINED: frozenset({IdentityStatus.REVOKED, IdentityStatus.DESTROYED}),
    IdentityStatus.REVOKED: frozenset({IdentityStatus.DESTROYED}),
    IdentityStatus.DESTROYED: frozenset(),
}


class IdentityManager:
    """Engagement-bound, idempotent identity lifecycle without secret storage."""

    def __init__(self) -> None:
        self._profiles: dict[str, IdentityProfileRef] = {}
        self._lock = RLock()

    def create(self, profile: IdentityProfileRef) -> IdentityProfileRef:
        with self._lock:
            current = self._profiles.get(profile.identity_id)
            if current is not None:
                if current.engagement_id != profile.engagement_id:
                    raise ControlPlaneValidationError("identity_cross_engagement_reuse")
                return current
            self._profiles[profile.identity_id] = profile
            return profile

    def transition(
        self,
        identity_id: str,
        status: IdentityStatus,
        *,
        engagement_id: str,
    ) -> IdentityProfileRef:
        with self._lock:
            current = self._profiles.get(identity_id)
            if current is None:
                raise ControlPlaneValidationError("identity_not_found")
            if current.engagement_id != engagement_id:
                raise ControlPlaneValidationError("identity_cross_engagement_reuse")
            if status == current.status:
                return current
            if status not in _ALLOWED_TRANSITIONS[current.status]:
                raise ControlPlaneValidationError(
                    f"identity_transition_denied:{current.status}->{status}"
                )
            updated = current.model_copy(update={"status": status})
            self._profiles[identity_id] = updated
            return updated

    def get(self, identity_id: str, *, engagement_id: str) -> IdentityProfileRef | None:
        with self._lock:
            profile = self._profiles.get(identity_id)
            if profile is None or profile.engagement_id != engagement_id:
                return None
            return profile

    def snapshot(self, *, engagement_id: str) -> tuple[IdentityProfileRef, ...]:
        with self._lock:
            return tuple(
                profile
                for profile in self._profiles.values()
                if profile.engagement_id == engagement_id
            )


__all__ = [
    "ActionOutcome",
    "BrowserActionRequest",
    "BrowserSessionRef",
    "ControlPlaneValidationError",
    "DNSResolutionResult",
    "EmailEvent",
    "EngagementScope",
    "IdentityManager",
    "IdentityProfileRef",
    "IdentityStatus",
    "ScopeDecision",
    "ScopeDecisionType",
    "ScopeRule",
    "WorkflowStatus",
    "WorkflowStep",
    "compile_scope",
    "evaluate_dns",
    "evaluate_scope",
    "normalize_hostname",
]
