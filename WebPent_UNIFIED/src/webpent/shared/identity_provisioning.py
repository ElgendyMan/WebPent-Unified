"""Fail-closed, adapter-driven test-identity provisioning contracts.

This module deliberately contains no browser, Gmail, IMAP, or HTTP transport.  The
runtime injects bounded adapters; state receives only report-safe references.
"""
from __future__ import annotations

import hashlib
import secrets
import string
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, model_validator

from webpent.auth.reauth_vault import identity_vault_key, seal_identity_profiles
from webpent.config.settings import get_settings
from webpent.shared.control_plane import (
    EngagementScope,
    IdentityProfileRef,
    IdentityStatus,
    evaluate_scope,
)


class IdentityProvisioningStatus(StrEnum):
    DISABLED = "disabled"
    NO_FORMS_DETECTED = "no_forms_detected"
    PENDING = "pending"
    VERIFIED = "verified"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    FAILED = "failed"


class SignupFormDetected(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: str = Field(min_length=1, max_length=160)
    client_id: str = Field(min_length=1, max_length=160)
    target_signup_url: str = Field(min_length=1, max_length=2048)
    detected_form_fields: tuple[str, ...] = ()
    source: str = Field(default="crawler", min_length=1, max_length=80)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IdentityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: str = Field(min_length=1, max_length=160)
    client_id: str = Field(min_length=1, max_length=160)
    target_signup_url: str = Field(min_length=1, max_length=2048)
    detected_form_fields: tuple[str, ...] = ()
    scope_token: EngagementScope


class SignupSubmitted(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    correlation_id: str = Field(min_length=16, max_length=160)
    identity_id: str = Field(min_length=1, max_length=160)
    engagement_id: str = Field(min_length=1, max_length=160)
    target_signup_url: str = Field(min_length=1, max_length=2048)
    email_ref: str = Field(min_length=1, max_length=240)
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VerificationMaterialFound(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    correlation_id: str = Field(min_length=16, max_length=160)
    target_origin: str = Field(min_length=1, max_length=2048)
    material_type: str = Field(pattern="^(otp|link)$")
    material_ref: str = Field(min_length=1, max_length=240)
    event_ref: str = Field(min_length=1, max_length=240)
    found_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="before")
    @classmethod
    def reject_raw_material(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            keys = {str(key).lower() for key in value}
            if keys.intersection({"otp", "code", "password", "body", "message_body", "token"}):
                raise ValueError("raw_verification_material_rejected")
        return value


class IdentityRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    identity_id: str = Field(min_length=1, max_length=160)
    engagement_id: str = Field(min_length=1, max_length=160)
    email_ref: str = Field(min_length=1, max_length=240)
    password_ref: str = Field(min_length=1, max_length=240)
    verification_status: IdentityProvisioningStatus
    proof_ref: str = Field(default="", max_length=240)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    profile_ref: IdentityProfileRef | None = None


class EmailVerificationWatcher:
    """Bounded mailbox watcher facade; a real Gmail/IMAP adapter is injected."""

    def __init__(
        self,
        poller: Callable[[SignupSubmitted], VerificationMaterialFound | None],
        *,
        timeout_seconds: int = 120,
    ) -> None:
        self._poller = poller
        self._timeout_seconds = max(1, min(int(timeout_seconds), 600))

    def wait_for_material(self, submitted: SignupSubmitted) -> VerificationMaterialFound | None:
        try:
            material = self._poller(submitted)
        except Exception:
            return None
        if material is None or material.correlation_id != submitted.correlation_id:
            return None
        return material


def _safe_slug(value: str) -> str:
    slug = "".join(
        char for char in value.lower() if char.isalnum() or char in "-_"
    )[:32]
    return slug or "engagement"


def _identity_id(request: IdentityRequest) -> str:
    digest = hashlib.sha256(
        f"{request.client_id}:{request.engagement_id}:{request.target_signup_url}".encode()
    ).hexdigest()[:20]
    return f"identity-{digest}"


def _password() -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    return "".join(secrets.choice(alphabet) for _ in range(28))


class IdentityProvisioningAgent:
    """Provision one engagement-bound identity through injected adapters only."""

    def __init__(
        self,
        *,
        submit_signup: Callable[[IdentityRequest, str, str], bool],
        watcher: EmailVerificationWatcher,
        complete_verification: Callable[[SignupSubmitted, VerificationMaterialFound], bool],
        mailbox_ref: str,
        domain: str = "testmailbox.invalid",
        ttl_seconds: int = 1800,
        max_signups: int = 5,
    ) -> None:
        if not mailbox_ref or "://" not in mailbox_ref:
            raise ValueError("mailbox_ref_must_be_opaque_reference")
        self._submit_signup = submit_signup
        self._watcher = watcher
        self._complete_verification = complete_verification
        self._mailbox_ref = mailbox_ref
        self._domain = domain.lower().strip(".")
        self._ttl_seconds = max(60, min(int(ttl_seconds), 3600))
        self._max_signups = max(0, min(int(max_signups), 50))
        self._counts: dict[str, int] = {}

    def provision(self, event: SignupFormDetected, scope: EngagementScope) -> dict[str, Any]:
        if self._max_signups == 0:
            return {
                "status": IdentityProvisioningStatus.BLOCKED.value,
                "reason": "signup_budget_zero",
            }
        if event.engagement_id != scope.engagement_id:
            return {
                "status": IdentityProvisioningStatus.BLOCKED.value,
                "reason": "engagement_scope_mismatch",
            }
        decision = evaluate_scope(scope, event.target_signup_url)
        if not decision.allowed:
            return {
                "status": IdentityProvisioningStatus.BLOCKED.value,
                "reason": "signup_url_out_of_scope",
            }
        used = self._counts.get(event.engagement_id, 0)
        if used >= self._max_signups:
            return {
                "status": IdentityProvisioningStatus.BLOCKED.value,
                "reason": "signup_budget_exhausted",
            }
        request = IdentityRequest(
            engagement_id=event.engagement_id,
            client_id=event.client_id,
            target_signup_url=event.target_signup_url,
            detected_form_fields=event.detected_form_fields,
            scope_token=scope,
        )
        identity_id = _identity_id(request)
        email = f"{_safe_slug(event.engagement_id)}+{identity_id[-8:]}@{self._domain}"
        password = _password()
        self._counts[event.engagement_id] = used + 1
        try:
            submitted_ok = bool(self._submit_signup(request, email, password))
        except Exception:
            submitted_ok = False
        if not submitted_ok:
            return {
                "status": IdentityProvisioningStatus.FAILED.value,
                "reason": "signup_submission_failed",
            }
        correlation_id = f"corr-{secrets.token_urlsafe(18)}"
        submitted = SignupSubmitted(
            correlation_id=correlation_id,
            identity_id=identity_id,
            engagement_id=event.engagement_id,
            target_signup_url=event.target_signup_url,
            email_ref=f"vault://{event.engagement_id}/{self._mailbox_ref}/alias",
        )
        seal_identity_profiles(
            identity_vault_key(event.client_id, event.engagement_id),
            {identity_id: {"credentials": {"username": email, "password": password}}},
        )
        material = self._watcher.wait_for_material(submitted)
        if material is None:
            return {
                "status": IdentityProvisioningStatus.INCONCLUSIVE.value,
                "reason": "mailbox_timeout_or_correlation_failure",
                "signup_submitted": submitted.model_dump(mode="json"),
            }
        link_origin = f"{urlparse(material.target_origin).scheme}://{urlparse(material.target_origin).netloc}"
        if not evaluate_scope(scope, link_origin).allowed:
            return {
                "status": IdentityProvisioningStatus.BLOCKED.value,
                "reason": "verification_target_out_of_scope",
                "signup_submitted": submitted.model_dump(mode="json"),
            }
        try:
            verified = bool(self._complete_verification(submitted, material))
        except Exception:
            verified = False
        if not verified:
            return {
                "status": IdentityProvisioningStatus.FAILED.value,
                "reason": "verification_completion_failed",
                "signup_submitted": submitted.model_dump(mode="json"),
            }
        now = datetime.now(timezone.utc)
        profile = IdentityProfileRef(
            identity_id=identity_id,
            engagement_id=event.engagement_id,
            email_ref=email,
            username_ref=email,
            role="test-user",
            tenant_ref=event.client_id,
            created_at=now,
            status=IdentityStatus.VERIFIED,
            provenance="identity_provisioning_agent",
        )
        return {
            "status": IdentityProvisioningStatus.VERIFIED.value,
            "identity_records": {
                identity_id: IdentityRecord(
                    identity_id=identity_id,
                    engagement_id=event.engagement_id,
                    email_ref=email,
                    password_ref=(
                        f"vault://{event.client_id}:{event.engagement_id}"
                        f"/identity/{identity_id}/password"
                    ),
                    verification_status=IdentityProvisioningStatus.VERIFIED,
                    proof_ref=material.event_ref,
                    created_at=now,
                    expires_at=now + timedelta(seconds=self._ttl_seconds),
                    profile_ref=profile,
                ).model_dump(mode="json")
            },
            "identity_profiles": {identity_id: profile.model_dump(mode="json")},
            "signup_submissions": [submitted.model_dump(mode="json")],
            "verification_material_events": [
                {"event_ref": material.event_ref, "status": "redacted"}
            ],
        }


def project_signup_form_events(
    crawled_data: Mapping[str, Any] | None,
    *,
    engagement_id: str,
    client_id: str,
    source: str = "crawler",
) -> list[dict[str, Any]]:
    """Project only report-safe signup metadata from crawler/JS observations.

    Form values are intentionally never copied. A form is considered a signup
    candidate only when its URL or field names contain an explicit registration
    marker. Missing tenant identifiers or non-HTTP(S) actions are rejected.
    """
    if not engagement_id.strip() or not client_id.strip():
        return []
    forms = (crawled_data or {}).get("forms") if isinstance(crawled_data, Mapping) else []
    if not isinstance(forms, list):
        return []
    markers = ("signup", "sign-up", "register", "registration", "create-account", "create_account")
    projected: list[dict[str, Any]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for raw_form in forms[:100]:
        if not isinstance(raw_form, Mapping):
            continue
        target_url = str(raw_form.get("action") or raw_form.get("source_url") or "").strip()
        parsed = urlparse(target_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        raw_data = raw_form.get("data")
        field_names = tuple(
            sorted(
                {
                    str(name).strip()[:120]
                    for name in (raw_data.keys() if isinstance(raw_data, Mapping) else ())
                    if str(name).strip()
                }
            )
        )
        haystack = " ".join((target_url, *field_names)).lower()
        if not any(marker in haystack for marker in markers):
            continue
        key = (target_url, field_names)
        if key in seen:
            continue
        seen.add(key)
        projected.append(
            SignupFormDetected(
                engagement_id=engagement_id.strip(),
                client_id=client_id.strip(),
                target_signup_url=target_url,
                detected_form_fields=field_names,
                source=source,
            ).model_dump(mode="json")
        )
    return projected


def _aggregate_identity_status(statuses: list[str]) -> str:
    """Aggregate per-form outcomes without upgrading an unproven result."""
    if not statuses:
        return IdentityProvisioningStatus.NO_FORMS_DETECTED.value
    for status in (
        IdentityProvisioningStatus.VERIFIED.value,
        IdentityProvisioningStatus.FAILED.value,
        IdentityProvisioningStatus.INCONCLUSIVE.value,
        IdentityProvisioningStatus.BLOCKED.value,
    ):
        if status in statuses:
            return status
    return IdentityProvisioningStatus.INCONCLUSIVE.value


def identity_provisioning_node(state: dict[str, Any]) -> dict[str, Any]:
    """Run optional bounded provisioning for crawler-discovered signup forms.

    This node consumes only report-safe form metadata and a live agent injected
    through ``RuntimeContext``. Missing settings, scope, agent, or malformed form
    input never falls through to a submission; they produce an explicit result.
    """
    settings = get_settings()
    if not getattr(settings, "identity_provisioning_enabled", False):
        return {"identity_provisioning_status": IdentityProvisioningStatus.DISABLED.value}

    forms = state.get("signup_forms_detected") or []
    if not forms:
        return {
            "identity_provisioning_status": IdentityProvisioningStatus.NO_FORMS_DETECTED.value
        }

    runtime_context = state.get("runtime_context")
    agent = getattr(runtime_context, "identity_provisioning_agent", None)
    if agent is None:
        return {
            "identity_provisioning_status": IdentityProvisioningStatus.BLOCKED.value,
            "errors": ["identity_provisioning:agent_not_configured"],
        }
    scope = getattr(runtime_context, "engagement_scope", None)
    if not isinstance(scope, EngagementScope):
        return {
            "identity_provisioning_status": IdentityProvisioningStatus.BLOCKED.value,
            "errors": ["identity_provisioning:scope_not_configured"],
        }

    default_engagement = str(state.get("engagement_id") or scope.engagement_id).strip()
    default_client = str(state.get("client_id") or "").strip()
    statuses: list[str] = []
    output: dict[str, Any] = {
        "signup_submissions": [],
        "verification_material_events": [],
        "identity_records": {},
        "identity_profiles": {},
        "errors": [],
    }
    for raw_form in forms:
        try:
            form_data = dict(raw_form) if isinstance(raw_form, Mapping) else {}
            form_data.setdefault("engagement_id", default_engagement)
            form_data.setdefault("client_id", default_client)
            form = SignupFormDetected.model_validate(form_data)
        except Exception as exc:
            statuses.append(IdentityProvisioningStatus.BLOCKED.value)
            output["errors"].append(
                f"identity_provisioning:invalid_signup_form:{type(exc).__name__}"
            )
            continue
        try:
            result = agent.provision(form, scope)
        except Exception as exc:
            result = {
                "status": IdentityProvisioningStatus.FAILED.value,
                "reason": f"agent_error:{type(exc).__name__}",
            }
        status = str(result.get("status") or IdentityProvisioningStatus.INCONCLUSIVE.value)
        statuses.append(status)
        for key in ("signup_submissions", "verification_material_events"):
            values = result.get(key)
            if isinstance(values, list):
                output[key].extend(values)
        for key in ("identity_records", "identity_profiles"):
            values = result.get(key)
            if isinstance(values, Mapping):
                output[key].update(values)
        reason = str(result.get("reason") or "").strip()
        if reason:
            output["errors"].append(f"identity_provisioning:{reason}")

    output["identity_provisioning_status"] = _aggregate_identity_status(statuses)
    if not output["errors"]:
        output.pop("errors")
    return output


__all__ = [
    "EmailVerificationWatcher",
    "IdentityProvisioningAgent",
    "identity_provisioning_node",
    "project_signup_form_events",
    "IdentityProvisioningStatus",
    "IdentityRecord",
    "IdentityRequest",
    "SignupFormDetected",
    "SignupSubmitted",
    "VerificationMaterialFound",
]
