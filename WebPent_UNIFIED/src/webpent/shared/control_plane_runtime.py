"""Runtime-safe browser, email, workflow, and proof control-plane helpers.

No helper in this module creates a network client, browser, subprocess, or Gmail
connection. External effects are supplied as injected handlers and must still be
registered and authorized by the WebPent execution plane by the caller.
"""

from __future__ import annotations

import hashlib
import html
import re
import secrets
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from webpent.models.evidence import redact_sensitive
from webpent.models.proof_bundle import ProofBundle, build_proof_bundle
from webpent.shared.control_plane import (
    ActionOutcome,
    BrowserActionRequest,
    BrowserSessionRef,
    EmailEvent,
    EngagementScope,
    IdentityProfileRef,
    ScopeDecision,
    ScopeDecisionType,
    WorkflowStatus,
    WorkflowStep,
    evaluate_scope,
)

_SECRET_FIELD_NAMES = frozenset(
    {
        "password",
        "passwd",
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
_INJECTION_PATTERNS = (
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.I),
    re.compile(r"system\s+prompt|developer\s+message|tool\s+permission", re.I),
    re.compile(r"send\s+(?:me\s+)?(?:the\s+)?password|reveal\s+secret", re.I),
)
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
_OTP_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")
_PROFILE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")


def _safe_profile_segment(value: str, *, field_name: str) -> str:
    segment = str(value or "").strip()
    if (
        not segment
        or segment in {".", ".."}
        or "/" in segment
        or "\\" in segment
        or not _PROFILE_SEGMENT_RE.fullmatch(segment)
    ):
        raise ValueError(f"{field_name}_path_segment_invalid")
    return segment


def _digest(value: Any) -> str:
    clean, _ = redact_sensitive(value)
    payload = repr(clean).encode("utf-8", "ignore")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _contains_secret_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower().replace("-", "_") in _SECRET_FIELD_NAMES:
                return True
            if _contains_secret_key(child):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_secret_key(child) for child in value)
    return False


_BROWSER_OBSERVATION_SCALARS = frozenset(
    {
        "handler_status",
        "handler_id",
        "handler_version",
        "target_backed",
        "observation_role",
        "target_fingerprint",
        "request_digest",
        "response_digest",
        "status_code",
        "final_url_shape_digest",
        "dialog_count",
        "network_event_count",
        "dom_digest",
        "screenshot_digest",
        "replayable",
        "reason",
        "semantic_profile",
        "semantic_observation_version",
        "content_type_family",
        "response_length_bucket",
        "semantic_path_digest",
        "metric_line_count_bucket",
        "policy_directive_count_bucket",
        "log_record_count_bucket",
        "signature_field_count_bucket",
        "semantic_reason",
        "semantic_match",
        "semantic_oracle_ready",
        "directory_shape",
        "verbose_error_shape",
        "scoreboard_shape",
    }
)


def project_browser_observation(value: Any) -> dict[str, Any]:
    """Return a bounded, digest-only browser observation projection."""
    if not isinstance(value, Mapping) or _contains_secret_key(value):
        return {}
    projected: dict[str, Any] = {}
    for key in _BROWSER_OBSERVATION_SCALARS:
        if key not in value:
            continue
        item = value[key]
        if key in {
            "target_backed",
            "replayable",
        }:
            if isinstance(item, bool):
                projected[key] = item
        elif key in {
            "status_code",
            "dialog_count",
            "network_event_count",
            "response_length_bucket",
            "metric_line_count_bucket",
            "policy_directive_count_bucket",
            "log_record_count_bucket",
            "signature_field_count_bucket",
        }:
            if isinstance(item, int) and not isinstance(item, bool):
                projected[key] = max(0, min(1_000_000, item))
        elif key in {
            "semantic_match",
            "semantic_oracle_ready",
            "directory_shape",
            "verbose_error_shape",
            "scoreboard_shape",
        }:
            if isinstance(item, bool):
                projected[key] = item
        else:
            text = str(item or "")[:240]
            if key.endswith("_digest") or key in {
                "target_fingerprint",
                "request_digest",
                "response_digest",
            }:
                if text.startswith("sha256:") and len(text) == 71:
                    projected[key] = text
            elif text:
                projected[key] = text
    for key, item_keys, limit in (
        ("dialog_events", ("type", "message_digest"), 32),
        ("network_events", ("status", "url_shape_digest", "resource_type"), 128),
    ):
        items = value.get(key)
        if not isinstance(items, (list, tuple)):
            continue
        safe_items: list[dict[str, Any]] = []
        for item in items[:limit]:
            if not isinstance(item, Mapping) or _contains_secret_key(item):
                continue
            safe_item: dict[str, Any] = {}
            for item_key in item_keys:
                if item_key not in item:
                    continue
                item_value = item[item_key]
                if item_key == "status":
                    if isinstance(item_value, int) and not isinstance(item_value, bool):
                        safe_item[item_key] = max(0, min(1000, item_value))
                elif item_key.endswith("_digest"):
                    digest = str(item_value or "")
                    if digest.startswith("sha256:") and len(digest) == 71:
                        safe_item[item_key] = digest
                else:
                    safe_item[item_key] = str(item_value or "")[:120]
            if safe_item:
                safe_items.append(safe_item)
        if safe_items:
            projected[key] = safe_items
    return projected


def _intent_binding(value: Any | None) -> tuple[str, str]:
    """Return schema and digest for a bounded passive intent projection."""
    if value is None:
        return "", ""
    if hasattr(value, "model_dump"):
        payload = value.model_dump(mode="json")
    elif isinstance(value, Mapping):
        payload = dict(value)
    else:
        raise ValueError("application_intent_invalid")
    if _contains_secret_key(payload):
        raise ValueError("application_intent_contains_secret")
    if payload.get("bounded") is not True or payload.get("passive_only") is not True:
        raise ValueError("application_intent_must_be_bounded_passive")
    schema = str(payload.get("schema_version") or "").strip()[:80]
    if not schema:
        raise ValueError("application_intent_schema_required")
    return schema, _digest(payload)


class EmailCorrelationQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    engagement_id: str = Field(min_length=1, max_length=160)
    mailbox_ref: str = Field(min_length=1, max_length=240)
    recipient_ref: str = Field(min_length=1, max_length=240)
    sender_domains: tuple[str, ...] = ()
    correlation_nonce: str = Field(min_length=16, max_length=160)
    target_origin: str = Field(min_length=1, max_length=2048)
    not_before: datetime
    not_after: datetime

    @model_validator(mode="after")
    def _window(self) -> EmailCorrelationQuery:
        if self.not_before.tzinfo is None or self.not_after.tzinfo is None:
            raise ValueError("email_window_must_be_timezone_aware")
        if self.not_after <= self.not_before:
            raise ValueError("email_window_invalid")
        if self.not_after - self.not_before > timedelta(hours=1):
            raise ValueError("email_window_too_large")
        return self


class EmailArtifact(BaseModel):
    """Short-lived reference only; the value itself is intentionally absent."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    artifact_ref: str = Field(min_length=1, max_length=240)
    artifact_type: str = Field(min_length=1, max_length=40)
    value_digest: str = Field(min_length=71, max_length=71)
    expires_at: datetime
    target_origin: str = Field(min_length=1, max_length=2048)

    @model_validator(mode="after")
    def _future(self) -> EmailArtifact:
        if self.expires_at.tzinfo is None or self.expires_at <= datetime.now(timezone.utc):
            raise ValueError("artifact_expired")
        return self


class ParsedEmail(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    event: EmailEvent
    artifact: EmailArtifact | None = None
    safe_text_digest: str
    quarantined: bool
    reasons: tuple[str, ...] = ()


def _strip_active_html(value: str) -> str:
    text = re.sub(
        r"<(script|style|iframe|object|embed|form)\b[^>]*>.*?</\1>",
        " ",
        value,
        flags=re.I | re.S,
    )
    text = re.sub(r"<[^>]+>", " ", text)
    return html.unescape(re.sub(r"\s+", " ", text)).strip()


def _safe_sender_domain(sender: str) -> str:
    address = str(sender or "").strip().lower()
    if "@" not in address or address.count("@") != 1:
        return ""
    domain = address.rsplit("@", 1)[1].strip().rstrip(".")
    if not domain or any(char in domain for char in "/\\<> \t"):
        return ""
    return domain.encode("idna").decode("ascii")


def parse_email_message(
    raw_message: Mapping[str, Any],
    query: EmailCorrelationQuery,
    scope: EngagementScope,
    *,
    now: datetime | None = None,
    artifact_ttl: timedelta = timedelta(minutes=5),
) -> ParsedEmail:
    """Parse one untrusted message into a redacted event or quarantine result.

    The raw mapping is consumed ephemerally. No body, OTP, attachment, or URL
    value is copied into the returned models. An activation URL is only accepted
    after the pure Scope Engine approves it.
    """
    current = now or datetime.now(timezone.utc)
    message_id = str(raw_message.get("message_id") or "").strip()
    sender = _safe_sender_domain(str(raw_message.get("sender") or ""))
    recipient = str(raw_message.get("recipient") or "").strip().lower()
    subject = str(raw_message.get("subject") or "")
    body = str(raw_message.get("body") or raw_message.get("html") or "")
    attachment_names = tuple(str(item)[:120] for item in raw_message.get("attachments", ()) or ())
    clean_text = _strip_active_html(body)
    reasons: list[str] = []
    if current < query.not_before or current > query.not_after:
        reasons.append("correlation_window_expired")
    if not message_id:
        reasons.append("message_id_missing")
    if not sender or (query.sender_domains and sender not in query.sender_domains):
        reasons.append("sender_domain_not_allowed")
    if query.recipient_ref.lower() not in recipient:
        reasons.append("recipient_not_correlated")
    if query.correlation_nonce not in clean_text:
        reasons.append("nonce_not_correlated")
    received = raw_message.get("received_at")
    if not isinstance(received, datetime):
        reasons.append("received_at_missing")
        received = current
    elif received.tzinfo is None or not query.not_before <= received <= query.not_after:
        reasons.append("message_outside_time_window")
    if attachment_names:
        reasons.append("attachments_blocked")
    if any(pattern.search(clean_text) for pattern in _INJECTION_PATTERNS):
        reasons.append("prompt_injection_detected")
    urls = tuple(_URL_RE.findall(clean_text))
    scoped_urls = tuple(url for url in urls if evaluate_scope(scope, url).allowed)
    out_of_scope_urls = tuple(url for url in urls if not evaluate_scope(scope, url).allowed)
    if out_of_scope_urls:
        reasons.append("activation_link_outside_scope")
    artifact: EmailArtifact | None = None
    if not reasons:
        if scoped_urls:
            selected = scoped_urls[0].rstrip(".,)")
            artifact = EmailArtifact(
                artifact_ref=f"artifact://activation/{_digest(selected)[7:23]}",
                artifact_type="activation_url",
                value_digest=_digest(selected),
                expires_at=current + artifact_ttl,
                target_origin=query.target_origin,
            )
        else:
            otp_match = _OTP_RE.search(clean_text)
            if otp_match:
                raw_otp = otp_match.group(1)
                artifact = EmailArtifact(
                    artifact_ref=f"vault://otp/{secrets.token_hex(8)}",
                    artifact_type="otp",
                    value_digest=_digest(raw_otp),
                    expires_at=current + artifact_ttl,
                    target_origin=query.target_origin,
                )
            else:
                reasons.append("activation_artifact_missing")
    quarantined = bool(reasons)
    if quarantined:
        artifact = None
    event = EmailEvent(
        message_id_hash=_digest(message_id),
        mailbox_ref=query.mailbox_ref,
        sender_domain=sender or "invalid.invalid",
        subject_hash=_digest(subject),
        received_at=received,
        correlation_nonce=query.correlation_nonce,
        target_origin=query.target_origin,
        artifact_ref=artifact.artifact_ref if artifact else "",
        confidence=0.0 if quarantined else 1.0,
        status="quarantined" if quarantined else "matched",
        quarantined=quarantined,
        prompt_injection_detected="prompt_injection_detected" in reasons,
    )
    return ParsedEmail(
        event=event,
        artifact=artifact,
        safe_text_digest=_digest(clean_text),
        quarantined=quarantined,
        reasons=tuple(dict.fromkeys(reasons)),
    )


class BrowserSessionManager:
    """Manage references and isolated directories, never raw browser state."""

    def __init__(self, profile_root: str | Path) -> None:
        self.profile_root = Path(profile_root)
        self._sessions: dict[str, BrowserSessionRef] = {}
        self._lock = RLock()

    def create_session(
        self,
        *,
        engagement_id: str,
        profile_ref: str,
        browser_type: str = "chromium",
        authenticated_origins: tuple[str, ...] = (),
        ttl: timedelta = timedelta(hours=1),
        cookie_fingerprint: str,
    ) -> BrowserSessionRef:
        if ttl <= timedelta(0):
            raise ValueError("session_ttl_invalid")
        safe_engagement_id = _safe_profile_segment(
            engagement_id, field_name="engagement_id"
        )
        safe_profile_ref = _safe_profile_segment(profile_ref, field_name="profile_ref")
        session_id = f"session-{secrets.token_hex(12)}"
        context_id = f"context-{secrets.token_hex(12)}"
        directory = self.profile_root / safe_engagement_id / safe_profile_ref
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        session = BrowserSessionRef(
            session_id=session_id,
            engagement_id=engagement_id,
            profile_ref=profile_ref,
            browser_type=browser_type,
            context_id=context_id,
            authenticated_origins=authenticated_origins,
            expires_at=datetime.now(timezone.utc) + ttl,
            cookie_fingerprint=cookie_fingerprint,
        )
        with self._lock:
            self._sessions[session_id] = session
        return session

    def get(self, session_id: str, *, engagement_id: str) -> BrowserSessionRef | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.engagement_id != engagement_id:
                return None
            if session.expires_at <= datetime.now(timezone.utc):
                return None
            return session

    def revoke(self, session_id: str, *, engagement_id: str) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.engagement_id != engagement_id:
                return False
            del self._sessions[session_id]
            return True


class BrowserActionAdapter:
    """Typed adapter boundary; actual handler must be injected and pre-registered."""

    def __init__(
        self,
        handler: Callable[[BrowserActionRequest], Mapping[str, Any]],
        *,
        probe_registrar: Callable[[str, str], None] | None = None,
        probe_cleaner: Callable[[str], None] | None = None,
    ) -> None:
        self._handler = handler
        self._probe_registrar = probe_registrar
        self._probe_cleaner = probe_cleaner

    def register_ephemeral_probe(self, probe_ref: str, value: str) -> None:
        if self._probe_registrar is None:
            raise RuntimeError("ephemeral_probe_registrar_unavailable")
        self._probe_registrar(probe_ref, value)

    def clear_ephemeral_probe(self, probe_ref: str) -> None:
        if self._probe_cleaner is not None:
            self._probe_cleaner(probe_ref)

    def execute(
        self,
        request: BrowserActionRequest,
        session: BrowserSessionRef,
        *,
        allow_operations: frozenset[str] = frozenset(
            {
                "navigate",
                "click",
                "fill",
                "upload",
                "download",
                "screenshot",
                "dom_capture",
                "observe_network",
                "validate_input",
                "typed_search",
            }
        ),
    ) -> ActionOutcome:
        if request.scope_decision.decision != ScopeDecisionType.ALLOWED:
            return ActionOutcome(
                action_id=request.action_id,
                status="blocked_by_precondition",
                reason="scope_decision_not_allowed",
            )
        if request.engagement_id != session.engagement_id:
            return ActionOutcome(
                action_id=request.action_id,
                status="blocked_by_precondition",
                reason="session_engagement_mismatch",
            )
        if request.session_id != session.session_id:
            return ActionOutcome(
                action_id=request.action_id,
                status="blocked_by_precondition",
                reason="session_id_mismatch",
            )
        if session.expires_at <= datetime.now(timezone.utc):
            return ActionOutcome(
                action_id=request.action_id,
                status="blocked_by_precondition",
                reason="browser_session_expired",
            )
        if request.user_takeover_required:
            return ActionOutcome(
                action_id=request.action_id,
                status="needs_user_takeover",
                reason="explicit_user_takeover_required",
            )
        if request.operation not in allow_operations:
            return ActionOutcome(
                action_id=request.action_id,
                status="blocked_by_precondition",
                reason="browser_operation_not_allowlisted",
            )
        try:
            result = self._handler(request)
        except Exception as exc:
            raise RuntimeError(
                f"browser_handler_failure:{type(exc).__name__}"
            ) from exc
        if not isinstance(result, Mapping) or _contains_secret_key(result):
            return ActionOutcome(
                action_id=request.action_id,
                status="blocked_by_precondition",
                reason="adapter_output_not_redaction_safe",
            )
        clean, _ = redact_sensitive(dict(result))
        handler_status = str(clean.get("handler_status") or "completed")
        if handler_status != "completed":
            return ActionOutcome(
                action_id=request.action_id,
                status="blocked_by_precondition",
                reason=str(clean.get("reason") or "browser_handler_blocked")[:300],
                clean=False,
                observation=clean,
            )
        observation_ref = f"observation://browser/{_digest(clean)[7:23]}"
        return ActionOutcome(
            action_id=request.action_id,
            status="completed",
            observation_refs=(observation_ref,),
            reason="browser_action_completed_redacted",
            clean=False,
            observation=clean,
        )


class GmailAdapter:
    """Read-only injected mailbox adapter; outbound/security operations are denied."""

    def __init__(self, reader: Callable[[EmailCorrelationQuery], Mapping[str, Any] | None]) -> None:
        self._reader = reader
        self._seen_message_digests: set[str] = set()
        self._lock = RLock()

    def read_correlated(
        self,
        query: EmailCorrelationQuery,
        scope: EngagementScope,
    ) -> ParsedEmail:
        raw = self._reader(query)
        if raw is None:
            raise RuntimeError("mailbox_message_unavailable")
        if not isinstance(raw, Mapping):
            raise RuntimeError("mailbox_adapter_output_invalid")
        parsed = parse_email_message(raw, query, scope)
        message_id = str(raw.get("message_id") or "").strip()
        message_digest = _digest(message_id) if message_id else ""
        with self._lock:
            duplicate = bool(message_digest and message_digest in self._seen_message_digests)
            if message_digest:
                self._seen_message_digests.add(message_digest)
        if not duplicate:
            return parsed
        duplicate_event = parsed.event.model_copy(
            update={
                "artifact_ref": "",
                "confidence": 0.0,
                "status": "quarantined",
                "quarantined": True,
            }
        )
        return parsed.model_copy(
            update={
                "event": duplicate_event,
                "artifact": None,
                "quarantined": True,
                "reasons": (*parsed.reasons, "duplicate_message"),
            }
        )

    def __getattr__(self, name: str) -> Any:
        if name in {"send", "change_password", "change_recovery", "add_forwarding", "delete"}:
            raise AttributeError(f"gmail_operation_denied:{name}")
        raise AttributeError(name)


class WorkflowRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    workflow_id: str = Field(min_length=1, max_length=160)
    engagement_id: str = Field(min_length=1, max_length=160)
    identity_id: str = Field(min_length=1, max_length=160)
    session_id: str = Field(min_length=1, max_length=160)
    state: str = "created"
    completed_step_ids: tuple[str, ...] = ()
    idempotency_keys: tuple[str, ...] = ()
    application_intent_schema: str = ""
    application_intent_fingerprint: str = ""
    status: WorkflowStatus = WorkflowStatus.PENDING
    reason: str = ""


class WorkflowStateMachine:
    """Engagement/identity/session-bound, idempotent workflow transition machine."""

    def __init__(self) -> None:
        self._records: dict[str, WorkflowRecord] = {}
        self._lock = RLock()

    def start(
        self,
        *,
        workflow_id: str,
        engagement_id: str,
        identity: IdentityProfileRef,
        session: BrowserSessionRef,
        intent_model: Any | None = None,
    ) -> WorkflowRecord:
        if identity.engagement_id != engagement_id or session.engagement_id != engagement_id:
            raise ValueError("workflow_binding_mismatch")
        intent_schema, intent_fingerprint = _intent_binding(intent_model)
        record = WorkflowRecord(
            workflow_id=workflow_id,
            engagement_id=engagement_id,
            identity_id=identity.identity_id,
            session_id=session.session_id,
            application_intent_schema=intent_schema,
            application_intent_fingerprint=intent_fingerprint,
        )
        with self._lock:
            current = self._records.get(workflow_id)
            if current is not None:
                if (
                    current.application_intent_fingerprint
                    and intent_fingerprint
                    and current.application_intent_fingerprint != intent_fingerprint
                ):
                    raise ValueError("workflow_intent_mismatch")
                if not current.application_intent_fingerprint and intent_fingerprint:
                    current = current.model_copy(
                        update={
                            "application_intent_schema": intent_schema,
                            "application_intent_fingerprint": intent_fingerprint,
                        }
                    )
                    self._records[workflow_id] = current
                return current
            self._records[workflow_id] = record
        return record

    def apply(
        self,
        step: WorkflowStep,
        *,
        engagement_id: str,
        identity_id: str,
        session_id: str,
        idempotency_key: str,
        intent_model: Any | None = None,
    ) -> WorkflowRecord:
        with self._lock:
            current = self._records.get(step.workflow_id)
            if current is None:
                raise ValueError("workflow_not_found")
            if (current.engagement_id, current.identity_id, current.session_id) != (
                engagement_id,
                identity_id,
                session_id,
            ):
                raise ValueError("workflow_binding_mismatch")
            if current.application_intent_fingerprint:
                _, intent_fingerprint = _intent_binding(intent_model)
                if intent_fingerprint != current.application_intent_fingerprint:
                    updated = current.model_copy(
                        update={
                            "status": WorkflowStatus.BLOCKED,
                            "reason": "workflow_intent_mismatch",
                        }
                    )
                    self._records[step.workflow_id] = updated
                    return updated
            if idempotency_key in current.idempotency_keys:
                return current
            transition = step.expected_state_transition.split("->", 1)
            if len(transition) != 2 or current.state != transition[0].strip():
                updated = current.model_copy(
                    update={
                        "status": WorkflowStatus.BLOCKED,
                        "reason": "workflow_precondition_failed",
                    }
                )
                self._records[step.workflow_id] = updated
                return updated
            next_state = transition[1].strip()
            status = (
                WorkflowStatus.COMPLETED
                if next_state in {"completed", "authenticated"}
                else WorkflowStatus.RUNNING
            )
            updated = current.model_copy(
                update={
                    "state": next_state,
                    "completed_step_ids": (*current.completed_step_ids, step.step_id),
                    "idempotency_keys": (*current.idempotency_keys, idempotency_key),
                    "status": status,
                    "reason": "",
                }
            )
            self._records[step.workflow_id] = updated
            return updated

    def block(self, workflow_id: str, *, reason: str) -> WorkflowRecord:
        with self._lock:
            current = self._records.get(workflow_id)
            if current is None:
                raise ValueError("workflow_not_found")
            updated = current.model_copy(
                update={"status": WorkflowStatus.BLOCKED, "reason": str(reason)[:300]}
            )
            self._records[workflow_id] = updated
            return updated

    def resume(self, workflow_id: str, *, engagement_id: str) -> WorkflowRecord | None:
        with self._lock:
            record = self._records.get(workflow_id)
            if record is None or record.engagement_id != engagement_id:
                return None
            return record


class ControlPlaneProofInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    engagement_id: str = Field(min_length=1, max_length=160)
    finding_id: str = Field(min_length=1, max_length=160)
    hypothesis_id: str = Field(min_length=1, max_length=160)
    target_fingerprint: str = Field(min_length=1, max_length=200)
    scope_decision: ScopeDecision
    action_chain: tuple[str, ...] = Field(min_length=1, max_length=64)
    before_state: Mapping[str, Any]
    after_state: Mapping[str, Any]
    causal_signal: bool
    negative_control_complete: bool
    replayable: bool
    tool_versions: Mapping[str, str]
    input_hashes: tuple[str, ...] = ()
    output_hashes: tuple[str, ...] = ()
    cleanup_status: str = "complete"
    evidence: tuple[Any, ...] = Field(min_length=1, max_length=32)
    negative_control: Any
    evidence_refs: tuple[str, ...] = Field(min_length=1, max_length=32)
    validator_id: str = Field(min_length=1, max_length=120)
    validator_version: str = Field(min_length=1, max_length=80)
    target_package_id: str | None = Field(default=None, max_length=160)
    target_package_sha256: str | None = None
    target_package_scope_digest: str | None = None
    target_package_policy_digest: str | None = None

    @model_validator(mode="after")
    def _no_secrets(self) -> ControlPlaneProofInput:
        if _contains_secret_key(self.before_state) or _contains_secret_key(self.after_state):
            raise ValueError("proof_state_contains_secret")
        if self.scope_decision.decision != ScopeDecisionType.ALLOWED:
            raise ValueError("proof_scope_not_allowed")
        if not self.causal_signal or not self.negative_control_complete or not self.replayable:
            raise ValueError("proof_promotion_conditions_incomplete")
        return self


def seal_control_plane_proof(
    value: ControlPlaneProofInput,
    *,
    actor: str = "control-plane",
) -> ProofBundle:
    """Build and seal a proof bundle only after all strict inputs are present."""
    replay_metadata = {
        "replayable": value.replayable,
        "action_chain": list(value.action_chain),
        "before_state": dict(value.before_state),
        "after_state": dict(value.after_state),
        "tool_versions": dict(value.tool_versions),
        "input_hashes": list(value.input_hashes),
        "output_hashes": list(value.output_hashes),
    }
    bundle = build_proof_bundle(
        engagement_id=value.engagement_id,
        finding_id=value.finding_id,
        hypothesis_id=value.hypothesis_id,
        target_fingerprint=value.target_fingerprint,
        evidence=list(value.evidence),
        evidence_refs=list(value.evidence_refs),
        negative_control=value.negative_control,
        scope_context=value.scope_decision.model_dump(mode="json"),
        identity_context={"action_chain_digest": _digest(value.action_chain)},
        request_evidence=list(value.action_chain),
        response_evidence=list(value.output_hashes),
        baseline=dict(value.before_state),
        causal_oracle={
            "causal_signal": value.causal_signal,
            "negative_control_complete": value.negative_control_complete,
        },
        validator_id=value.validator_id,
        validator_version=value.validator_version,
        target_package_id=value.target_package_id,
        target_package_sha256=value.target_package_sha256,
        target_package_scope_digest=value.target_package_scope_digest,
        target_package_policy_digest=value.target_package_policy_digest,
        replay_metadata=replay_metadata,
        cleanup_status=value.cleanup_status,
    )
    return bundle.append_custody(actor=actor, action="control_plane_proof_ready").seal(actor=actor)


__all__ = [
    "BrowserActionAdapter",
    "project_browser_observation",
    "BrowserSessionManager",
    "ControlPlaneProofInput",
    "EmailArtifact",
    "EmailCorrelationQuery",
    "GmailAdapter",
    "ParsedEmail",
    "WorkflowRecord",
    "WorkflowStateMachine",
    "parse_email_message",
    "seal_control_plane_proof",
]
