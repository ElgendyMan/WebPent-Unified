"""Deterministic reliability gates for advisory LLM decisions.

The LLM is an untrusted planner. This module validates and sanitizes its
structured proposal, then applies the same scope/capability/budget vocabulary
used by the action authority. It never executes a request and never confirms a
finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from webpent.shared.redaction import redact_text

ReliabilityStatus = Literal["accepted", "needs_review", "rejected"]

_INJECTION_MARKERS = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "system message",
    "developer message",
    "reveal the prompt",
    "exfiltrate",
    "disable safety",
)

_SENSITIVE_METADATA_KEYS = {
    "authorization",
    "cookie",
    "cookies",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "session",
    "session_id",
}
_MAX_METADATA_DEPTH = 4
_MAX_METADATA_ITEMS = 32


def sanitize_untrusted_text(value: Any, *, limit: int = 1200) -> str:
    """Normalize untrusted model text without interpreting instructions."""
    text = redact_text(str(value or ""))
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
    return " ".join(text.split())[:limit]


def _sanitize_metadata(value: Any, *, depth: int = 0) -> Any:
    """Return bounded JSON-like metadata with sensitive fields redacted."""
    if depth > _MAX_METADATA_DEPTH:
        raise ValueError("metadata nesting exceeds safety limit")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return sanitize_untrusted_text(value, limit=400)
    if isinstance(value, dict):
        if len(value) > _MAX_METADATA_ITEMS:
            raise ValueError("metadata object exceeds safety limit")
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            if not isinstance(raw_key, str):
                raise ValueError("metadata keys must be strings")
            key = sanitize_untrusted_text(raw_key, limit=80).lower()
            if not key:
                raise ValueError("metadata keys must not be empty")
            if key in _SENSITIVE_METADATA_KEYS or any(
                marker in key for marker in ("password", "secret", "token", "cookie", "credential")
            ):
                result[key] = "[REDACTED]"
            else:
                result[key] = _sanitize_metadata(raw_value, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        if len(value) > _MAX_METADATA_ITEMS:
            raise ValueError("metadata list exceeds safety limit")
        return [_sanitize_metadata(item, depth=depth + 1) for item in value]
    raise ValueError("metadata contains a non-JSON value")


class LLMDecisionEnvelope(BaseModel):
    """Strict, bounded representation of an advisory LLM proposal."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: int = Field(default=1, ge=1, le=3)
    decision_id: str = Field(min_length=3, max_length=160)
    decision_type: Literal["research_action", "hypothesis", "triage", "report_advice"]
    action_class: str = Field(default="", max_length=80)
    target_ref: str = Field(default="", max_length=500)
    objective: str = Field(default="", max_length=500)
    untrusted_text: str = Field(default="", max_length=1200)
    required_capabilities: list[str] = Field(default_factory=list, max_length=12)
    estimated_cost: float = Field(default=1.0, ge=0.0, le=100000.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    requires_approval: bool = False
    active: bool = False
    destructive: bool = False
    causal_signal: bool = False
    negative_control_complete: bool = False
    evidence_refs: list[str] = Field(default_factory=list, max_length=30)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("untrusted_text", mode="before")
    @classmethod
    def _sanitize_text(cls, value: Any) -> str:
        return sanitize_untrusted_text(value)

    @field_validator("target_ref", "objective", "action_class", mode="before")
    @classmethod
    def _bound_strings(cls, value: Any) -> str:
        return sanitize_untrusted_text(value, limit=500)

    @field_validator("metadata", mode="before")
    @classmethod
    def _safe_metadata(cls, value: Any) -> dict[str, Any]:
        sanitized = _sanitize_metadata(value)
        if not isinstance(sanitized, dict):
            raise ValueError("metadata must be an object")
        return sanitized


@dataclass(frozen=True)
class ReliabilityPolicy:
    """Explicit policy inputs for one engagement."""

    allowed_origin: str
    available_capabilities: frozenset[str] = frozenset()
    max_cost: float = 100.0
    used_cost: float = 0.0
    allow_active: bool = False
    allow_destructive: bool = False
    require_approval_for_active: bool = True
    allowed_decision_types: frozenset[str] = frozenset(
        {"research_action", "hypothesis", "triage", "report_advice"}
    )


@dataclass(frozen=True)
class ReliabilityResult:
    """Auditable outcome of all deterministic reliability gates."""

    status: ReliabilityStatus
    envelope: LLMDecisionEnvelope | None
    reasons: tuple[str, ...] = ()
    stages: tuple[str, ...] = ()
    sanitized: bool = False
    trace: list[dict[str, str]] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.status == "accepted"


def _origin(value: str) -> str:
    try:
        parsed = urlsplit(str(value or "").strip())
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    port = parsed.port
    default = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
        parsed.scheme.lower() == "https" and port in {None, 443}
    )
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{'' if default else f':{port}'}"


def _has_injection_marker(text: str) -> bool:
    normalized = text.lower()
    return any(marker in normalized for marker in _INJECTION_MARKERS)


class LLMReliabilityGate:
    """Validate advisory model output without invoking tools or transports."""

    _STAGES = ("schema", "sanitization", "scope", "policy", "capability", "budget")

    def evaluate(self, payload: Any, policy: ReliabilityPolicy) -> ReliabilityResult:
        stages: list[str] = []
        trace: list[dict[str, str]] = []

        try:
            envelope = (
                payload
                if isinstance(payload, LLMDecisionEnvelope)
                else LLMDecisionEnvelope.model_validate(payload)
            )
        except ValidationError as exc:
            return ReliabilityResult(
                status="rejected",
                envelope=None,
                reasons=(f"schema:invalid:{len(exc.errors())}",),
                stages=("schema",),
                trace=[{"stage": "schema", "status": "rejected"}],
            )
        stages.append("schema")
        trace.append({"stage": "schema", "status": "passed"})

        clean_text = sanitize_untrusted_text(envelope.untrusted_text)
        sanitized = clean_text != envelope.untrusted_text
        reasons: list[str] = []
        if _has_injection_marker(clean_text):
            reasons.append("sanitization:instruction_like_content_in_untrusted_text")
        stages.append("sanitization")
        trace.append(
            {
                "stage": "sanitization",
                "status": "rejected" if reasons else "passed",
            }
        )

        target_origin = _origin(envelope.target_ref)
        allowed_origin = _origin(policy.allowed_origin)
        if target_origin != allowed_origin or not target_origin:
            reasons.append("scope:target_origin_mismatch")
        stages.append("scope")
        trace.append(
            {
                "stage": "scope",
                "status": "rejected" if target_origin != allowed_origin else "passed",
            }
        )

        if envelope.decision_type not in policy.allowed_decision_types:
            reasons.append("policy:decision_type_not_allowlisted")
        if envelope.destructive and not policy.allow_destructive:
            reasons.append("policy:destructive_decision_rejected")
        if envelope.active and not policy.allow_active:
            reasons.append("policy:active_decision_not_enabled")
        if (
            envelope.active
            and policy.require_approval_for_active
            and not envelope.requires_approval
        ):
            reasons.append("policy:active_decision_requires_approval")
        if envelope.causal_signal and not envelope.negative_control_complete:
            reasons.append("policy:causal_signal_requires_negative_control")
        if _has_injection_marker(envelope.objective):
            reasons.append("policy:instruction_like_objective_rejected")
        stages.append("policy")
        trace.append(
            {"stage": "policy", "status": "rejected" if reasons else "passed"}
        )

        missing = sorted(
            set(envelope.required_capabilities) - set(policy.available_capabilities)
        )
        if missing:
            reasons.append(f"capability:unavailable:{','.join(missing)[:240]}")
        stages.append("capability")
        trace.append(
            {
                "stage": "capability",
                "status": "rejected" if missing else "passed",
            }
        )

        if envelope.estimated_cost <= 0:
            reasons.append("budget:cost_must_be_positive")
        if policy.used_cost + envelope.estimated_cost > policy.max_cost:
            reasons.append("budget:engagement_limit_exceeded")
        stages.append("budget")
        trace.append(
            {
                "stage": "budget",
                "status": "rejected"
                if any(reason.startswith("budget:") for reason in reasons)
                else "passed",
            }
        )

        if reasons:
            status: ReliabilityStatus = (
                "needs_review"
                if any("approval" in reason for reason in reasons)
                and not any(
                    reason.startswith(("scope:", "capability:", "budget:"))
                    for reason in reasons
                )
                else "rejected"
            )
        else:
            status = "accepted"
        return ReliabilityResult(
            status=status,
            envelope=envelope,
            reasons=tuple(reasons),
            stages=tuple(stages),
            sanitized=sanitized,
            trace=trace,
        )


def llm_budget_allows(action_budget: Any, *, estimated_cost: float = 1.0) -> tuple[bool, str]:
    """Fail-closed check for optional LLM work within an engagement budget."""
    if not isinstance(action_budget, dict):
        return True, "budget:unbounded_legacy_state"
    remaining = action_budget.get("remaining_cost")
    if remaining is None:
        limit = float(action_budget.get("limit", 0.0) or 0.0)
        used = float(action_budget.get("used_cost", 0.0) or 0.0)
        remaining = limit - used
    try:
        allowed = float(remaining) >= float(estimated_cost) and float(remaining) > 0
    except (TypeError, ValueError):
        return False, "budget:invalid_remaining_cost"
    return (True, "budget:allowed") if allowed else (False, "budget:llm_exhausted")


__all__ = [
    "LLMDecisionEnvelope",
    "LLMReliabilityGate",
    "ReliabilityPolicy",
    "ReliabilityResult",
    "sanitize_untrusted_text",
    "llm_budget_allows",
]
