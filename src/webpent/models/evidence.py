"""Canonical evidence contracts for additive tool integration.

The existing WebPent agents return heterogeneous values (JSONL records, URL
lists, and raw text).  This module provides a small, serialisable contract
that can be populated beside those values without changing their public
return types.  It deliberately stores references and hashes for raw output,
not raw credentials, cookies, tokens, or passwords.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

ExecutionStatus = Literal[
    "success",
    "partial",
    "failed",
    "empty",
    "blocked",
    "not_run",
]
ScopeDecision = Literal["allowed", "denied", "unknown", "not_checked", "off_scope"]
RedactionStatus = Literal["clean", "redacted", "not_applicable"]
RelationStatus = Literal["observed", "inconclusive", "needs_review", "confirmed"]

_SENSITIVE_KEYS = re.compile(
    r"(?:^|[_-])(?:authorization|cookie|set-cookie|token|secret|password|passwd|"
    r"api[_-]?key|access[_-]?key|client[_-]?secret|session|credential|jwt|"
    r"raw[_-]?(?:request|response)[_-]?body|(?:request|response)[_-]?body|"
    r"screenshot|dom(?:[_-]snapshot)?|html[_-]?body)(?:$|[_-])",
    re.IGNORECASE,
)
_SENSITIVE_TEXT = (
    (re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(cookie\s*:\s*)[^\r\n]+"), r"\1[REDACTED]"),
    (
        re.compile(
            r"(?i)([?&](?:token|api[_-]?key|password|secret|session|jwt)=)"
            r"[^&#\s]+"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)([\"'](?:token|secret|password|api[_-]?key|session)"
            r"[\"']\s*:\s*[\"'])[^\"']*([\"'])"
        ),
        r"\1[REDACTED]\2",
    ),
)


def _redact_text(value: str) -> tuple[str, bool]:
    redacted = value
    changed = False
    for pattern, replacement in _SENSITIVE_TEXT:
        redacted, count = pattern.subn(replacement, redacted)
        changed = changed or count > 0
    return redacted, changed


def redact_sensitive(value: Any, *, key_hint: str = "") -> tuple[Any, bool]:
    """Recursively redact secret-shaped values and return ``(value, changed)``."""
    if _SENSITIVE_KEYS.search(key_hint):
        return "[REDACTED]", True
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, dict):
        changed = False
        clean: dict[str, Any] = {}
        for key, item in value.items():
            clean_item, item_changed = redact_sensitive(item, key_hint=str(key))
            clean[str(key)] = clean_item
            changed = changed or item_changed
        return clean, changed
    if isinstance(value, (list, tuple, set)):
        clean_items = []
        changed = False
        for item in value:
            clean_item, item_changed = redact_sensitive(item)
            clean_items.append(clean_item)
            changed = changed or item_changed
        return clean_items, changed
    return value, False


def _json_safe(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    return str(value)


def canonical_json(value: Any) -> str:
    """Return deterministic JSON suitable for hashes and evidence IDs."""
    return json.dumps(_json_safe(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def command_fingerprint(command: Sequence[str] | None) -> str | None:
    """Hash a redacted argv; never retain the command or its arguments."""
    if not command:
        return None
    redacted, _ = redact_sensitive([str(part) for part in command])
    return f"sha256:{sha256_text(redacted)}"


def _timestamp(value: datetime | str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class EvidenceRef(BaseModel):
    """A redacted pointer to evidence retained outside structured state."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    id: str = Field(default_factory=lambda: f"evref_{uuid4().hex}", min_length=1)
    kind: str = Field(default="observation", min_length=1)
    digest: str = Field(..., pattern=r"^sha256:[0-9a-f]{64}$")
    locator: str = Field(..., min_length=1, max_length=500)
    size_bytes: int | None = Field(default=None, ge=0)
    redaction_status: RedactionStatus = "clean"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata", mode="before")
    @classmethod
    def _redact_metadata(cls, value: Any) -> dict[str, Any]:
        clean, _ = redact_sensitive(value if isinstance(value, dict) else {})
        return clean


class Observation(BaseModel):
    """A normalized, evidence-backed observation emitted by a tool adapter."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    id: str = Field(default_factory=lambda: f"obs_{uuid4().hex}", min_length=1)
    target: str = Field(..., min_length=1)
    asset: str | None = None
    endpoint: str | None = None
    method: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tool_name: str = Field(..., min_length=1)
    tool_version: str = Field(default="unknown", min_length=1)
    status: ExecutionStatus = "success"
    value: Any = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    scope_decision: ScopeDecision = "not_checked"
    redaction_status: RedactionStatus = "clean"
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target", "asset", "endpoint", "method", mode="before")
    @classmethod
    def _redact_scalar(cls, value: Any) -> Any:
        if value is None:
            return None
        clean, _ = redact_sensitive(str(value))
        return clean

    @field_validator("parameters", "value", "metadata", mode="before")
    @classmethod
    def _redact_complex(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class RelationalEvidence(BaseModel):
    """A normalized edge linking two observations or security surfaces.

    Relational evidence is deliberately separate from :class:`Finding`.
    It records a reproducible relationship (for example, an identity-to-
    resource differential or a finding-to-workflow link), but it is not proof
    of a vulnerability by itself. Promotion requires a downstream validator
    or explicit human review.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    id: str = Field(default_factory=lambda: f"rel_{uuid4().hex}", min_length=1)
    type: str = Field(default="related", min_length=1, max_length=120)
    relation_type: str | None = Field(default=None, max_length=120)
    source_id: str | None = Field(default=None, max_length=300)
    target_id: str | None = Field(default=None, max_length=300)
    source_finding_id: str | None = Field(default=None, max_length=300)
    target_finding_id: str | None = Field(default=None, max_length=300)
    resource_url: str | None = Field(default=None, max_length=2048)
    object_id: str | None = Field(default=None, max_length=300)
    from_identity: str | None = Field(default=None, max_length=200)
    to_identity: str | None = Field(default=None, max_length=200)
    from_accessible: bool | None = None
    to_accessible: bool | None = None
    owner_identity: str | None = Field(default=None, max_length=200)
    differential: bool = False
    status: RelationStatus = "observed"
    confidence_level: str = Field(default="Needs Human Review", max_length=80)
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "source_id",
        "target_id",
        "source_finding_id",
        "target_finding_id",
        "resource_url",
        "object_id",
        "from_identity",
        "to_identity",
        "owner_identity",
        mode="before",
    )
    @classmethod
    def _redact_relation_scalar(cls, value: Any) -> Any:
        if value is None:
            return None
        clean, _ = redact_sensitive(str(value))
        return clean

    @field_validator("evidence_refs", "metadata", mode="before")
    @classmethod
    def _redact_relation_complex(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class ToolExecution(BaseModel):
    """Normalized execution metadata with no raw command or raw output."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    id: str = Field(default_factory=lambda: f"exec_{uuid4().hex}", min_length=1)
    tool_name: str = Field(..., min_length=1)
    tool_version: str = Field(default="unknown", min_length=1)
    target: str = Field(..., min_length=1)
    asset: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    command_fingerprint: str | None = None
    started_at: datetime
    finished_at: datetime
    status: ExecutionStatus = "success"
    return_code: int | None = None
    timeout_seconds: float | None = Field(default=None, ge=0.0)
    raw_output_ref: EvidenceRef | None = None
    raw_output_bytes: int | None = Field(default=None, ge=0)
    scope_decision: ScopeDecision = "not_checked"
    redaction_status: RedactionStatus = "clean"
    error_class: str | None = None

    @field_validator("target", "asset", mode="before")
    @classmethod
    def _redact_target(cls, value: Any) -> Any:
        if value is None:
            return None
        clean, _ = redact_sensitive(str(value))
        return clean

    @field_validator("parameters", mode="before")
    @classmethod
    def _redact_parameters(cls, value: Any) -> dict[str, Any]:
        clean, _ = redact_sensitive(value if isinstance(value, dict) else {})
        return clean


class NormalizedArtifact(BaseModel):
    """A stable, redacted artifact extracted from an observation."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)

    id: str = Field(default_factory=lambda: f"artifact_{uuid4().hex}", min_length=1)
    artifact_type: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    identity_key: str = Field(..., min_length=1)
    source_observation_id: str = Field(..., min_length=1)
    value: Any = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    redaction_status: RedactionStatus = "clean"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("value", "metadata", mode="before")
    @classmethod
    def _redact_artifact(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean


class AdapterResult(BaseModel):
    """Serializable result returned by a canonical adapter facade."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    execution: ToolExecution
    observations: list[Observation] = Field(default_factory=list)
    artifacts: list[NormalizedArtifact] = Field(default_factory=list)
    error: str | None = None

    def to_state(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def make_evidence_ref(
    raw_output: Any,
    *,
    locator: str,
    kind: str = "tool_output",
) -> EvidenceRef:
    """Create a digest-only evidence reference after redaction."""
    clean, changed = redact_sensitive(raw_output)
    serialized = canonical_json(clean)
    digest = f"sha256:{hashlib.sha256(serialized.encode('utf-8')).hexdigest()}"
    return EvidenceRef(
        kind=kind,
        digest=digest,
        locator=locator,
        size_bytes=len(serialized.encode("utf-8")),
        redaction_status="redacted" if changed else "clean",
    )
