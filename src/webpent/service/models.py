"""Typed, redaction-safe contracts for the multi-campaign product layer."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean(value: Any, limit: int = 240) -> str:
    return str(value or "").strip()[:limit]

_SAFE_CAMPAIGN_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,127})$")
_SENSITIVE_METADATA_KEYS = (
    "password", "passwd", "secret", "token", "cookie", "authorization",
    "api_key", "apikey", "credentials", "credential", "vault", "private_key",
)


def sanitize_metadata(value: Any, *, key: str = "") -> Any:
    """Recursively remove secret-bearing metadata before it reaches SQLite."""
    lowered = str(key).lower()
    if any(marker in lowered for marker in _SENSITIVE_METADATA_KEYS):
        return None
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for child_key, child_value in value.items():
            cleaned = sanitize_metadata(child_value, key=str(child_key))
            if cleaned is not None:
                result[str(child_key)[:80]] = cleaned
        return result
    if isinstance(value, (list, tuple)):
        return [cleaned for item in value if (cleaned := sanitize_metadata(item, key=key)) is not None][:100]
    if isinstance(value, str):
        return value[:1000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:1000]


def validate_campaign_id(value: str) -> str:
    text = str(value or "").strip()
    if not _SAFE_CAMPAIGN_ID.fullmatch(text) or text in {".", ".."} or ".." in text:
        raise ValueError("campaign_id_invalid_safe_slug")
    return text


class CampaignLifecycle(StrEnum):
    PLANNED = "PLANNED"
    RUNNING = "RUNNING"
    OPERATOR_HALTED = "OPERATOR_HALTED"
    COMPLETED = "COMPLETED"


class FindingLifecycle(StrEnum):
    CANDIDATE = "candidate"
    PROMOTED = "promoted"
    REFUTED = "refuted"
    NEEDS_HUMAN_REVIEW = "needs-human-review"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class CampaignSpec:
    campaign_id: str
    target_url: str
    owner_id: str = "operator"
    budget_limit: float = 10.0
    max_actions: int = 100
    retry_limit: int = 2
    window_start: str | None = None
    window_end: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        parsed = urlsplit(self.target_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("campaign_target_url_invalid")
        object.__setattr__(self, "campaign_id", validate_campaign_id(self.campaign_id))
        object.__setattr__(self, "metadata", sanitize_metadata(self.metadata))
        if float(self.budget_limit) <= 0:
            raise ValueError("campaign_budget_must_be_positive")
        if int(self.max_actions) <= 0:
            raise ValueError("campaign_max_actions_must_be_positive")
        if int(self.retry_limit) < 0 or int(self.retry_limit) > 10:
            raise ValueError("campaign_retry_limit_out_of_range")

    @property
    def target_origin(self) -> str:
        parsed = urlsplit(self.target_url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": _clean(self.campaign_id, 128),
            "target_url": _clean(self.target_url, 1000),
            "target_origin": _clean(self.target_origin, 300),
            "owner_id": _clean(self.owner_id, 128),
            "budget_limit": round(float(self.budget_limit), 6),
            "max_actions": int(self.max_actions),
            "retry_limit": int(self.retry_limit),
            "window_start": self.window_start,
            "window_end": self.window_end,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class CampaignSnapshot:
    campaign_id: str
    run_id: str
    state: str
    target_url: str
    owner_id: str
    budget_limit: float
    used_budget: float
    used_actions: int
    vault_namespace: str
    audit_namespace: str
    retry_count: int
    retry_limit: int
    last_error: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)
    last_rejection: dict[str, Any] | None = None
    updated_at: str = field(default_factory=_now)

    @property
    def budget_ratio(self) -> float:
        if self.budget_limit <= 0:
            return 1.0
        return min(1.0, max(0.0, self.used_budget / self.budget_limit))

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["budget_ratio"] = round(self.budget_ratio, 6)
        return result


@dataclass(frozen=True)
class FindingEvent:
    campaign_id: str
    finding_id: str
    status: str
    severity: str = "unknown"
    title: str = ""
    evidence_ref: str = ""
    cost: float = 0.0
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now)

    @property
    def idempotency_key(self) -> str:
        raw = f"{self.campaign_id}:{self.finding_id}:{self.status}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def redacted_payload(self) -> dict[str, Any]:
        safe = {
            "event": "webpent_finding_lifecycle",
            "campaign_id": _clean(self.campaign_id, 128),
            "finding_id": _clean(self.finding_id, 160),
            "status": _clean(self.status, 64),
            "severity": _clean(self.severity, 32),
            "title": _clean(self.title, 300),
            "evidence_ref": _clean(self.evidence_ref, 160),
            "cost": round(max(0.0, float(self.cost)), 6),
            "created_at": self.created_at,
        }
        for key in ("vulnerability_type", "vuln_class", "route", "cvss_score"):
            value = self.payload.get(key)
            if value is not None:
                safe[key] = _clean(value, 1000 if key == "route" else 160)
        return safe


@dataclass(frozen=True)
class AlertEvent:
    campaign_id: str
    kind: str
    payload: dict[str, Any]
    idempotency_key: str
    created_at: str = field(default_factory=_now)


@dataclass(frozen=True)
class SchedulerJob:
    job_id: str
    campaign_id: str
    due_at: str
    window_start: str | None
    window_end: str | None
    retry_limit: int
    attempts: int = 0
    status: str = "scheduled"
    last_error: str = ""


@dataclass(frozen=True)
class HealthRun:
    run_id: str
    gate_name: str
    exit_code: int
    ok: bool
    output_digest: str
    output_preview: str
    started_at: str
    ended_at: str
    source_digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "AlertEvent",
    "CampaignLifecycle",
    "CampaignSnapshot",
    "CampaignSpec",
    "FindingEvent",
    "FindingLifecycle",
    "HealthRun",
    "SchedulerJob",
    "canonical_json",
    "sanitize_metadata",
    "validate_campaign_id",
]
