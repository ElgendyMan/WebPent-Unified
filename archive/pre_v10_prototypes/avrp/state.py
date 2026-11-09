"""Continuous, checkpoint-safe research state for AVRP.

The state is advisory telemetry. It does not authorize actions, execute I/O,
create findings, or mutate the existing campaign executor.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import canonical_json, redact_sensitive

_SCHEMA_VERSION = 1


def _clean(value: Any, limit: int = 500) -> str:
    clean, _ = redact_sensitive(str(value or ""))
    return " ".join(clean.split())[:limit]


def _clean_list(values: Sequence[Any], limit: int = 100) -> list[str]:
    return [_clean(value, 240) for value in values[:limit] if _clean(value, 240)]


def _timestamp(value: Any = None) -> str:
    if value:
        return _clean(value, 64)
    return datetime.now(UTC).replace(microsecond=0).isoformat()


class ResearchStateUpdate(BaseModel):
    """An auditable state delta; evidence and rationale are mandatory."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    update_id: str = Field(min_length=3, max_length=160)
    field_name: str = Field(min_length=3, max_length=80)
    value: Any
    evidence_refs: list[str] = Field(min_length=1, max_length=30)
    timestamp: str = Field(min_length=8, max_length=80)
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = Field(min_length=3, max_length=500)

    @field_validator(
        "update_id", "field_name", "evidence_refs", "timestamp", "reason", mode="before"
    )
    @classmethod
    def _redact(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple)):
            return _clean_list(value, 30)
        return _clean(value)

    def as_dict(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload["value"], _ = redact_sensitive(payload["value"])
        payload, _ = redact_sensitive(payload)
        return payload


class ResearchMemoryState(BaseModel):
    """Long-lived but explicitly scoped research memory.

    Every mutable item is represented by an update record, making snapshots
    deterministic and allowing a caller to replay or reject a delta without
    granting AVRP any authority over the campaign.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=_SCHEMA_VERSION, ge=1, le=10)
    target_ref: str = Field(min_length=3, max_length=500)
    engagement_id: str = Field(min_length=3, max_length=160)
    active_investigations: list[str] = Field(default_factory=list, max_length=100)
    completed_investigations: list[str] = Field(default_factory=list, max_length=100)
    rejected_paths: list[str] = Field(default_factory=list, max_length=200)
    unknown_areas: list[str] = Field(default_factory=list, max_length=200)
    high_value_assets: list[str] = Field(default_factory=list, max_length=200)
    security_assumptions: list[str] = Field(default_factory=list, max_length=200)
    research_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    updates: list[ResearchStateUpdate] = Field(default_factory=list, max_length=1000)

    @field_validator(
        "target_ref",
        "engagement_id",
        "active_investigations",
        "completed_investigations",
        "rejected_paths",
        "unknown_areas",
        "high_value_assets",
        "security_assumptions",
        mode="before",
    )
    @classmethod
    def _redact_fields(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple)):
            return _clean_list(value)
        return _clean(value)

    @staticmethod
    def _update_id(field_name: str, value: Any, evidence_refs: Sequence[str]) -> str:
        payload = {
            "field_name": _clean(field_name, 80),
            "value": str(value),
            "evidence_refs": sorted(_clean_list(evidence_refs, 30)),
        }
        return "state:" + hashlib.sha256(canonical_json(payload).encode()).hexdigest()[:24]

    @classmethod
    def new(cls, *, target_ref: str, engagement_id: str) -> ResearchMemoryState:
        """Create an empty isolated state; no target contact occurs."""
        return cls(target_ref=_clean(target_ref), engagement_id=_clean(engagement_id))

    def apply_update(
        self,
        *,
        field_name: str,
        value: Any,
        evidence_refs: Sequence[str],
        confidence: float,
        reason: str,
        timestamp: str | None = None,
    ) -> ResearchMemoryState:
        """Return a new state after validating an explicit evidence-backed delta."""
        if not evidence_refs or not all(_clean(item, 240) for item in evidence_refs):
            raise ValueError("state update requires non-empty evidence_refs")
        if not _clean(reason, 500):
            raise ValueError("state update requires a reason")
        if not 0.0 <= float(confidence) <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        allowed = {
            "active_investigations",
            "completed_investigations",
            "rejected_paths",
            "unknown_areas",
            "high_value_assets",
            "security_assumptions",
            "research_confidence",
        }
        if field_name not in allowed:
            raise ValueError(f"unsupported research state field: {field_name}")
        update = ResearchStateUpdate(
            update_id=self._update_id(field_name, value, evidence_refs),
            field_name=field_name,
            value=value,
            evidence_refs=list(evidence_refs),
            timestamp=_timestamp(timestamp),
            confidence=confidence,
            reason=reason,
        )
        if any(item.update_id == update.update_id for item in self.updates):
            return self
        data = self.model_dump(mode="python")
        data["updates"] = [*self.updates, update]
        if field_name == "research_confidence":
            data[field_name] = float(confidence)
        elif isinstance(value, (list, tuple)):
            data[field_name] = _clean_list(value)
        else:
            data[field_name] = [*_clean_list(getattr(self, field_name), 200), _clean(value, 240)]
        return type(self).model_validate(data)

    def snapshot(self) -> dict[str, Any]:
        """Return a deterministic redacted snapshot with an integrity hash."""
        payload = self.model_dump(mode="json")
        payload["updates"] = [item.as_dict() for item in self.updates]
        payload, _ = redact_sensitive(payload)
        payload["snapshot_hash"] = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
        return payload

    @classmethod
    def restore(
        cls,
        snapshot: Mapping[str, Any],
        *,
        expected_target_ref: str | None = None,
        expected_engagement_id: str | None = None,
    ) -> ResearchMemoryState:
        """Restore only a compatible, integrity-checked, isolated snapshot."""
        data = dict(snapshot)
        supplied_hash = str(data.pop("snapshot_hash", ""))
        if not supplied_hash:
            raise ValueError("snapshot_hash is required")
        clean, _ = redact_sensitive(data)
        calculated = hashlib.sha256(canonical_json(clean).encode()).hexdigest()
        if supplied_hash != calculated:
            raise ValueError("snapshot integrity mismatch")
        if int(clean.get("schema_version", 0)) != _SCHEMA_VERSION:
            raise ValueError("unsupported research state schema version")
        if expected_target_ref and clean.get("target_ref") != expected_target_ref:
            raise ValueError("target isolation mismatch")
        if expected_engagement_id and clean.get("engagement_id") != expected_engagement_id:
            raise ValueError("engagement isolation mismatch")
        return cls.model_validate(clean)


@dataclass(frozen=True)
class StateTransition:
    """Report-safe before/after state transition metadata."""

    update_id: str
    field_name: str
    status: str
    evidence_refs: tuple[str, ...]
    confidence: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "update_id": self.update_id,
            "field_name": self.field_name,
            "status": self.status,
            "evidence_refs": list(self.evidence_refs),
            "confidence": self.confidence,
            "advisory_only": True,
        }


__all__ = ["ResearchMemoryState", "ResearchStateUpdate", "StateTransition"]
