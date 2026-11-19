"""Bounded, serializable state for an autonomous research campaign."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from webpent.research_engine.research_budget import ResearchBudget

_SECRET_KEYS = {
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "cookie",
    "authorization",
    "payload",
    "body",
}


def _reject_secret_like(value: Any, path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in _SECRET_KEYS:
                raise ValueError(f"unsafe_campaign_field:{path}{key}")
            _reject_secret_like(child, f"{path}{key}.")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_secret_like(child, f"{path}{index}.")


class CampaignLineage(BaseModel):
    """Immutable checkpoint provenance for one campaign state."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    parent_snapshot_digest: str = Field(default="", pattern=r"^(|[0-9a-f]{64})$")
    event_id: str = Field(default="initial", min_length=1, max_length=160)
    sequence: int = Field(default=0, ge=0)
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CampaignState(BaseModel):
    """Target- and engagement-scoped bounded campaign checkpoint."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: int = Field(default=1, ge=1)
    campaign_id: str = Field(min_length=1, max_length=160)
    target_identity: str = Field(min_length=1, max_length=160)
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    knowledge_model_version: str = Field(default="target-knowledge-v2", min_length=1, max_length=80)
    current_objectives: tuple[str, ...] = Field(default=(), max_length=64)
    research_budget: ResearchBudget = Field(default_factory=ResearchBudget)
    time_budget: int = Field(default=0, ge=0, le=86_400_000)
    completed_tasks: tuple[str, ...] = Field(default=(), max_length=10_000)
    failed_tasks: tuple[str, ...] = Field(default=(), max_length=10_000)
    blocked_tasks: tuple[str, ...] = Field(default=(), max_length=10_000)
    active_hypotheses: tuple[str, ...] = Field(default=(), max_length=10_000)
    discovered_assets: tuple[str, ...] = Field(default=(), max_length=10_000)
    evidence_summary: dict[str, str] = Field(default_factory=dict, max_length=128)
    lineage: CampaignLineage = Field(default_factory=CampaignLineage)

    @field_validator(
        "current_objectives",
        "completed_tasks",
        "failed_tasks",
        "blocked_tasks",
        "active_hypotheses",
        "discovered_assets",
    )
    @classmethod
    def _safe_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        clean = tuple(str(value).strip()[:240] for value in values if str(value).strip())
        _reject_secret_like(clean)
        return clean

    @field_validator("evidence_summary")
    @classmethod
    def _safe_summary(cls, value: dict[str, str]) -> dict[str, str]:
        _reject_secret_like(value)
        return {str(key)[:120]: str(item)[:400] for key, item in value.items()}

    @model_validator(mode="after")
    def _disjoint_task_buckets(self) -> CampaignState:
        buckets = [set(self.completed_tasks), set(self.failed_tasks), set(self.blocked_tasks)]
        if any(
            left & right for index, left in enumerate(buckets) for right in buckets[index + 1 :]
        ):
            raise ValueError("campaign_task_status_overlap")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=False)

    def canonical_json(self) -> str:
        return json.dumps(
            self.canonical_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )

    def snapshot(self) -> str:
        """Return deterministic JSON without filesystem or network I/O."""
        return self.canonical_json()

    @classmethod
    def restore(cls, snapshot: str) -> CampaignState:
        if not isinstance(snapshot, str) or len(snapshot) > 2_000_000:
            raise ValueError("invalid_campaign_snapshot")
        try:
            decoded = json.loads(snapshot)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid_campaign_snapshot") from exc
        if not isinstance(decoded, dict) or decoded.get("schema_version") != 1:
            raise ValueError("unsupported_campaign_snapshot_schema")
        _reject_secret_like(decoded)
        return cls.model_validate(decoded)

    def snapshot_digest(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def evolve(self, *, event_id: str, **updates: Any) -> CampaignState:
        """Create a new checkpoint linked to this state."""
        clean_event = event_id.strip()[:160]
        if not clean_event:
            raise ValueError("empty_campaign_event_id")
        next_lineage = CampaignLineage(
            parent_snapshot_digest=self.snapshot_digest(),
            event_id=clean_event,
            sequence=self.lineage.sequence + 1,
        )
        return self.model_copy(update={**updates, "lineage": next_lineage})

    def mark_task(
        self, task_id: str, status: Literal["completed", "failed", "blocked"]
    ) -> CampaignState:
        clean = task_id.strip()[:160]
        if not clean:
            raise ValueError("empty_campaign_task_id")
        updates: dict[str, Any] = {
            "completed_tasks": tuple(item for item in self.completed_tasks if item != clean),
            "failed_tasks": tuple(item for item in self.failed_tasks if item != clean),
            "blocked_tasks": tuple(item for item in self.blocked_tasks if item != clean),
        }
        bucket_name = f"{status}_tasks"
        current = getattr(self, bucket_name)
        updates[bucket_name] = tuple(item for item in current if item != clean) + (clean,)
        return self.evolve(event_id=f"task:{status}:{clean}", **updates)


__all__ = ["CampaignLineage", "CampaignState"]
