"""Bounded attack-surface intelligence for ASROS.

This module ranks already-known target surfaces.  It does not discover by
network, create requests, grant authority, or turn a score into a finding.
All inputs are target-scoped and evidence-linked projections.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from webpent.models.evidence import redact_sensitive


class SurfaceKind(str, Enum):
    ENDPOINT = "endpoint"
    API = "api"
    FUNCTION = "function"
    WORKFLOW = "workflow"
    OBJECT = "object"


class SurfaceSignal(BaseModel):
    """One bounded scoring input with explicit provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=120)
    value: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    source: str = Field(min_length=1, max_length=160)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(str(value).strip()[:240] for value in values if str(value).strip())
        )


class AttackSurfaceItem(BaseModel):
    """A rankable surface projection, never an executable action."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    surface_id: str = Field(min_length=3, max_length=240)
    kind: SurfaceKind
    canonical_name: str = Field(min_length=1, max_length=320)
    target_id: str = Field(min_length=1, max_length=200)
    signals: tuple[SurfaceSignal, ...] = Field(default=(), max_length=32)
    required_capability: str = Field(default="analysis", min_length=1, max_length=120)
    scope_allowed: bool = False
    execution_capability: bool = False
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)

    @field_validator("canonical_name", "target_id")
    @classmethod
    def _redact_identity(cls, value: str) -> str:
        clean, _ = redact_sensitive(value)
        return clean[:320]

    @field_validator("evidence_refs")
    @classmethod
    def _unique_evidence(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(str(value).strip()[:240] for value in values if str(value).strip())
        )

    @model_validator(mode="after")
    def _cannot_execute(self) -> AttackSurfaceItem:
        if self.execution_capability:
            raise ValueError("attack_surface_cannot_grant_execution")
        return self

    def score(self) -> float:
        """Return a deterministic advisory priority score in [0, 1]."""
        weights = {
            "business_impact": 0.22,
            "privilege_sensitivity": 0.18,
            "data_sensitivity": 0.18,
            "complexity": 0.12,
            "unknown_behavior": 0.18,
            "previous_evidence": 0.12,
        }
        values = {signal.name: signal.value for signal in self.signals}
        score = sum(weight * values.get(name, 0.0) for name, weight in weights.items())
        if not self.scope_allowed:
            score *= 0.0
        return round(min(max(score, 0.0), 1.0), 6)

    def ranking_key(self) -> tuple[float, str]:
        return (-self.score(), self.surface_id)


class DynamicResearchMap(BaseModel):
    """Deterministic ranked map of surfaces for advisory research planning."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: int = Field(default=1, frozen=True)
    target_id: str = Field(min_length=1, max_length=200)
    surfaces: tuple[AttackSurfaceItem, ...] = Field(default=(), max_length=2_000)
    ranked_surface_ids: tuple[str, ...] = Field(default=(), max_length=2_000)
    generated_from: tuple[str, ...] = Field(default=(), max_length=64)
    authoritative: bool = False
    execution_capability: bool = False

    @model_validator(mode="after")
    def _consistent(self) -> DynamicResearchMap:
        ids = [item.surface_id for item in self.surfaces]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate_attack_surface_id")
        expected = tuple(
            item.surface_id for item in sorted(self.surfaces, key=AttackSurfaceItem.ranking_key)
        )
        if self.ranked_surface_ids and self.ranked_surface_ids != expected:
            raise ValueError("attack_surface_rank_order_mismatch")
        if self.authoritative or self.execution_capability:
            raise ValueError("research_map_cannot_grant_authority")
        return self

    @classmethod
    def build(
        cls,
        *,
        target_id: str,
        surfaces: tuple[AttackSurfaceItem, ...] | list[AttackSurfaceItem] = (),
        generated_from: tuple[str, ...] | list[str] = (),
    ) -> DynamicResearchMap:
        ordered = tuple(sorted(surfaces, key=AttackSurfaceItem.ranking_key))
        return cls(
            target_id=target_id,
            surfaces=ordered,
            ranked_surface_ids=tuple(item.surface_id for item in ordered),
            generated_from=tuple(
                dict.fromkeys(str(item)[:240] for item in generated_from if str(item).strip())
            ),
        )

    def content_hash(self) -> str:
        payload = self.model_dump(mode="json")
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode()).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


__all__ = ["AttackSurfaceItem", "DynamicResearchMap", "SurfaceKind", "SurfaceSignal"]
