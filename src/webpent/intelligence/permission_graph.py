"""Permission graph projections used for authorization research planning."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PermissionObservation(BaseModel):
    """An observed access relation, never an authorization grant."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    principal_id: str = Field(..., min_length=1, max_length=160)
    resource_id: str = Field(..., min_length=1, max_length=160)
    action: str = Field(..., min_length=1, max_length=120)
    access: Literal["allow", "deny", "unknown"] = "unknown"
    role_id: str | None = Field(default=None, max_length=160)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_refs(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))


class PermissionGraph(BaseModel):
    """Target-scoped authorization observations for matrix planning."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: int = 1
    engagement_id: str = Field(..., min_length=1, max_length=200)
    target_id: str = Field(..., min_length=1, max_length=200)
    observations: list[PermissionObservation] = Field(default_factory=list, max_length=512)

    def add_observation(self, observation: PermissionObservation) -> None:
        if observation not in self.observations:
            self.observations.append(observation)

    def matrix(self) -> dict[str, dict[str, str]]:
        """Return a stable principal/resource/action summary for planning."""
        result: dict[str, dict[str, str]] = {}
        for observation in self.observations:
            key = f"{observation.principal_id}:{observation.resource_id}"
            result.setdefault(key, {})[observation.action] = observation.access
        return result

    def evidence_refs(self) -> list[str]:
        return sorted({ref for item in self.observations for ref in item.evidence_refs})[:64]


__all__ = ["PermissionGraph", "PermissionObservation"]
