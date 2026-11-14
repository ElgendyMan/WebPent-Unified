"""Application-level model primitives for the additive Target Brain.

These models describe observations and planning metadata only.  They do not
store secrets, raw bodies, payloads, cookies, or executable actions.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ApplicationAsset(BaseModel):
    """A bounded application asset observed during an authorized engagement."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    asset_id: str = Field(..., min_length=1, max_length=160)
    kind: Literal[
        "host",
        "identity",
        "role",
        "object",
        "order",
        "invoice",
        "payment",
        "document",
        "endpoint",
        "service",
        "other",
    ]
    name: str = Field(..., min_length=1, max_length=200)
    identifier: str | None = Field(default=None, max_length=500)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_refs(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))


class ApplicationModel(BaseModel):
    """Target-scoped inventory of application assets."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: int = 1
    engagement_id: str = Field(..., min_length=1, max_length=200)
    target_id: str = Field(..., min_length=1, max_length=200)
    assets: dict[str, ApplicationAsset] = Field(default_factory=dict)

    def add_asset(self, asset: ApplicationAsset) -> None:
        """Add or merge an asset without mixing identifiers or evidence."""
        current = self.assets.get(asset.asset_id)
        if current is None:
            self.assets[asset.asset_id] = asset
            return
        if current.kind != asset.kind or current.name != asset.name:
            raise ValueError("asset_identity_conflict")
        self.assets[asset.asset_id] = current.model_copy(
            update={
                "identifier": asset.identifier or current.identifier,
                "evidence_refs": list(dict.fromkeys(current.evidence_refs + asset.evidence_refs)),
                "confidence": max(current.confidence, asset.confidence),
            }
        )

    def evidence_refs(self) -> list[str]:
        """Return a stable report-safe evidence projection."""
        return sorted({ref for asset in self.assets.values() for ref in asset.evidence_refs})[:64]


__all__ = ["ApplicationAsset", "ApplicationModel"]
