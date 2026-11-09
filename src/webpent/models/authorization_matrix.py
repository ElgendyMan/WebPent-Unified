"""Typed, report-safe authorization comparison matrix models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

AccessExpectation = Literal["allow", "deny", "unknown"]
OwnershipRelation = Literal["owner", "non_owner", "unknown"]
ComparisonKind = Literal["horizontal", "vertical", "ownership_differential", "same_role"]


class AuthorizationMatrixRow(BaseModel):
    """One identity/object/endpoint/method observation without credentials."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True, str_strip_whitespace=True)

    identity_ref: str = Field(..., min_length=1, max_length=128)
    role: str = Field(default="unknown", min_length=1, max_length=80)
    object_ref: str | None = Field(default=None, max_length=160)
    endpoint: str = Field(..., min_length=1, max_length=1000)
    method: str = Field(default="GET", min_length=1, max_length=16)
    ownership_relation: OwnershipRelation = "unknown"
    expected_access: AccessExpectation = "unknown"
    observed_access: bool
    status_code: int = Field(..., ge=0, le=999)
    response_fingerprint: str = Field(..., min_length=1, max_length=128)
    evidence_refs: list[str] = Field(default_factory=list, max_length=16)
    redacted: bool = True

    @field_validator("method", mode="before")
    @classmethod
    def _normalise_method(cls, value: object) -> str:
        return str(value or "GET").upper()[:16]


class AuthorizationComparison(BaseModel):
    """Pairwise differential for two identities on the same resource."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True, str_strip_whitespace=True)

    left_identity_ref: str = Field(..., min_length=1, max_length=128)
    right_identity_ref: str = Field(..., min_length=1, max_length=128)
    left_role: str = Field(default="unknown", min_length=1, max_length=80)
    right_role: str = Field(default="unknown", min_length=1, max_length=80)
    object_ref: str | None = Field(default=None, max_length=160)
    endpoint: str = Field(..., min_length=1, max_length=1000)
    method: str = Field(default="GET", min_length=1, max_length=16)
    comparison_kind: ComparisonKind
    access_differential: bool
    status_differential: bool
    fingerprint_differential: bool
    owner_identity_ref: str | None = None
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    redacted: bool = True


class AuthorizationMatrix(BaseModel):
    """Deterministic matrix projection and explicit coverage accounting."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True, str_strip_whitespace=True)

    version: str = "1"
    identities: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    objects: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    rows: list[AuthorizationMatrixRow] = Field(default_factory=list)
    comparisons: list[AuthorizationComparison] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list)
    redaction: str = "credentials_and_raw_bodies_omitted"

    @property
    def confirmed_differential_count(self) -> int:
        return sum(
            1
            for comparison in self.comparisons
            if comparison.access_differential and comparison.owner_identity_ref
        )


__all__ = [
    "AuthorizationComparison",
    "AuthorizationMatrix",
    "AuthorizationMatrixRow",
]
