"""Report-safe identity and authorization matrix models.

These models describe observations only. They never carry credentials, cookies,
raw response bodies, payloads, or execution authority.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

IdentityRole = Literal[
    "anonymous",
    "user",
    "premium_user",
    "admin",
    "service_account",
    "unknown",
]
AccessExpectation = Literal["allow", "deny", "unknown"]
OwnershipRelation = Literal["owner", "non_owner", "unknown"]
ComparisonKind = Literal["horizontal", "vertical", "ownership_differential", "same_role"]


class IdentityActor(BaseModel):
    """Stable public identity metadata; no authentication material is allowed."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    identity_ref: str = Field(..., min_length=1, max_length=128)
    role: IdentityRole = "unknown"
    is_anonymous: bool = False
    redacted: bool = True


class IdentityObservation(BaseModel):
    """One bounded access observation for a target-scoped matrix."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    identity_ref: str = Field(..., min_length=1, max_length=128)
    role: IdentityRole = "unknown"
    object_ref: str | None = Field(default=None, max_length=160)
    endpoint: str = Field(..., min_length=1, max_length=1000)
    method: str = Field(default="GET", min_length=1, max_length=16)
    ownership_relation: OwnershipRelation = "unknown"
    expected_access: AccessExpectation = "unknown"
    observed_access: bool = False
    status_code: int = Field(default=0, ge=0, le=999)
    response_fingerprint: str = Field(..., min_length=1, max_length=128)
    evidence_refs: list[str] = Field(default_factory=list, max_length=16)
    target_backed: bool = False
    redacted: bool = True

    @field_validator("method", mode="before")
    @classmethod
    def _normalise_method(cls, value: object) -> str:
        return str(value or "GET").upper()[:16]

    @field_validator("endpoint")
    @classmethod
    def _reject_secret_query(cls, value: str) -> str:
        lowered = value.lower()
        for marker in ("token=", "password=", "secret=", "api_key=", "authorization="):
            if marker in lowered:
                raise ValueError("secret-shaped query material is not accepted")
        return value


class IdentityComparison(BaseModel):
    """Pairwise comparison; it is not itself a confirmed vulnerability."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    left_identity_ref: str = Field(..., min_length=1, max_length=128)
    right_identity_ref: str = Field(..., min_length=1, max_length=128)
    object_ref: str | None = Field(default=None, max_length=160)
    endpoint: str = Field(..., min_length=1, max_length=1000)
    method: str = Field(default="GET", min_length=1, max_length=16)
    comparison_kind: ComparisonKind
    access_differential: bool
    status_differential: bool
    fingerprint_differential: bool
    owner_identity_ref: str | None = None
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    promotion_status: Literal["candidate", "needs_replay", "blocked"] = "needs_replay"
    redacted: bool = True


class IdentityMatrix(BaseModel):
    """Bounded, isolated identity coverage and differential projection."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    version: str = "1"
    target_id: str = Field(..., min_length=1, max_length=128)
    engagement_id: str = Field(..., min_length=1, max_length=128)
    identities: list[IdentityActor] = Field(default_factory=list, max_length=64)
    observations: list[IdentityObservation] = Field(default_factory=list, max_length=500)
    comparisons: list[IdentityComparison] = Field(default_factory=list, max_length=1000)
    coverage_gaps: list[str] = Field(default_factory=list, max_length=128)
    redaction: str = "credentials_cookies_payloads_and_raw_bodies_omitted"

    @property
    def differential_count(self) -> int:
        return sum(1 for item in self.comparisons if item.access_differential)


__all__ = [
    "AccessExpectation",
    "ComparisonKind",
    "IdentityActor",
    "IdentityComparison",
    "IdentityMatrix",
    "IdentityObservation",
    "IdentityRole",
    "OwnershipRelation",
]
