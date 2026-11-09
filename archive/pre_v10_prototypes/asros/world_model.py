"""Security World Model for bounded autonomous research.

The world model is a redacted, target-scoped projection over existing knowledge
contracts.  It explains business intent, security invariants, and observed
behaviour, but it never executes requests, grants authority, or creates findings.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from webpent.knowledge.model_v2 import TargetKnowledgeV2
from webpent.models.evidence import redact_sensitive

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class Freshness(str, Enum):
    FRESH = "fresh"
    RECENT = "recent"
    STALE = "stale"
    UNKNOWN = "unknown"


class EvidenceLineage(BaseModel):
    """Evidence references and provenance for one world-model element."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    source: str = Field(min_length=1, max_length=160)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    freshness: Freshness = Freshness.UNKNOWN
    observed_at: datetime = _EPOCH

    @field_validator("evidence_refs")
    @classmethod
    def _refs_are_safe(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        clean: list[str] = []
        for value in values:
            ref, _ = redact_sensitive(str(value))
            if ref.strip():
                clean.append(ref.strip()[:240])
        if not clean:
            raise ValueError("lineage_evidence_required")
        return tuple(dict.fromkeys(clean))

    @field_validator("observed_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return _EPOCH if value.tzinfo is None else value.astimezone(UTC)


class BusinessIntent(BaseModel):
    """A target-scoped statement of what a workflow is intended to do."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    intent_id: str = Field(min_length=1, max_length=180)
    goal: str = Field(min_length=3, max_length=500)
    workflow: str = Field(min_length=1, max_length=200)
    transaction: str | None = Field(default=None, max_length=200)
    state_transitions: tuple[str, ...] = Field(default=(), max_length=16)
    ownership_rules: tuple[str, ...] = Field(default=(), max_length=16)
    trust_assumptions: tuple[str, ...] = Field(default=(), max_length=16)
    lineage: EvidenceLineage

    @field_validator("state_transitions", "ownership_rules", "trust_assumptions")
    @classmethod
    def _bounded_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(str(value).strip()[:320] for value in values if str(value).strip())
        )


class InvariantKind(str, Enum):
    OWNERSHIP = "ownership"
    ROLE_BOUNDARY = "role_boundary"
    TRANSACTION = "transaction"
    DATA_FLOW = "data_flow"
    WORKFLOW = "workflow"


class SecurityInvariant(BaseModel):
    """A falsifiable security expectation, not a vulnerability verdict."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    invariant_id: str = Field(min_length=1, max_length=180)
    statement: str = Field(min_length=8, max_length=700)
    kind: InvariantKind
    subject: str = Field(min_length=1, max_length=180)
    protected_resource: str = Field(min_length=1, max_length=180)
    allowed_conditions: tuple[str, ...] = Field(default=(), max_length=16)
    forbidden_conditions: tuple[str, ...] = Field(default=(), max_length=16)
    lineage: EvidenceLineage

    @field_validator("allowed_conditions", "forbidden_conditions")
    @classmethod
    def _bounded_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(str(value).strip()[:320] for value in values if str(value).strip())
        )


class BehaviorStatus(str, Enum):
    EXPECTED = "expected"
    OBSERVED = "observed"
    DEVIATION = "deviation"
    UNKNOWN = "unknown"


class BehaviorObservation(BaseModel):
    """Expected/observed behaviour comparison backed by references only."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    behavior_id: str = Field(min_length=1, max_length=180)
    subject: str = Field(min_length=1, max_length=180)
    expected: str = Field(min_length=3, max_length=500)
    observed: str | None = Field(default=None, max_length=500)
    status: BehaviorStatus = BehaviorStatus.UNKNOWN
    deviation: str | None = Field(default=None, max_length=500)
    lineage: EvidenceLineage

    @model_validator(mode="after")
    def _deviation_requires_observation(self) -> BehaviorObservation:
        if self.status == BehaviorStatus.DEVIATION and not self.observed:
            raise ValueError("behavior_deviation_observation_required")
        return self


class InvariantAssessment(BaseModel):
    """Advisory reasoning result for an invariant."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    invariant_id: str = Field(min_length=1, max_length=180)
    result: str = Field(pattern="^(unassessed|supported|disputed|blocked)$")
    rationale: str = Field(min_length=3, max_length=700)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    requires_causal_validation: bool = True


class SecurityWorldModel(BaseModel):
    """Living but deterministic security projection for one exact target scope."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: int = Field(default=1, frozen=True)
    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    knowledge_hash: str = Field(min_length=16, max_length=128)
    business_intents: tuple[BusinessIntent, ...] = Field(default=(), max_length=256)
    invariants: tuple[SecurityInvariant, ...] = Field(default=(), max_length=256)
    behaviours: tuple[BehaviorObservation, ...] = Field(default=(), max_length=512)
    coverage_gaps: tuple[str, ...] = Field(default=(), max_length=128)
    authoritative: bool = False
    execution_capability: bool = False

    @model_validator(mode="after")
    def _unique_ids_and_scope(self) -> SecurityWorldModel:
        for values, key in (
            (self.business_intents, "intent_id"),
            (self.invariants, "invariant_id"),
            (self.behaviours, "behavior_id"),
        ):
            ids = [getattr(value, key) for value in values]
            if len(ids) != len(set(ids)):
                raise ValueError(f"duplicate_world_model_{key}")
        if self.authoritative or self.execution_capability:
            raise ValueError("world_model_cannot_grant_authority")
        return self

    def content_hash(self) -> str:
        payload = self.model_dump(mode="json")
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def invariant_assessment(self, invariant_id: str) -> InvariantAssessment:
        invariant = next(
            (item for item in self.invariants if item.invariant_id == invariant_id), None
        )
        if invariant is None:
            raise KeyError(invariant_id)
        related = [item for item in self.behaviours if item.subject == invariant.protected_resource]
        deviations = [item for item in related if item.status == BehaviorStatus.DEVIATION]
        if deviations:
            refs = tuple(
                dict.fromkeys(ref for item in deviations for ref in item.lineage.evidence_refs)
            )
            return InvariantAssessment(
                invariant_id=invariant_id,
                result="disputed",
                rationale=(
                    "Observed behaviour deviates from the invariant expectation; "
                    "causal validation is still required."
                ),
                evidence_refs=refs,
            )
        if related and all(item.status == BehaviorStatus.EXPECTED for item in related):
            refs = tuple(
                dict.fromkeys(ref for item in related for ref in item.lineage.evidence_refs)
            )
            return InvariantAssessment(
                invariant_id=invariant_id,
                result="supported",
                rationale=(
                    "Available observations are consistent with the invariant; "
                    "this is not proof of universal enforcement."
                ),
                evidence_refs=refs,
            )
        return InvariantAssessment(
            invariant_id=invariant_id,
            result="unassessed",
            rationale="No sufficient behaviour comparison is available for this invariant.",
            evidence_refs=(),
        )

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_target_knowledge(
        cls,
        knowledge: TargetKnowledgeV2,
        *,
        business_intents: Iterable[BusinessIntent] = (),
        invariants: Iterable[SecurityInvariant] = (),
        behaviours: Iterable[BehaviorObservation] = (),
        coverage_gaps: Iterable[str] = (),
    ) -> SecurityWorldModel:
        if not isinstance(knowledge, TargetKnowledgeV2):
            raise TypeError("target_knowledge_v2_required")
        return cls(
            engagement_id=knowledge.engagement_id,
            target_id=knowledge.target_id,
            knowledge_hash=knowledge.content_hash(),
            business_intents=tuple(business_intents),
            invariants=tuple(invariants),
            behaviours=tuple(behaviours),
            coverage_gaps=tuple(
                dict.fromkeys(
                    str(item).strip()[:240] for item in coverage_gaps if str(item).strip()
                )
            ),
        )


__all__ = [
    "BehaviorObservation",
    "BehaviorStatus",
    "BusinessIntent",
    "EvidenceLineage",
    "Freshness",
    "InvariantAssessment",
    "InvariantKind",
    "SecurityInvariant",
    "SecurityWorldModel",
]
