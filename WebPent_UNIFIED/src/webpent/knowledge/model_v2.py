"""Target Knowledge Model v2 contracts.

The v2 model is a passive, engagement-scoped projection.  It records what was
observed and where it came from; it never infers authorization, executes a
request, or promotes a finding.  The model intentionally stores references and
redacted metadata instead of raw request/response material.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.knowledge.target_knowledge import TargetKnowledgeModel
from webpent.models.evidence import redact_sensitive

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_SECRET_MARKERS = (
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
)


class KnowledgeLifecycle(str, Enum):
    """Lifecycle state of an observation or projection, not a finding verdict."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    VALIDATED = "validated"
    STALE = "stale"
    BLOCKED = "blocked"


class KnowledgeEntityKind(str, Enum):
    """Closed entity vocabulary required by the target understanding model."""

    APPLICATION = "application"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    ROLE = "role"
    USER = "user"
    IDENTITY = "identity"
    RESOURCE = "resource"
    OBJECT = "object"
    PERMISSION = "permission"
    DATA_FLOW = "data_flow"
    WORKFLOW = "workflow"
    TRUST_BOUNDARY = "trust_boundary"
    SECURITY_CONTROL = "security_control"
    SERVICE = "service"


class KnowledgeObservation(BaseModel):
    """A source observation referenced by one or more model entities."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    observation_id: str = Field(min_length=1, max_length=200)
    source: str = Field(min_length=1, max_length=160)
    observed_at: datetime = _EPOCH
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    lifecycle: KnowledgeLifecycle = KnowledgeLifecycle.OBSERVED
    facts: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def _utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(str(item)[:240] for item in values if str(item).strip()))

    @field_validator("facts")
    @classmethod
    def _safe_facts(cls, values: dict[str, Any]) -> dict[str, Any]:
        return _safe_mapping(values)


class KnowledgeEntity(BaseModel):
    """An evidence-linked target entity with explicit lifecycle metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    entity_id: str = Field(min_length=1, max_length=200)
    kind: KnowledgeEntityKind
    canonical_key: str = Field(min_length=1, max_length=320)
    source_observation: str = Field(min_length=1, max_length=200)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    observed_at: datetime = _EPOCH
    lifecycle: KnowledgeLifecycle = KnowledgeLifecycle.OBSERVED
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def _utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(str(item)[:240] for item in values if str(item).strip()))

    @field_validator("metadata")
    @classmethod
    def _safe_metadata(cls, values: dict[str, Any]) -> dict[str, Any]:
        return _safe_mapping(values)


class KnowledgeRelation(BaseModel):
    """A typed relationship between two entities, backed by an observation."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    relation_id: str = Field(min_length=1, max_length=240)
    relation: str = Field(min_length=1, max_length=80)
    source_entity: str = Field(min_length=1, max_length=200)
    target_entity: str = Field(min_length=1, max_length=200)
    source_observation: str = Field(min_length=1, max_length=200)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    observed_at: datetime = _EPOCH
    lifecycle: KnowledgeLifecycle = KnowledgeLifecycle.OBSERVED
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def _utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(str(item)[:240] for item in values if str(item).strip()))

    @field_validator("metadata")
    @classmethod
    def _safe_metadata(cls, values: dict[str, Any]) -> dict[str, Any]:
        return _safe_mapping(values)


class TargetKnowledgeV2(BaseModel):
    """Persistent target understanding projection used by graph and planner."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: int = Field(default=2, frozen=True)
    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    entities: dict[str, KnowledgeEntity] = Field(default_factory=dict)
    observations: dict[str, KnowledgeObservation] = Field(default_factory=dict)
    relations: tuple[KnowledgeRelation, ...] = Field(default=(), max_length=2_000)

    @field_validator("entities")
    @classmethod
    def _entity_keys_match(cls, values: dict[str, KnowledgeEntity]) -> dict[str, KnowledgeEntity]:
        if any(key != entity.entity_id for key, entity in values.items()):
            raise ValueError("knowledge_entity_key_mismatch")
        return values

    @field_validator("observations")
    @classmethod
    def _observation_keys_match(
        cls, values: dict[str, KnowledgeObservation]
    ) -> dict[str, KnowledgeObservation]:
        if any(key != observation.observation_id for key, observation in values.items()):
            raise ValueError("knowledge_observation_key_mismatch")
        return values

    @field_validator("relations")
    @classmethod
    def _unique_relation_ids(
        cls, values: tuple[KnowledgeRelation, ...]
    ) -> tuple[KnowledgeRelation, ...]:
        seen: set[str] = set()
        for relation in values:
            if relation.relation_id in seen:
                raise ValueError("duplicate_knowledge_relation")
            seen.add(relation.relation_id)
        return values

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def content_hash(self) -> str:
        """Return a deterministic hash of the redacted model content."""
        payload = self.model_dump(mode="json")
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def to_snapshot_json(self) -> str:
        """Serialize a canonical, redacted snapshot for persistence or replay."""
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_snapshot_json(cls, snapshot: str) -> TargetKnowledgeV2:
        """Restore a validated snapshot without adding execution authority."""
        if not isinstance(snapshot, str) or not snapshot.strip():
            raise ValueError("knowledge_snapshot_required")
        try:
            payload = json.loads(snapshot)
        except json.JSONDecodeError as exc:
            raise ValueError("knowledge_snapshot_invalid_json") from exc
        if not isinstance(payload, dict) or payload.get("schema_version") != 2:
            raise ValueError("knowledge_snapshot_schema_mismatch")
        return cls.model_validate(payload)

    def entities_of_kind(self, kind: KnowledgeEntityKind | str) -> tuple[KnowledgeEntity, ...]:
        value = kind.value if isinstance(kind, KnowledgeEntityKind) else str(kind)
        return tuple(entity for entity in self.entities.values() if entity.kind.value == value)


def _safe_scalar(value: Any) -> Any:
    if isinstance(value, str):
        clean, _ = redact_sensitive(value)
        return " ".join(clean.split())[:320]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return str(value)[:320]


def _safe_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    """Keep metadata bounded and remove secret-like keys recursively."""
    safe: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key).strip().lower()
        if not key or any(marker in key for marker in _SECRET_MARKERS):
            continue
        if isinstance(raw_value, Mapping):
            safe[key] = _safe_mapping(raw_value)
        elif isinstance(raw_value, (list, tuple)):
            safe[key] = [_safe_scalar(item) for item in raw_value[:20]]
        else:
            safe[key] = _safe_scalar(raw_value)
    return safe


def _stable_entity_id(kind: str, canonical_key: str) -> str:
    digest = hashlib.sha256(f"{kind}|{canonical_key}".encode()).hexdigest()[:24]
    return f"entity:{kind}:{digest}"


def build_target_knowledge_v2(
    *,
    engagement_id: str,
    target_id: str,
    observations: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...] = (),
    entities: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...] = (),
    relations: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...] = (),
) -> TargetKnowledgeV2:
    """Build a deterministic v2 model from already collected observations."""
    observation_models: dict[str, KnowledgeObservation] = {}
    for raw in observations:
        observation = KnowledgeObservation.model_validate(dict(raw))
        observation_models[observation.observation_id] = observation

    entity_models: dict[str, KnowledgeEntity] = {}
    for raw in entities:
        data = dict(raw)
        kind = KnowledgeEntityKind(str(data["kind"]))
        canonical_key = str(data.get("canonical_key") or data.get("name") or "").strip()
        if not canonical_key:
            raise ValueError("knowledge_entity_canonical_key_required")
        entity_id = str(data.get("entity_id") or _stable_entity_id(kind.value, canonical_key))
        entity = KnowledgeEntity.model_validate(
            {
                **data,
                "entity_id": entity_id,
                "kind": kind,
            }
        )
        if entity.source_observation not in observation_models:
            raise ValueError("knowledge_entity_source_observation_missing")
        entity_models[entity_id] = entity

    relation_models: list[KnowledgeRelation] = []
    for index, raw in enumerate(relations, start=1):
        relation = KnowledgeRelation.model_validate(
            {"relation_id": f"relation:{index}", **dict(raw)}
        )
        if (
            relation.source_entity not in entity_models
            or relation.target_entity not in entity_models
        ):
            raise ValueError("knowledge_relation_entity_missing")
        if relation.source_observation not in observation_models:
            raise ValueError("knowledge_relation_source_observation_missing")
        relation_models.append(relation)

    return TargetKnowledgeV2(
        engagement_id=engagement_id,
        target_id=target_id,
        entities=entity_models,
        observations=observation_models,
        relations=tuple(relation_models),
    )


def upgrade_legacy_knowledge(model: TargetKnowledgeModel, *, target_id: str) -> TargetKnowledgeV2:
    """Create a v2 projection from the existing v1 model without losing v1 data."""
    if not isinstance(model, TargetKnowledgeModel):
        raise TypeError("target_knowledge_model_required")
    observations: list[dict[str, Any]] = []
    entities: list[dict[str, Any]] = []
    for node in model.nodes.values():
        observation_id = f"legacy:{node.node_id}"
        observations.append(
            {
                "observation_id": observation_id,
                "source": "legacy_target_knowledge",
                "confidence": node.confidence,
                "evidence_refs": tuple(node.evidence_refs),
            }
        )
        entities.append(
            {
                "entity_id": node.node_id,
                "kind": node.kind.value,
                "canonical_key": node.canonical_key,
                "source_observation": observation_id,
                "confidence": node.confidence,
                "evidence_refs": tuple(node.evidence_refs),
                "metadata": node.metadata,
            }
        )
    return build_target_knowledge_v2(
        engagement_id=model.engagement_id,
        target_id=target_id,
        observations=observations,
        entities=entities,
    )


__all__ = [
    "KnowledgeEntity",
    "KnowledgeEntityKind",
    "KnowledgeLifecycle",
    "KnowledgeObservation",
    "KnowledgeRelation",
    "TargetKnowledgeV2",
    "build_target_knowledge_v2",
    "upgrade_legacy_knowledge",
]
