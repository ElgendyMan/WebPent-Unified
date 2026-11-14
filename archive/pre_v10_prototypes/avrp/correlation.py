"""Cross-observation correlation for AVRP.

This module turns already-recorded, redacted observations into advisory
relationships. It never treats a relationship as a finding or sends traffic.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import canonical_json, redact_sensitive
from webpent.models.research import InformationObservation


def _redact(value: Any, limit: int = 500) -> str:
    clean, _ = redact_sensitive(str(value or ""))
    return " ".join(clean.split())[:limit]


def _redact_list(values: Sequence[Any], limit: int = 30) -> list[str]:
    result: list[str] = []
    for item in values[:limit]:
        value = _redact(item, 240)
        if value and value not in result:
            result.append(value)
    return result


class EvidenceNode(BaseModel):
    """One observation-derived node in the report-safe relationship graph."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    node_id: str = Field(min_length=3, max_length=160)
    observation_id: str = Field(min_length=3, max_length=160)
    kind: str = Field(min_length=2, max_length=80)
    value_ref: str = Field(min_length=1, max_length=240)
    evidence_refs: list[str] = Field(min_length=1, max_length=30)

    @field_validator(
        "node_id", "observation_id", "kind", "value_ref", "evidence_refs", mode="before"
    )
    @classmethod
    def _clean(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple)):
            return _redact_list(value)
        return _redact(value)


class SecurityRelationship(BaseModel):
    """A hypothesis-level relation between multiple observations."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    relationship_id: str = Field(min_length=3, max_length=160)
    relationship_type: Literal[
        "authorization_boundary",
        "ownership_boundary",
        "privilege_boundary",
        "workflow_dependency",
        "data_exposure",
        "unknown",
    ]
    source_observation_ids: list[str] = Field(min_length=2, max_length=20)
    source_node_ids: list[str] = Field(min_length=1, max_length=20)
    reasoning: str = Field(min_length=3, max_length=500)
    confidence: float = Field(ge=0.0, le=1.0)
    validation_requirement: str = Field(min_length=3, max_length=500)
    status: Literal["hypothesis", "blocked"] = "hypothesis"

    @field_validator(
        "relationship_id",
        "relationship_type",
        "source_observation_ids",
        "source_node_ids",
        "reasoning",
        "validation_requirement",
        "status",
        mode="before",
    )
    @classmethod
    def _redact(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple)):
            return _redact_list(value, 20)
        return _redact(value)

    def as_dict(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        clean, _ = redact_sensitive(payload)
        return clean


class EvidenceRelationshipGraph(BaseModel):
    """Deterministic graph of observation nodes and advisory relations."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target_ref: str = Field(min_length=3, max_length=500)
    nodes: list[EvidenceNode] = Field(default_factory=list, max_length=500)
    relationships: list[SecurityRelationship] = Field(default_factory=list, max_length=200)

    @field_validator("target_ref", mode="before")
    @classmethod
    def _clean_target(cls, value: Any) -> str:
        return _redact(value)

    def as_dict(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        clean, _ = redact_sensitive(payload)
        return clean

    def graph_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.as_dict()).encode()).hexdigest()


class EvidenceCorrelationEngine:
    """Correlate explicit observation metadata, fail-closed on missing context."""

    _RELATION_RULES: tuple[tuple[str, str, str, str, str], ...] = (
        (
            "object_identifier",
            "role_difference",
            "authorization_boundary",
            "An object reference coexists with a role differential.",
            "Obtain a causal candidate/control pair with an approved oracle.",
        ),
        (
            "ownership_relation",
            "object_identifier",
            "ownership_boundary",
            "An ownership relation and object reference may expose an ownership boundary.",
            "Verify requester/owner contrast with independent negative control.",
        ),
        (
            "privilege_context",
            "role_difference",
            "privilege_boundary",
            "A privilege context and role differential may indicate a privilege boundary.",
            "Validate only through a policy-approved, read-only oracle.",
        ),
        (
            "workflow_transition",
            "business_impact",
            "workflow_dependency",
            "A workflow transition is linked to a reported business-impact condition.",
            "Demonstrate the transition and impact causally without mutation.",
        ),
        (
            "sensitive_data",
            "object_identifier",
            "data_exposure",
            "Sensitive-data metadata and object references may form a data-exposure path.",
            "Confirm exposure with an approved oracle and redacted evidence.",
        ),
    )

    def correlate(
        self,
        observations: Iterable[InformationObservation],
        *,
        target_ref: str,
    ) -> EvidenceRelationshipGraph:
        """Build a graph only from explicit observation metadata and evidence refs."""
        if not _redact(target_ref):
            raise ValueError("target_ref is required")
        items = tuple(observations)
        nodes: list[EvidenceNode] = []
        by_kind: dict[str, list[EvidenceNode]] = {}
        for observation in items:
            if not isinstance(observation, InformationObservation):
                raise TypeError("observations must be InformationObservation instances")
            if not observation.evidence_refs:
                continue
            metadata = observation.metadata if isinstance(observation.metadata, dict) else {}
            kinds = metadata.get("security_signals", [])
            if isinstance(kinds, str):
                kinds = [kinds]
            if not isinstance(kinds, (list, tuple)):
                continue
            for raw_kind in kinds[:20]:
                kind = _redact(raw_kind, 80).lower().replace("-", "_")
                if not kind:
                    continue
                value_ref = _redact(metadata.get(f"{kind}_ref") or kind, 240)
                node_id = (
                    "node:"
                    + hashlib.sha256(
                        canonical_json(
                            {
                                "observation_id": observation.observation_id,
                                "kind": kind,
                                "value_ref": value_ref,
                            }
                        ).encode()
                    ).hexdigest()[:24]
                )
                node = EvidenceNode(
                    node_id=node_id,
                    observation_id=observation.observation_id,
                    kind=kind,
                    value_ref=value_ref,
                    evidence_refs=observation.evidence_refs,
                )
                if node.node_id not in {item.node_id for item in nodes}:
                    nodes.append(node)
                    by_kind.setdefault(kind, []).append(node)

        relationships: list[SecurityRelationship] = []
        for left_kind, right_kind, rel_type, reasoning, requirement in self._RELATION_RULES:
            left_nodes = by_kind.get(left_kind, [])
            right_nodes = by_kind.get(right_kind, [])
            for left in left_nodes:
                for right in right_nodes:
                    source_observations = sorted({left.observation_id, right.observation_id})
                    if len(source_observations) < 2:
                        continue
                    payload = {
                        "target_ref": _redact(target_ref),
                        "relationship_type": rel_type,
                        "source_observations": source_observations,
                    }
                    relation_id = (
                        "rel:" + hashlib.sha256(canonical_json(payload).encode()).hexdigest()[:24]
                    )
                    relationship = SecurityRelationship(
                        relationship_id=relation_id,
                        relationship_type=rel_type,
                        source_observation_ids=source_observations,
                        source_node_ids=sorted({left.node_id, right.node_id}),
                        reasoning=reasoning,
                        confidence=0.55,
                        validation_requirement=requirement,
                    )
                    if relationship.relationship_id not in {
                        item.relationship_id for item in relationships
                    }:
                        relationships.append(relationship)
        nodes.sort(key=lambda item: item.node_id)
        relationships.sort(key=lambda item: item.relationship_id)
        return EvidenceRelationshipGraph(
            target_ref=target_ref,
            nodes=nodes,
            relationships=relationships,
        )


__all__ = [
    "EvidenceCorrelationEngine",
    "EvidenceNode",
    "EvidenceRelationshipGraph",
    "SecurityRelationship",
]
