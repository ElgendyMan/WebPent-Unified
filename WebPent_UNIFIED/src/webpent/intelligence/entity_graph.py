"""Bounded entity relationship graph for Target Brain observations."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EntityNode(BaseModel):
    """A report-safe entity node; values are identifiers, not secrets."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    node_id: str = Field(..., min_length=1, max_length=160)
    entity_type: Literal["user", "role", "order", "payment", "document", "account", "other"]
    label: str = Field(..., min_length=1, max_length=200)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_refs(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))


class EntityRelation(BaseModel):
    """A typed relation between two nodes in one target scope."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    source_id: str = Field(..., min_length=1, max_length=160)
    relation: str = Field(..., min_length=1, max_length=120)
    target_id: str = Field(..., min_length=1, max_length=160)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_refs(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))


class EntityGraph(BaseModel):
    """Mutable-in-memory graph whose identifiers are bound to one target."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: int = 1
    engagement_id: str = Field(..., min_length=1, max_length=200)
    target_id: str = Field(..., min_length=1, max_length=200)
    nodes: dict[str, EntityNode] = Field(default_factory=dict)
    relations: list[EntityRelation] = Field(default_factory=list, max_length=256)

    def add_node(self, node: EntityNode) -> None:
        self.nodes[node.node_id] = node

    def add_relation(self, relation: EntityRelation) -> None:
        if relation.source_id not in self.nodes or relation.target_id not in self.nodes:
            raise ValueError("entity_relation_requires_known_nodes")
        if relation not in self.relations:
            self.relations.append(relation)

    def evidence_refs(self) -> list[str]:
        return sorted(
            {ref for node in self.nodes.values() for ref in node.evidence_refs}
            | {ref for relation in self.relations for ref in relation.evidence_refs}
        )[:64]


__all__ = ["EntityGraph", "EntityNode", "EntityRelation"]
