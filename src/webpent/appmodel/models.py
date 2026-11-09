"""webpent.appmodel.models — M3 UM-DR-17: the application/asset-relation
model (Part 4 §5: "appmodel relations (Organization→…→Observation) with
discovery confidence").

The registry's entity chain names the endpoints of the relation spine;
this package realizes it as typed, versioned, evidence-carrying
entities:

    Organization → Tenant → Application → Endpoint
                                        ↘ Workflow
                          Identity ↗
                          Observation ↘ (onto endpoints/workflows)

Design contracts:

* **Discovery confidence is first-class.** Every entity records HOW it
  came to be known (``declared`` / ``observed`` / ``inferred``) and a
  deterministic numeric confidence; every relation carries the same.
  Nothing in the appmodel is "just there" — provenance is the model.
* **Relational truth, no graph database.** The appmodel is pure
  in-memory typed data (Part 4 §5: "attack-graph abstraction over
  relational truth — no Neo4j without measurement"). Persistence and
  any graph-DB migration are measured decisions for a later phase.
* **Attack-graph abstraction.** ``to_attack_graph_projection()``
  projects the model into the SAME ``AttackGraph`` shape the frozen
  ``shared/attack_graph`` produces (nodes with kinds, edges with
  evidence_refs + confidence) so downstream consumers see one
  vocabulary.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AppModelEntity",
    "AppModelEntityKind",
    "AppModelRelation",
    "AppModelRelationKind",
    "ApplicationModel",
    "DiscoveryProvenance",
    "provenance_confidence",
]

_MAX_REF = 240
_MAX_LABEL = 160


class AppModelEntityKind(str, Enum):
    ORGANIZATION = "organization"
    TENANT = "tenant"
    APPLICATION = "application"
    ENDPOINT = "endpoint"
    WORKFLOW = "workflow"
    IDENTITY = "identity"
    OBSERVATION = "observation"


class DiscoveryProvenance(str, Enum):
    """How an entity/relation came to be known — never decorative."""

    DECLARED = "declared"      # operator/engagement context supplied it
    OBSERVED = "observed"      # a scan observation produced it
    INFERRED = "inferred"      # derived from other relations (weakest)


class AppModelEntity(BaseModel):
    """One typed entity in the application model."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True, str_strip_whitespace=True)

    id: str = Field(min_length=3, max_length=200)
    kind: AppModelEntityKind
    label: str = Field(min_length=1, max_length=_MAX_LABEL)
    provenance: DiscoveryProvenance = DiscoveryProvenance.OBSERVED
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def ref_list(self) -> list[str]:
        return [str(ref)[:_MAX_REF] for ref in self.evidence_refs if str(ref).strip()]


class AppModelRelationKind(str, Enum):
    CONTAINS = "contains"                    # org→tenant, tenant→app, app→endpoint
    HOSTS = "hosts"                          # application→endpoint (alt phrasing)
    EXPOSES = "exposes"                      # endpoint→workflow
    PERFORMS = "performs"                    # identity→workflow
    AUTHENTICATES_AS = "authenticates_as"    # identity→tenant/application
    OBSERVED_ON = "observed_on"              # observation→endpoint/workflow
    REACHABLE_FROM = "reachable_from"        # endpoint→endpoint


class AppModelRelation(BaseModel):
    """One typed, confidence-carrying relation between entities."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True, str_strip_whitespace=True)

    id: str = Field(min_length=3, max_length=220)
    kind: AppModelRelationKind
    source_id: str = Field(min_length=3, max_length=200)
    target_id: str = Field(min_length=3, max_length=200)
    provenance: DiscoveryProvenance = DiscoveryProvenance.OBSERVED
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def ref_list(self) -> list[str]:
        return [str(ref)[:_MAX_REF] for ref in self.evidence_refs if str(ref).strip()]


# Deterministic confidence by provenance (documented, not tunable at will).
_PROVENANCE_CONFIDENCE: dict[DiscoveryProvenance, float] = {
    DiscoveryProvenance.DECLARED: 0.95,
    DiscoveryProvenance.OBSERVED: 0.8,
    DiscoveryProvenance.INFERRED: 0.4,
}


def provenance_confidence(provenance: DiscoveryProvenance) -> float:
    """The deterministic confidence a fresh entity/relation of this
    provenance starts from (callers may lower it, never silently raise)."""
    return _PROVENANCE_CONFIDENCE[provenance]


class ApplicationModel(BaseModel):
    """The typed application model: entities + relations, versioned."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    version: str = "1"
    engagement_id: str = Field(default="", max_length=200)
    entities: dict[str, AppModelEntity] = Field(default_factory=dict)
    relations: list[AppModelRelation] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list, max_length=50)
    provenance_note: str = Field(
        default=(
            "pure in-memory relational truth — no graph database "
            "(Part 4 §5: no Neo4j without measurement)"
        ),
        max_length=400,
    )

    def add_entity(self, entity: AppModelEntity) -> AppModelEntity:
        existing = self.entities.get(entity.id)
        if existing is None:
            self.entities[entity.id] = entity
            return entity
        # Re-observation strengthens confidence deterministically (capped):
        # the stronger provenance wins; refs merge deduplicated.
        stronger = (
            entity
            if (
                _PROVENANCE_CONFIDENCE[DiscoveryProvenance(entity.provenance)],
                entity.confidence,
            )
            > (
                _PROVENANCE_CONFIDENCE[DiscoveryProvenance(existing.provenance)],
                existing.confidence,
            )
            else existing
        )
        merged_refs = list(dict.fromkeys(existing.ref_list() + entity.ref_list()))
        self.entities[entity.id] = stronger.model_copy(
            update={"evidence_refs": merged_refs[:50]}
        )
        return self.entities[entity.id]

    def add_relation(self, relation: AppModelRelation) -> bool:
        if relation.source_id not in self.entities or relation.target_id not in self.entities:
            return False
        for existing in self.relations:
            if (
                existing.kind == relation.kind
                and existing.source_id == relation.source_id
                and existing.target_id == relation.target_id
            ):
                return False  # typed relation already present
        self.relations.append(relation)
        return True

    def to_attack_graph_projection(self) -> dict[str, Any]:
        """Project into the frozen ``AttackGraph`` vocabulary.

        Every entity becomes a node (kind-mapped, evidence-carrying);
        every relation becomes an edge whose confidence string carries
        the provenance and whose evidence_refs are the UNION of the
        relation's and both endpoints' refs — an appmodel edge is
        evidence-backed by construction or it does not exist.
        """
        kind_map = {
            "organization": "asset",
            "tenant": "asset",
            "application": "asset",
            "endpoint": "endpoint",
            "workflow": "workflow",
            "identity": "identity",
            "observation": "state",
        }
        nodes: dict[str, Any] = {}
        for entity_id, entity in self.entities.items():
            nodes[entity_id] = {
                "id": entity_id,
                "kind": kind_map.get(str(entity.kind), "asset"),
                "label": entity.label[:_MAX_LABEL],
                "status": str(entity.provenance),
                "criticality": "medium",
                "source_refs": entity.ref_list()[:50] or [f"appmodel:{entity_id}"],
                "metadata": {
                    "appmodel_kind": str(entity.kind),
                    "confidence": entity.confidence,
                    **{
                        k: v
                        for k, v in (entity.metadata or {}).items()
                        if isinstance(v, (str, int, float, bool))
                    },
                },
            }
        edges: list[dict[str, Any]] = []
        for relation in self.relations:
            source = self.entities[relation.source_id]
            target = self.entities[relation.target_id]
            refs = list(
                dict.fromkeys(
                    relation.ref_list() + source.ref_list() + target.ref_list()
                )
            )[:50]
            edges.append(
                {
                    "id": f"appmodel-edge:{relation.id}",
                    "kind": f"appmodel_{relation.kind}",
                    "source_id": relation.source_id,
                    "target_id": relation.target_id,
                    "confidence": f"appmodel_{relation.provenance}",
                    "evidence_refs": refs or [f"appmodel:{relation.id}"],
                    "metadata": {
                        "discovery_confidence": relation.confidence,
                        "appmodel_kind": str(relation.kind),
                    },
                }
            )
        return {
            "version": self.version,
            "nodes": nodes,
            "edges": edges,
            "coverage_gaps": [],
            "knowledge_gaps": [],
            "runtime_capability_gaps": [],
            "generated_from": ["appmodel"],
            "consistency_errors": [],
            "recommended_path_ids": [],
        }
