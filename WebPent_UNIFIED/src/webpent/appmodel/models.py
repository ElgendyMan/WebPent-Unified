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
from collections.abc import Mapping
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
    """How an entity/relation came to be known — never decorative.

    UM-DR-37 Part 5.2 extends the vocabulary with the two states the
    mission requires: UNKNOWN (explicitly not known — never silently
    defaulted) and CONTRADICTED (evidence conflicts; the original
    evidence is KEPT and the contradiction is recorded — see
    ``ApplicationModel.mark_contradicted``).
    """

    DECLARED = "declared"      # operator/engagement context supplied it
    OBSERVED = "observed"      # a scan observation produced it
    INFERRED = "inferred"      # derived from other relations (weakest)
    UNKNOWN = "unknown"        # explicitly absent knowledge (UM-DR-37)
    CONTRADICTED = "contradicted"  # conflicting evidence recorded (UM-DR-37)


class AppModelEntity(BaseModel):
    """One typed entity in the application model."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True, str_strip_whitespace=True)

    id: str = Field(min_length=3, max_length=200)
    kind: AppModelEntityKind
    label: str = Field(min_length=1, max_length=_MAX_LABEL)
    provenance: DiscoveryProvenance = DiscoveryProvenance.OBSERVED
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)
    # UM-DR-37 Part 5.2: staleness metadata — when this fact was last
    # observed (ISO-8601 UTC; ``None`` only for records built before the
    # field existed).
    observed_at: str | None = None
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
    OWNS = "owns"                            # identity→endpoint/resource


# UM-DR-36 (2026-11-12): ``OWNS`` was added by the corrective closure to
# materialize real object-ownership evidence (crawled endpoint records
# carrying ``owner_identity``). It is created ONLY from recorded evidence —
# never from hypothesis text — and feeds the ownership-relation research
# hints and the Discovery Funnel's ``object_ownership_relations`` metric.


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
    observed_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def ref_list(self) -> list[str]:
        return [str(ref)[:_MAX_REF] for ref in self.evidence_refs if str(ref).strip()]


# Deterministic confidence by provenance (documented, not tunable at will).


def _utc_now_iso() -> str:
    """Current UTC time, ISO-8601 with seconds precision (stamped at
    entity/relation add time — first observation wins on merge)."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


_PROVENANCE_CONFIDENCE: dict[DiscoveryProvenance, float] = {
    DiscoveryProvenance.DECLARED: 0.95,
    DiscoveryProvenance.OBSERVED: 0.8,
    DiscoveryProvenance.INFERRED: 0.4,
    # UM-DR-37 Part 5.2: explicitly-unknown and contradicted knowledge
    # carry the weakest deterministic confidences — a contradiction is
    # never silently treated as fresh observation.
    DiscoveryProvenance.UNKNOWN: 0.1,
    DiscoveryProvenance.CONTRADICTED: 0.05,
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
    # UM-DR-37 Parts 5.5/5.6: revision counter (every add/contradiction
    # increments it) and the recorded contradiction log. A model delta
    # between two revisions is computable via ``delta_since``.
    revision: int = 1
    contradictions: list[dict[str, Any]] = Field(default_factory=list)
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
            stamped = entity.model_copy(
                update={"observed_at": entity.observed_at or _utc_now_iso()})
            self.entities[entity.id] = stamped
            self.revision += 1
            return stamped
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
        # the earliest observation timestamp wins (staleness metadata
        # records FIRST observation, not last write)
        observed_at = existing.observed_at or entity.observed_at or _utc_now_iso()
        # UM-DR-44 A5a: endpoint facets are ACCUMULATING or CURRENT-STATE
        # metadata — they never compete with the provenance winner.
        # methods_seen accumulates with set semantics (a POST observation
        # must not erase a recorded GET when the tie-break keeps the
        # existing record); status_code keeps the LATEST value (current
        # response state); identity facets (scheme/host/port/path) carry
        # the new observation's explicit values (equal by construction of
        # the canonical tuple id); other metadata keys merge additively.
        merged_metadata = dict(existing.metadata or {})
        if str(entity.kind) == "endpoint":
            new_meta = entity.metadata or {}
            if new_meta.get("methods_seen"):
                merged_metadata["methods_seen"] = sorted({
                    *(merged_metadata.get("methods_seen") or []),
                    *new_meta["methods_seen"],
                })[:16]
            if "status_code" in new_meta:
                merged_metadata["status_code"] = new_meta["status_code"]
            for facet in ("scheme", "host", "port", "path"):
                if new_meta.get(facet) is not None:
                    merged_metadata[facet] = new_meta[facet]
        self.entities[entity.id] = stronger.model_copy(
            update={"evidence_refs": merged_refs[:50],
                    "metadata": merged_metadata,
                    "observed_at": observed_at}
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
        stamped = relation.model_copy(
            update={"observed_at": relation.observed_at or _utc_now_iso()})
        self.relations.append(stamped)
        self.revision += 1
        return True

    def mark_contradicted(
        self,
        target_id: str,
        *,
        contradicting_evidence_ref: str,
        note: str = "",
    ) -> bool:
        """UM-DR-37 Part 5.5 — record CONFLICTING evidence honestly.

        The original evidence is KEPT (never replaced); the
        contradicting reference is appended; provenance flips to
        CONTRADICTED with its deterministic weakest confidence; the
        contradiction itself is logged on the model with both sides.
        Downstream consumers see the conflict instead of a silently
        overwritten fact.
        """
        target: AppModelEntity | AppModelRelation | None = None
        is_relation = False
        entity = self.entities.get(target_id)
        if entity is not None:
            target = entity
        else:
            for relation in self.relations:
                if relation.id == target_id:
                    target = relation
                    is_relation = True
                    break
        if target is None:
            return False
        original_provenance = str(target.provenance)
        original_confidence = float(target.confidence)
        original_refs = target.ref_list()
        merged_refs = list(
            dict.fromkeys(original_refs + [str(contradicting_evidence_ref)
                                           [:_MAX_REF]])
        )[:50]
        updated = target.model_copy(update={
            # model_copy bypasses validation, so store the enum VALUE —
            # use_enum_values only applies on validated construction.
            "provenance": DiscoveryProvenance.CONTRADICTED.value,
            "confidence": _PROVENANCE_CONFIDENCE[
                DiscoveryProvenance.CONTRADICTED],
            "evidence_refs": merged_refs,
            "metadata": {
                **(target.metadata or {}),
                "contradiction_note": str(note)[:300],
            },
        })
        if is_relation:
            for index, relation in enumerate(self.relations):
                if relation.id == target_id:
                    self.relations[index] = updated
                    break
        else:
            self.entities[target_id] = updated
        self.contradictions.append({
            "target_id": target_id,
            "target_kind": "relation" if is_relation else "entity",
            "original_provenance": original_provenance,
            "original_confidence": original_confidence,
            "original_evidence_refs": original_refs[:50],
            "contradicting_evidence_ref": str(contradicting_evidence_ref)[
                :_MAX_REF],
            "note": str(note)[:300],
        })
        self.revision += 1
        return True

    def apply_observation(
        self,
        observation: dict[str, Any],
    ) -> dict[str, Any]:
        """UM-DR-43 Workstream A — incremental single-observation update.

        Applies ONE observation to the model WITHOUT rebuilding it: the
        typed entities and relations this observation evidences are
        merged via add_entity/add_relation (which already preserve
        provenance, merge evidence refs, and strengthen confidence
        deterministically), and every derived fact records exactly the
        provenance the observation carries — an INFERRED link is never
        stored as OBSERVED, and an unresolvable observation ABSTAINS
        (records a coverage gap) instead of inventing structure.

        Observation contract (all fields optional except url/actor):
          url:          the observed request URL (endpoint identity)
          method:       HTTP method (stored in endpoint metadata)
          actor:        principal/role identity that made/may make the
                        request (IDENTITY entity + OBSERVED_ON relation —
                        provenance INFERRED, never OBSERVED, because the
                        model does not see the server's decision)
          status_code:  response status (endpoint metadata + evidence)
          evidence_ref: provenance token (request id, ledger digest,
                        observation id) — REQUIRED for traceability;
                        without it the observation is rejected.
          inferred:     mapping of {entity_kind: label} for relationships
                        the CALLER inferred — stored as INFERRED with
                        the deterministic weak confidence.

        Returns a bounded, explainable result: what was touched, which
        provenance was assigned, and which parts abstained with why.
        """
        evidence_ref = str(observation.get("evidence_ref") or "").strip()
        if not evidence_ref:
            return {"applied": False, "reason": "evidence_ref_required",
                    "touched": [], "abstained": []}
        url = str(observation.get("url") or "").strip()
        method = str(observation.get("method") or "GET").strip().upper()[:8]
        actor = str(observation.get("actor") or "").strip()
        status_code = observation.get("status_code")
        inferred = observation.get("inferred") or {}
        touched: list[str] = []
        abstained: list[dict[str, str]] = []

        if url:
            from webpent.appmodel.builder import _endpoint_id_of, _endpoint_tuple_key
            # UM-DR-44 A5a: endpoint identity is the canonical
            # (scheme, host, effective port, path) tuple — the SSOT
            # _endpoint_id_of, shared with the full-rebuild builder.
            # The previous f"{host}{path}" key dropped scheme and port,
            # collapsing https/http and implicit/explicit-port origins
            # into ONE entity (merging evidence across different trust
            # boundaries). A URL without scheme+host has NO identity —
            # the observation abstains instead of inventing one.
            endpoint_id = _endpoint_id_of(url)
            if endpoint_id is not None:
                scheme, host, effective_port, canon_path = \
                    _endpoint_tuple_key(url)
                tuple_key = f"{scheme}://{host}:{effective_port}{canon_path}"
                self.add_entity(AppModelEntity(
                    id=endpoint_id,
                    kind=AppModelEntityKind.ENDPOINT,
                    label=f"endpoint:{tuple_key}"[:160],
                    provenance=DiscoveryProvenance.OBSERVED,
                    confidence=provenance_confidence(
                        DiscoveryProvenance.OBSERVED),
                    evidence_refs=[evidence_ref[:_MAX_REF]],
                    metadata={
                        "scheme": scheme,
                        "host": host,
                        "port": effective_port,
                        "path": canon_path,
                        "methods_seen": [method],
                        **({"status_code": int(status_code)}
                           if isinstance(status_code, int) else {}),
                    },
                ))
                touched.append(endpoint_id)
            else:
                abstained.append({"what": "endpoint", "why": "unparseable_url"})
        else:
            abstained.append({"what": "endpoint", "why": "no_url_abstained"})

        if actor:
            principal_id = f"identity:{actor[:120]}"
            self.add_entity(AppModelEntity(
                id=principal_id,
                kind=AppModelEntityKind.IDENTITY,
                label=f"identity:{actor[:120]}",
                # The observation evidences the REQUEST, not the server's
                # authorization decision — the link stays INFERRED.
                provenance=DiscoveryProvenance.INFERRED,
                confidence=provenance_confidence(
                    DiscoveryProvenance.INFERRED),
                evidence_refs=[evidence_ref[:_MAX_REF]],
            ))
            touched.append(principal_id)
            if url and host and endpoint_id in self.entities:
                self.add_relation(AppModelRelation(
                    id=f"{principal_id}->observed_on->{endpoint_id}",
                    kind=AppModelRelationKind.OBSERVED_ON,
                    source_id=principal_id,
                    target_id=endpoint_id,
                    provenance=DiscoveryProvenance.INFERRED,
                    confidence=provenance_confidence(
                        DiscoveryProvenance.INFERRED),
                    evidence_refs=[evidence_ref[:_MAX_REF]],
                ))
        if isinstance(inferred, Mapping):
            for kind_raw, label in list(inferred.items())[:16]:
                kind = str(kind_raw).strip().lower()
                label = str(label).strip()
                if not label:
                    continue
                try:
                    entity_kind = AppModelEntityKind(kind)
                except ValueError:
                    abstained.append({"what": f"inferred:{kind_raw}",
                                      "why": "unknown_entity_kind"})
                    continue
                inferred_id = f"{kind}:{label[:120]}"
                self.add_entity(AppModelEntity(
                    id=inferred_id,
                    kind=entity_kind,
                    label=f"{kind}:{label}"[:160],
                    provenance=DiscoveryProvenance.INFERRED,
                    confidence=provenance_confidence(
                        DiscoveryProvenance.INFERRED),
                    evidence_refs=[evidence_ref[:_MAX_REF]],
                ))
                touched.append(inferred_id)
        return {
            "applied": True,
            "touched": touched[:50],
            "touched_count": len(touched),
            "abstained": abstained[:20],
            "revision": self.revision,
        }

    def delta_since(self, previous: "ApplicationModel") -> dict[str, Any]:
        """UM-DR-37 Part 5.6 — the observable delta between two model
        revisions: what was added/removed, which provenance changed, and
        which contradictions were recorded. Bounded, deterministic,
        explainable — no unexplainable updates."""
        previous_entities = set(previous.entities)
        current_entities = set(self.entities)

        def relation_key(relation: AppModelRelation) -> tuple[str, str, str]:
            return (str(relation.kind), relation.source_id, relation.target_id)

        previous_relations = {relation_key(r) for r in previous.relations}
        current_relations = {relation_key(r) for r in self.relations}
        provenance_changes: dict[str, dict[str, Any]] = {}
        for entity_id in sorted(current_entities & previous_entities):
            before = str(previous.entities[entity_id].provenance)
            after = str(self.entities[entity_id].provenance)
            if before != after:
                provenance_changes[entity_id] = {
                    "from": before, "to": after}
        return {
            "revision_from": previous.revision,
            "revision_to": self.revision,
            "entities_added": sorted(current_entities - previous_entities)[:50],
            "entities_added_count": len(current_entities - previous_entities),
            "entities_removed": sorted(previous_entities - current_entities)[:50],
            "entities_removed_count": len(previous_entities - current_entities),
            "relations_added": [
                list(key) for key in
                sorted(current_relations - previous_relations)
            ][:50],
            "relations_added_count": len(current_relations - previous_relations),
            "provenance_changes": provenance_changes,
            "contradictions_recorded": self.contradictions[
                len(previous.contradictions):][:50],
            "contradictions_recorded_count": max(
                0, len(self.contradictions) - len(previous.contradictions)),
        }

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
