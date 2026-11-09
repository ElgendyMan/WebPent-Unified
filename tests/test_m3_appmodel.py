"""M3 UM-DR-17: the application/asset-relation model (appmodel).

Part 4 §5 (via CANONICAL_PHASE_REGISTRY M3 scope): "appmodel relations
(Organization→…→Observation) with discovery confidence · attack-graph
abstraction over relational truth (no Neo4j without measurement)".

Contract under test:

1. **The typed spine** — Organization→Tenant→Application→Endpoint with
   Identity and Observation attached; every relation typed and
   end-point-checked (a relation to an unknown entity is refused).
2. **Discovery confidence** — declared/observed/inferred carry
   deterministic confidences; re-observation merges refs and keeps the
   stronger provenance; the projection surfaces provenance + numeric
   confidence per node/edge.
3. **The builder derives from real channels** — crawled_data endpoints,
   identity profiles, mental-model observations; absent channels become
   honest coverage gaps, never silent emptiness.
4. **The attack-graph abstraction** — the projection speaks the frozen
   AttackGraph vocabulary (nodes/edges/evidence_refs), merges
   additively into a built graph, and every projected edge carries
   evidence by construction.
"""

from __future__ import annotations

from typing import Any

from webpent.appmodel import (
    AppModelEntity,
    AppModelEntityKind,
    AppModelRelation,
    AppModelRelationKind,
    ApplicationModel,
    DiscoveryProvenance,
    build_application_model,
    merge_appmodel_into_attack_graph,
    provenance_confidence,
)
from webpent.shared.attack_graph import build_attack_graph

TARGET = "https://app.example.com"


def _state(**extra: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "engagement_id": "eng-appmodel",
        "target_url": TARGET,
        "crawled_data": {
            "openapi_routes": [{"method": "GET", "path": "/api/v2/users"}],
            "surface_records": [
                {"method": "GET", "url": f"{TARGET}/dashboard", "path": "/dashboard"}
            ],
            "shadow_endpoints": [{"method": "GET", "path": "/api/internal/admin"}],
        },
        "identity_profiles": {
            "owner": {"name": "owner", "role": "owner", "validated": True},
            "viewer": {"name": "viewer", "role": "viewer", "validated": False},
        },
    }
    state.update(extra)
    return state


# ---------------------------------------------------------------------------
# 1. The typed spine
# ---------------------------------------------------------------------------


def test_relation_to_unknown_entity_is_refused() -> None:
    model = ApplicationModel()
    org = AppModelEntity(
        id="appmodel-org:test",
        kind=AppModelEntityKind.ORGANIZATION,
        label="organization:test",
        provenance=DiscoveryProvenance.DECLARED,
    )
    model.add_entity(org)
    assert (
        model.add_relation(
            AppModelRelation(
                id="rel-to-missing-target",
                kind=AppModelRelationKind.CONTAINS,
                source_id="appmodel-org:test",
                target_id="appmodel-tenant:missing",
            )
        )
        is False
    )
    assert model.relations == []


def test_duplicate_typed_relations_are_idempotent() -> None:
    model = build_application_model(_state())
    relation_count = len(model.relations)
    tenant_id = "appmodel-tenant:eng-appmodel"
    app_id = next(
        eid for eid in model.entities if eid.startswith("appmodel-app:")
    )
    assert (
        model.add_relation(
            AppModelRelation(
                id=f"{tenant_id}->contains->{app_id}-dup",
                kind=AppModelRelationKind.CONTAINS,
                source_id=tenant_id,
                target_id=app_id,
            )
        )
        is False
    )
    assert len(model.relations) == relation_count


# ---------------------------------------------------------------------------
# 2. Discovery confidence
# ---------------------------------------------------------------------------


def test_provenance_confidence_ordering() -> None:
    assert (
        provenance_confidence(DiscoveryProvenance.DECLARED)
        > provenance_confidence(DiscoveryProvenance.OBSERVED)
        > provenance_confidence(DiscoveryProvenance.INFERRED)
    )


def test_reobservation_merges_refs_and_keeps_stronger_provenance() -> None:
    model = ApplicationModel()
    first = AppModelEntity(
        id="appmodel-endpoint:x",
        kind=AppModelEntityKind.ENDPOINT,
        label="endpoint:x",
        provenance=DiscoveryProvenance.OBSERVED,
        evidence_refs=["obs-1"],
    )
    model.add_entity(first)
    declared = AppModelEntity(
        id="appmodel-endpoint:x",
        kind=AppModelEntityKind.ENDPOINT,
        label="endpoint:x",
        provenance=DiscoveryProvenance.DECLARED,
        evidence_refs=["declared-1"],
    )
    model.add_entity(declared)
    merged = model.entities["appmodel-endpoint:x"]
    assert merged.provenance == "declared"
    assert set(merged.evidence_refs) == {"obs-1", "declared-1"}


# ---------------------------------------------------------------------------
# 3. The builder derives from real channels
# ---------------------------------------------------------------------------


def test_builder_derives_the_full_spine_from_real_state() -> None:
    model = build_application_model(_state())
    kinds = {e.kind for e in model.entities.values()}
    assert "organization" in kinds
    assert "tenant" in kinds
    assert "application" in kinds
    assert "endpoint" in kinds
    assert "identity" in kinds
    # Endpoints from all three crawled sources.
    endpoint_labels = {
        e.label for e in model.entities.values() if e.kind == "endpoint"
    }
    assert any("/api/v2/users" in label for label in endpoint_labels)
    assert any("/dashboard" in label for label in endpoint_labels)
    assert any("/api/internal/admin" in label for label in endpoint_labels)
    # The org→tenant relation is declared; app→endpoint observed.
    relation_kinds = {r.kind for r in model.relations}
    assert {"contains", "hosts", "authenticates_as"} <= relation_kinds


def test_builder_records_honest_coverage_gaps_when_channels_absent() -> None:
    model = build_application_model({"engagement_id": "eng-thin"})
    assert "appmodel_no_endpoints_derived" in model.coverage_gaps
    assert "appmodel_no_identities_derived" in model.coverage_gaps
    assert "appmodel_no_observations_derived" in model.coverage_gaps


def test_builder_is_fail_soft_on_structurally_odd_state() -> None:
    model = build_application_model(
        {"crawled_data": "not-a-dict", "identity_profiles": 42}
    )
    assert isinstance(model, ApplicationModel)
    assert model.entities  # org + tenant always exist (declared)


# ---------------------------------------------------------------------------
# 4. The attack-graph abstraction
# ---------------------------------------------------------------------------


def test_projection_speaks_the_attack_graph_vocabulary() -> None:
    model = build_application_model(_state())
    projection = model.to_attack_graph_projection()
    assert set(projection["nodes"]) == set(model.entities)
    assert projection["generated_from"] == ["appmodel"]
    allowed_kinds = {
        "asset", "endpoint", "workflow", "identity", "state",
        "permission", "privilege", "resource", "action", "impact",
        "object", "finding", "hypothesis",
    }
    assert all(node["kind"] in allowed_kinds for node in projection["nodes"].values())
    # Every projected edge carries evidence by construction.
    assert all(edge["evidence_refs"] for edge in projection["edges"])
    assert all(edge["confidence"].startswith("appmodel_") for edge in projection["edges"])


def test_merge_into_built_attack_graph_is_additive() -> None:
    state = _state()
    graph = build_attack_graph(
        None,
        relational_evidence=[
            {
                "resource_url": f"{TARGET}/api/v2/users",
                "from_identity": "identity-alice",
                "from_accessible": True,
                "evidence_refs": ["obs-rel-1"],
            }
        ],
    )
    before_nodes = set(graph["nodes"])
    before_edges = len(graph["edges"])
    appmodel = build_application_model(state)
    merged = merge_appmodel_into_attack_graph(graph, appmodel)
    # Nothing removed...
    assert before_nodes <= set(merged["nodes"])
    assert len(merged["edges"]) >= before_edges
    # ...appmodel entities added under their own id space...
    assert any(n.startswith("appmodel-") for n in merged["nodes"])
    # ...and the provenance is recorded.
    assert "appmodel" in merged["generated_from"]


def test_no_graph_database_anywhere() -> None:
    """Part 4 §5: relational truth stays in-memory (structural contract:
    no graph-DB driver import or client usage — prose mentions allowed)."""
    from pathlib import Path

    package = Path("src/webpent/appmodel")
    sources = "\n".join(p.read_text(encoding="utf-8") for p in package.glob("*.py"))
    for forbidden in (
        "import neo4j",
        "from neo4j",
        "GraphDatabase",
        "import gremlin",
        "from gremlin",
        "neo4j://",
        "bolt://",
    ):
        assert forbidden not in sources
