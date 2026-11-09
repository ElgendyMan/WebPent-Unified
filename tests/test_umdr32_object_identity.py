"""UM-DR-32 §4 — Object Identity Intelligence tests.

Covers the §9.1 fixture requirements for object identity:
  * two different endpoints representing the same object;
  * two different objects with identical numeric identifiers but
    distinct namespaces;
  * two resource types with identical numeric identifiers;
  * one object with multiple observed representations;
  * an ambiguous identity that must produce abstention;

plus the safety rules of §4.3/§4.4 and determinism.
"""
from __future__ import annotations

from webpent.production.object_identity import (
    IdentityEvidence,
    IdentityRelationshipKind,
    IdentityResolutionStatus,
    ObjectIdentityRegistry,
    ResourceObservation,
    observations_from_campaign_state,
)


def _obs(endpoint, *, rtype="orders", oid="123", tenant="", body_id=False,
         evidence=(), attributes=None, method="GET"):
    return ResourceObservation(
        endpoint=endpoint, method=method, resource_type=rtype,
        object_id=oid, object_id_source=(
            "response_body" if body_id else "path_segment"),
        tenant=tenant, evidence=list(evidence),
        attributes=attributes or {},
        observation_ref=f"obs:{endpoint}",
    )


class TestObjectIdentityModel:
    def test_same_object_two_endpoints_with_corroboration(self) -> None:
        # §9.1: /api/orders/123 and /api/o/123 are the SAME object when
        # both bodies carry the same object id (cross-endpoint evidence)
        registry = ObjectIdentityRegistry()
        left = _obs("/api/orders/123", body_id=True)
        right = _obs("/api/o/123", body_id=True)
        registry.ingest(left)
        registry.ingest(right)
        rel = registry.relate(left, right)
        assert rel.kind is IdentityRelationshipKind.ALTERNATE_REPRESENTATION
        # both representations resolve to ONE identity
        ids = {i.identity_id for i in registry.identities()}
        assert len(ids) == 1
        ident = registry.identities()[0]
        assert sorted(ident.representations) == [
            "/api/o/123", "/api/orders/123",
        ]

    def test_identical_numeric_id_different_tenants_never_merges(self) -> None:
        registry = ObjectIdentityRegistry()
        left = _obs("/api/tenant-a/orders/123", tenant="tenant-a")
        right = _obs("/api/tenant-b/orders/123", tenant="tenant-b")
        registry.ingest(left)
        registry.ingest(right)
        rel = registry.relate(left, right)
        assert rel.kind is (
            IdentityRelationshipKind.SAME_IDENTIFIER_DIFFERENT_NAMESPACE
        )
        assert len(registry.identities()) == 2  # two distinct identities

    def test_identical_id_different_resource_types_distinct(self) -> None:
        registry = ObjectIdentityRegistry()
        left = _obs("/api/orders/123", rtype="orders")
        right = _obs("/api/invoices/123", rtype="invoices")
        registry.ingest(left)
        registry.ingest(right)
        rel = registry.relate(left, right)
        assert rel.kind is IdentityRelationshipKind.DISTINCT_OBJECT

    def test_same_type_same_id_linked_by_api_reference_is_related(self) -> None:
        registry = ObjectIdentityRegistry()
        left = _obs("/api/orders/123", rtype="orders")
        right = _obs("/api/invoices/123", rtype="invoices", evidence=[
            IdentityEvidence(
                kind="api_resource_reference", value="orders:123",
                source_ref="/api/invoices/123",
            ),
        ])
        registry.ingest(left)
        registry.ingest(right)
        rel = registry.relate(left, right)
        # different types but EXPLICIT reference: related, not merged
        assert rel.kind is IdentityRelationshipKind.RELATED_OBJECT
        assert len(registry.identities()) == 2

    def test_multiple_representations_one_identity(self) -> None:
        registry = ObjectIdentityRegistry()
        obs_list = [
            _obs("/api/orders/123", body_id=True),
            _obs("/api/o/123", body_id=True),
            _obs("/api/order-details/123", body_id=True),
        ]
        for obs in obs_list:
            registry.ingest(obs)
        for i in range(len(obs_list)):
            for j in range(i + 1, len(obs_list)):
                rel = registry.relate(obs_list[i], obs_list[j])
                assert rel.kind is (
                    IdentityRelationshipKind.ALTERNATE_REPRESENTATION
                )
        assert len(registry.identities()) == 1
        assert len(registry.identities()[0].representations) == 3

    def test_ambiguous_identity_abstains(self) -> None:
        # same id, same type, tenant UNKNOWN on one side, no corroboration
        registry = ObjectIdentityRegistry()
        left = _obs("/api/orders/123", tenant="")
        right = _obs("/api/o/123", tenant="tenant-a")
        registry.ingest(left)
        registry.ingest(right)
        rel = registry.relate(left, right)
        assert rel.kind is IdentityRelationshipKind.AMBIGUOUS_IDENTITY
        assert registry.abstentions()
        # abstention does NOT merge
        assert len(registry.identities()) == 2

    def test_path_similarity_alone_never_merges(self) -> None:
        # two similar-looking paths with DIFFERENT ids: distinct, and no
        # relationship is manufactured from similarity
        registry = ObjectIdentityRegistry()
        left = _obs("/api/orders/123", oid="123")
        right = _obs("/api/orders/124", oid="124")
        registry.ingest(left)
        registry.ingest(right)
        rel = registry.relate(left, right)
        assert rel.kind is IdentityRelationshipKind.DISTINCT_OBJECT

    def test_numeric_id_match_alone_opens_candidate_not_merge(self) -> None:
        # same id, same type, same tenant, but NO corroborating evidence:
        # recorded as same_object candidate with note, not confirmed
        registry = ObjectIdentityRegistry()
        left = _obs("/api/orders/123", tenant="t1")
        right = _obs("/api/o/123", tenant="t1")
        registry.ingest(left)
        registry.ingest(right)
        rel = registry.relate(left, right)
        assert rel.kind is IdentityRelationshipKind.SAME_OBJECT
        assert "no corroboration" in rel.note

    def test_attribute_contradiction_preserved(self) -> None:
        registry = ObjectIdentityRegistry()
        left = _obs("/api/orders/123", tenant="t1", attributes={
            "created": "2026-01-01", "amount": 100,
        })
        right = _obs("/api/o/123", tenant="t1", attributes={
            "created": "2026-02-02", "amount": 100,
        })
        registry.ingest(left)
        registry.ingest(right)
        rel = registry.relate(left, right)
        # contradiction preserved: ambiguous with explicit note
        assert rel.kind is IdentityRelationshipKind.AMBIGUOUS_IDENTITY
        assert "created" in rel.note

    def test_conflicting_decisions_preserved_not_overwritten(self) -> None:
        registry = ObjectIdentityRegistry()
        # one pair of endpoints gets related twice with different kinds
        # via different observations — the conflict is preserved
        left = _obs("/api/orders/123", tenant="t1")
        right = _obs("/api/o/123", tenant="t1")
        registry.relate(left, right)  # same_object
        # now with contradicting tenant evidence
        left2 = _obs("/api/orders/123", tenant="t1")
        right2 = _obs("/api/o/123", tenant="t2")
        registry.relate(left2, right2)  # same_identifier_different_namespace
        assert registry.conflicts()  # both decisions preserved

    def test_evidence_provenance_carried_on_relationships(self) -> None:
        evidence = [IdentityEvidence(
            kind="canonical_link", value="/api/orders/123",
            source_ref="/api/o/123", observation_ref="fp-1",
        )]
        registry = ObjectIdentityRegistry()
        left = _obs("/api/orders/123", body_id=True)
        right = _obs("/api/o/123", body_id=True, evidence=evidence)
        registry.ingest(left)
        registry.ingest(right)
        rel = registry.relate(left, right)
        assert rel.evidence
        assert any(e.kind == "canonical_link" for e in rel.evidence)
        assert any(e.observation_ref == "fp-1" for e in rel.evidence)

    def test_resolution_is_deterministic_regardless_of_ingest_order(self) -> None:
        observations = [
            _obs("/api/orders/123", body_id=True, tenant="t1"),
            _obs("/api/o/123", body_id=True, tenant="t1"),
            _obs("/api/tenant-b/orders/123", tenant="t2"),
            _obs("/api/invoices/123", rtype="invoices", tenant="t1"),
        ]
        r1, r2 = ObjectIdentityRegistry(), ObjectIdentityRegistry()
        for obs in observations:
            r1.ingest(obs)
        for obs in reversed(observations):
            r2.ingest(obs)
        assert [i.identity_id for i in r1.identities()] == [
            i.identity_id for i in r2.identities()
        ]
        assert r1.stats() == r2.stats()

    def test_identity_id_is_path_independent(self) -> None:
        registry = ObjectIdentityRegistry()
        registry.ingest(_obs("/api/very/long/path/orders/123", body_id=True))
        registry.ingest(_obs("/o/123", body_id=True))
        # same anchor (tenant "", orders, 123) -> same identity id even
        # though the paths are completely different
        assert len(registry.identities()) == 1

    def test_volatile_and_secret_attributes_excluded(self) -> None:
        registry = ObjectIdentityRegistry()
        registry.ingest(_obs("/api/orders/123", attributes={
            "ts": 12345, "request_id": "abc", "amount": 42,
            "api_token": "secret", "name": "order-42",
        }))
        ident = registry.identities()[0]
        assert "amount" in ident.attributes
        assert "name" in ident.attributes
        assert "ts" not in ident.attributes
        assert "request_id" not in ident.attributes
        assert "api_token" not in ident.attributes

    def test_status_and_confidence_reported(self) -> None:
        registry = ObjectIdentityRegistry()
        registry.ingest(_obs("/api/orders/123", body_id=True, evidence=[
            IdentityEvidence(kind="canonical_link", value="x", source_ref="y"),
        ]))
        ident = registry.identities()[0]
        assert ident.status is IdentityResolutionStatus.RESOLVED_BY_EVIDENCE
        assert 0.5 <= ident.confidence <= 0.99

    def test_bounded_registry(self) -> None:
        registry = ObjectIdentityRegistry(max_identities=100)
        for i in range(400):
            registry.ingest(_obs(f"/api/orders/{i}", oid=str(i)))
        assert len(registry.identities()) <= 100
        assert registry.stats()["max_identities"] == 100


class TestCampaignStateIngestion:
    def test_openapi_routes_become_observations(self) -> None:
        state = {
            "crawled_data": {
                "openapi_routes": [
                    {"method": "GET", "path": "/api/orders/123"},
                    {"method": "GET", "path": "/api/orders/124"},
                    {"method": "POST", "path": "/api/orders"},  # collection: no id
                ],
            },
        }
        observations = observations_from_campaign_state(state)
        by_endpoint = {o.endpoint: o for o in observations}
        assert "/api/orders/123" in by_endpoint
        assert by_endpoint["/api/orders/123"].resource_type == "orders"
        assert by_endpoint["/api/orders/123"].object_id == "123"
        assert "/api/orders" not in by_endpoint  # no object id -> not anchored

    def test_workflow_observations_carry_tenant_and_evidence(self) -> None:
        state = {
            "workflow_observations": [
                {
                    "fingerprint": "fp" + "a" * 14,
                    "workflow_key": "order-approval",
                    "transition_key": "submit",
                    "endpoint": "/api/tenant-a/orders/501",
                    "method": "POST",
                    "tenant_ref": "tenant-a",
                    "authorization_boundary": "role_scoped",
                    "object_refs": ["501"],
                    "confidence": 0.7,
                },
            ],
        }
        observations = observations_from_campaign_state(state)
        assert len(observations) == 1
        obs = observations[0]
        assert obs.tenant == "tenant-a"
        assert obs.object_id == "501"
        assert obs.evidence and obs.evidence[0].kind == "workflow_reference"

    def test_nothing_fabricated_from_empty_state(self) -> None:
        assert observations_from_campaign_state({}) == []

    def test_query_string_is_not_part_of_resource_type(self) -> None:
        state = {
            "crawled_data": {"openapi_routes": [
                {"method": "GET", "path": "/api/orders/123?view=full"},
            ]},
        }
        observations = observations_from_campaign_state(state)
        assert observations[0].resource_type == "orders"
        assert observations[0].object_id == "123"
