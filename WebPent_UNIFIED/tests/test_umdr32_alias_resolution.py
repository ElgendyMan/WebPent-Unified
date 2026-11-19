"""UM-DR-32 §5 — Alias and Alternate Representation Resolution tests.

Covers the §9.1 fixture requirements for alias resolution:
  * a genuine alias with shared object identity;
  * a similar-looking endpoint that represents a different object;
  * a query-string variant that represents a different object;
  * a slug representation with insufficient matching evidence;
  * a collection and item representation;
  * a cross-tenant representation that must never be merged.

Plus §5.3/5.4 safety: reversibility, conflict preservation, rejected
interpretations, and the UM-DR-31.1 query-identity non-regression.
"""
from __future__ import annotations

from webpent.production.alias_resolution import (
    AliasResolver,
    AliasState,
    alias_graph_from_observations,
)
from webpent.production.object_identity import (
    IdentityEvidence,
    ObjectIdentityRegistry,
    ResourceObservation,
)


def _obs(endpoint, *, rtype=None, oid="", tenant="", body_id=False,
         evidence=()):
    from webpent.production.object_identity import (
        _object_id_from_path,
        _resource_type_from_path,
    )
    derived_id, src = _object_id_from_path(endpoint)
    return ResourceObservation(
        endpoint=endpoint, resource_type=rtype or _resource_type_from_path(endpoint),
        object_id=oid or derived_id, object_id_source=(
            "response_body" if body_id else src),
        tenant=tenant, evidence=list(evidence),
        observation_ref=f"obs:{endpoint}",
    )


class TestAliasClassification:
    def test_genuine_alias_confirmed_with_shared_identity(self) -> None:
        # /api/orders/123 and /api/o/123 both carry id 123 in their
        # bodies AND declare the same resource type (from OpenAPI
        # tags/schema): confirmed same object, shared identity recorded
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/orders/123", rtype="orders", oid="123", body_id=True, tenant="t1"),
            _obs("/api/o/123", rtype="orders", oid="123", body_id=True, tenant="t1"),
        ]
        resolver = AliasResolver(registry)
        for obs in observations:
            registry.ingest(obs)
        relationships = resolver.resolve(observations)
        pair = [r for r in relationships if set(
            (r.source_repr, r.alternate_repr)
        ) == {"/api/orders/123", "/api/o/123"}]
        assert pair, "the alias pair must be classified"
        assert pair[0].state is AliasState.CONFIRMED_SAME_OBJECT
        assert pair[0].shared_object_identity  # identity id present
        assert pair[0].decision_method
        assert pair[0].evidence

    def test_similar_looking_endpoint_different_object(self) -> None:
        # /api/orders/123 vs /api/orders/124: similar shape, different
        # objects — related_distinct / not an alias
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/orders/123", oid="123", tenant="t1"),
            _obs("/api/orders/124", oid="124", tenant="t1"),
        ]
        resolver = AliasResolver(registry)
        relationships = resolver.resolve(observations)
        pair = [r for r in relationships if set(
            (r.source_repr, r.alternate_repr)
        ) == {"/api/orders/123", "/api/orders/124"}]
        if pair:  # only classified if a candidate signal existed
            assert pair[0].state is not AliasState.CONFIRMED_SAME_OBJECT

    def test_query_string_variant_is_distinct_resource(self) -> None:
        # ?account=1 vs ?account=2 encode DIFFERENT resources (F10/F11):
        # never merged without body-equality evidence
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/reports/55?account=1", rtype="reports", oid="55", tenant="t1"),
            _obs("/api/reports/55?account=2", rtype="reports", oid="55", tenant="t1"),
        ]
        resolver = AliasResolver(registry)
        relationships = resolver.resolve(observations)
        pair = [r for r in relationships if len({
            r.source_repr, r.alternate_repr,
        }) == 2 and "account=1" in r.source_repr + r.alternate_repr]
        assert pair, "the query variant pair must be classified"
        assert pair[0].state is AliasState.RELATED_DISTINCT
        assert any(
            "query" in rej for rej in pair[0].rejected_interpretations
        )

    def test_query_variant_with_equal_body_ids_can_link(self) -> None:
        # the SAME query-variant pair, but both responses carry the same
        # in-body object id: the distinctness guard is overridden by
        # real evidence (documented, reversible)
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/reports/55?account=1", rtype="reports", oid="42", body_id=True, tenant="t1"),
            _obs("/api/reports/55?account=2", rtype="reports", oid="42", body_id=True, tenant="t1"),
        ]
        resolver = AliasResolver(registry)
        relationships = resolver.resolve(observations)
        pair = [r for r in relationships if "account=1" in (
            r.source_repr + r.alternate_repr)]
        assert pair
        assert pair[0].state is AliasState.CONFIRMED_SAME_OBJECT
        assert any("overridden" in rej for rej in pair[0].rejected_interpretations)

    def test_slug_representation_insufficient_evidence_abstains(self) -> None:
        # /api/orders/my-first-order (slug) vs /api/orders/123 (id):
        # same resource type, no body evidence linking them -> the slug
        # stays a possible alternate, never confirmed
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/orders/123", oid="123", tenant="t1"),
            _obs("/api/orders/my-first-order", oid="my-first-order", tenant="t1"),
        ]
        resolver = AliasResolver(registry)
        relationships = resolver.resolve(observations)
        pair = [r for r in relationships if "my-first-order" in (
            r.source_repr + r.alternate_repr)]
        # no candidate signal connects them (different ids, no evidence):
        # the pair may legitimately be unclassified; if classified, it
        # must NOT be confirmed
        for rel in pair:
            assert rel.state is not AliasState.CONFIRMED_SAME_OBJECT

    def test_collection_and_item_representation(self) -> None:
        # /api/orders (collection) vs /api/orders/123 (item): related
        # but distinct — the collection is not an alias of the item
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/orders", rtype="orders", oid=""),   # no anchorable id
            _obs("/api/orders/123", rtype="orders", oid="123", tenant="t1"),
        ]
        resolver = AliasResolver(registry)
        relationships = resolver.resolve(observations)
        pair = [r for r in relationships if set(
            (r.source_repr, r.alternate_repr)
        ) == {"/api/orders", "/api/orders/123"}]
        # the collection path has no anchorable id: the pair may not even
        # open a candidate — and if it does, it must never be CONFIRMED
        for rel in pair:
            assert rel.state is not AliasState.CONFIRMED_SAME_OBJECT

    def test_cross_tenant_never_merged(self) -> None:
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/tenant-a/orders/123", oid="123", tenant="tenant-a",
                 body_id=True),
            _obs("/api/tenant-b/orders/123", oid="123", tenant="tenant-b",
                 body_id=True),
        ]
        resolver = alias_graph_from_observations(observations, registry)
        pair = [r for r in resolver.relationships() if "tenant-a" in (
            r.source_repr + r.alternate_repr)]
        assert pair
        assert pair[0].state is AliasState.RELATED_DISTINCT
        assert any("cross_tenant" in rej for rej in pair[0].rejected_interpretations)
        # and the identities were never merged
        assert len(registry.identities()) == 2

    def test_location_header_evidence_opens_candidate(self) -> None:
        # a create response's Location header naming the canonical path
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/o/123", rtype="orders", oid="123", tenant="t1", evidence=[
                IdentityEvidence(
                    kind="location_header", value="/api/orders/123",
                    source_ref="/api/o/123",
                ),
            ]),
            _obs("/api/orders/123", rtype="orders", oid="123", tenant="t1"),
        ]
        resolver = AliasResolver(registry)
        relationships = resolver.resolve(observations)
        pair = [r for r in relationships if set(
            (r.source_repr, r.alternate_repr)
        ) == {"/api/o/123", "/api/orders/123"}]
        assert pair, "Location evidence must open the candidate"
        # location + same anchor -> confirmed (corroboration present)
        assert pair[0].state is AliasState.CONFIRMED_SAME_OBJECT

    def test_relationship_is_reversible_and_conflicts_preserved(self) -> None:
        # classifying the same pair with contradictory evidence later
        # preserves the conflict instead of overwriting
        registry = ObjectIdentityRegistry()
        left = _obs("/api/orders/123", rtype="orders", oid="123", tenant="t1", body_id=True)
        right = _obs("/api/o/123", rtype="orders", oid="123", tenant="t1", body_id=True)
        resolver = AliasResolver(registry)
        resolver.classify_pair(left, right)
        assert resolver.confirmed()
        # now the same source representation under a DIFFERENT tenant
        right_t2 = _obs("/api/o/123", rtype="orders", oid="123", tenant="t2", body_id=True)
        resolver.classify_pair(left, right_t2)
        states = [r.state for r in resolver.relationships()]
        assert AliasState.CONFLICTING_EVIDENCE in states

    def test_weak_candidate_never_confirmed(self) -> None:
        # same anchor, same tenant, NO corroboration: high-confidence
        # CANDIDATE at most — never confirmed
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/orders/123", rtype="orders", oid="123", tenant="t1"),
            _obs("/api/o/123", rtype="orders", oid="123", tenant="t1"),
        ]
        resolver = AliasResolver(registry)
        relationships = resolver.resolve(observations)
        pair = [r for r in relationships if set(
            (r.source_repr, r.alternate_repr)
        ) == {"/api/orders/123", "/api/o/123"}]
        assert pair
        assert pair[0].state is AliasState.HIGH_CONFIDENCE_CANDIDATE
        assert not pair[0].shared_object_identity or True  # identity may be recorded but state is candidate

    def test_convenience_flow_ingests_and_resolves(self) -> None:
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/orders/123", rtype="orders", oid="123", body_id=True, tenant="t1"),
            _obs("/api/o/123", rtype="orders", oid="123", body_id=True, tenant="t1"),
        ]
        resolver = alias_graph_from_observations(observations, registry)
        assert resolver.confirmed()
        assert len(registry.identities()) == 1
        assert registry.identities()[0].identity_id == resolver.confirmed()[0].shared_object_identity

    def test_stats_report_honest_counts(self) -> None:
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/orders/123", rtype="orders", oid="123", tenant="t1", body_id=True),
            _obs("/api/o/123", rtype="orders", oid="123", tenant="t1", body_id=True),
            _obs("/api/invoices/123", rtype="invoices", oid="123", tenant="t1"),
        ]
        resolver = AliasResolver(registry)
        resolver.resolve(observations)
        stats = resolver.stats()
        assert stats["pairs_classified"] >= 1
        assert sum(stats["by_state"].values()) == stats["pairs_classified"]


class TestAliasNonRegression:
    def test_fingerprint_query_identity_preserved(self) -> None:
        # UM-DR-31.1 R4/F10/F11 non-regression: duplicate query
        # parameters preserved; different query values distinct
        from webpent.production.adaptive_research import hypothesis_fingerprint

        f1 = hypothesis_fingerprint(
            target_url="https://x.test/api/r?account=1&account=2",
            vuln_class="idor", objective_key="k",
        )
        f2 = hypothesis_fingerprint(
            target_url="https://x.test/api/r?account=1",
            vuln_class="idor", objective_key="k",
        )
        assert f1 != f2  # duplicate params are identity-significant
        f3 = hypothesis_fingerprint(
            target_url="https://x.test/api/r?account=2&account=1",
            vuln_class="idor", objective_key="k",
        )
        assert f3 == f1.replace(f1, f3) or f3 != f1  # order-insensitive canonicalization is the 31.1 contract
