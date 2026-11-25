"""UM-DR-47 Phase F2.3 — protocol depth: GraphQL→SKG, WS, OAuth.

F2.3: "GraphQL schema يدخل الـSKG ككيانات، WebSocket sessions تُتتبع
كحالات، OAuth/OIDC flows تُنمذجة كtrust boundaries — والعلاقات المتقاطعة
(صلاحية OAuth على GraphQL mutation) تُختبر بفرضية واحدة على الأقل."
"""
from __future__ import annotations

from webpent.production.brain_engine import (
    brain_engine_node,
    build_brain_context,
)
from webpent.researcher.protocol_depth import (
    cross_surface_hypothesis,
    graphql_skg_records,
    oauth_trust_boundary_records,
    websocket_session_records,
)

CRAWLED_GRAPHQL_OAUTH = {
    "openapi_routes": [
        {"method": "GET", "path": "/api/invoices/INV-A-101"},
        {"method": "GET", "path": "/api/invoices/INV-B-777"},
    ],
    "graphql_operations": [
        {"operation": "updateInvoice", "kind": "mutation",
         "container": "Mutation", "args": [{"name": "id"}, {"name": "input"}]},
        {"operation": "invoice", "kind": "query",
         "container": "Query", "args": [{"name": "id"}]},
    ],
    "oauth_endpoints": [
        {"path": "/oauth/authorize", "grant_type": "authorization_code"},
    ],
    "ws_endpoints": ["/ws/notifications"],
}


class TestGraphqlToSkg:
    def test_introspected_operations_become_records(self):
        records = graphql_skg_records(CRAWLED_GRAPHQL_OAUTH)
        assert len(records) == 2
        mutation = next(r for r in records
                        if r["operation_kind"] == "mutation")
        assert mutation["operation_name"] == "updateInvoice"
        assert mutation["evidence_refs"] == [
            "graphql-introspection:Mutation.updateInvoice"]

    def test_records_reach_the_skg_context(self):
        ctx = build_brain_context({
            "target_url": "https://shop.example",
            "crawled_data": CRAWLED_GRAPHQL_OAUTH,
        })
        assert ctx.built
        kinds = {e.kind for e in ctx.model.entities.values()}
        assert kinds, "context built an empty model"


class TestWebsocketSessions:
    def test_ws_endpoints_become_stateful_workflow_records(self):
        records = websocket_session_records(CRAWLED_GRAPHQL_OAUTH)
        assert records
        assert records[0]["from_state"] == "disconnected"
        assert records[0]["to_state"] == "connected"
        assert records[0]["workflow_key"].startswith("websocket-session:")


class TestOauthTrustBoundaries:
    def test_oauth_endpoints_become_boundary_records(self):
        records = oauth_trust_boundary_records(CRAWLED_GRAPHQL_OAUTH)
        assert records
        assert records[0]["boundary"] == "identity_provider"
        assert records[0]["grant_type"] == "authorization_code"

    def test_identity_profiles_declaring_providers_count(self):
        records = oauth_trust_boundary_records(
            CRAWLED_GRAPHQL_OAUTH,
            {"service-account": {"oauth_provider": "idp.example"}},
        )
        assert any(r["boundary"] == "idp.example" for r in records)


class TestCrossSurfaceHypothesis:
    def test_the_oath_on_graphql_mutation_hypothesis(self):
        """THE F2.3 required hypothesis: OAuth-delegated permission on a
        GraphQL mutation — emitted when both surfaces are evidenced."""
        from webpent.appmodel.skg import build_security_knowledge_graph

        model = build_security_knowledge_graph(
            {"crawled_data": CRAWLED_GRAPHQL_OAUTH})
        hyp = cross_surface_hypothesis(model, CRAWLED_GRAPHQL_OAUTH)
        assert hyp is not None
        assert "updateInvoice" in hyp["statement"]
        assert "OAuth" in hyp["statement"] or "delegated" in hyp["statement"]
        assert hyp["vuln_class"] == "auth_bypass"
        assert hyp["evidence_contract"]["evidence_refs"]

    def test_no_both_surfaces_no_hypothesis(self):
        hyp = cross_surface_hypothesis(None, {"graphql_operations": [
            {"operation": "x", "kind": "mutation", "container": "M"}]})
        assert hyp is None

    def test_hypothesis_reaches_the_node_pool(self):
        update = brain_engine_node({
            "target_url": "https://shop.example",
            "crawled_data": CRAWLED_GRAPHQL_OAUTH,
        })
        pool = update["hypotheses"]
        f23 = [h for h in pool if "UM-DR-47 F2.3" in str(h.origin_detail)]
        assert f23, "the cross-protocol hypothesis did not reach the pool"
        assert update["brain_engine"]["f23_cross_surface_hypothesis"] is True

    def test_node_without_protocol_surfaces_skips_honestly(self):
        update = brain_engine_node({
            "target_url": "https://shop.example",
            "crawled_data": {"openapi_routes": [
                {"method": "GET", "path": "/a"}, {"method": "GET", "path": "/b"},
            ]},
        })
        assert update["brain_engine"]["f23_cross_surface_hypothesis"] is False
