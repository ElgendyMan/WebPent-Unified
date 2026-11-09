from webpent.shared.application_intent_graph import build_application_intent_model
from webpent.shared.surface_security import analyze_security_surface


def _sample(route: str) -> dict[str, object]:
    return {
        "endpoints": [route],
        "requests": [
            {
                "method": "POST",
                "title": "Create order",
                "workflow": "order_checkout",
                "state": "cart",
                "next_state": "paid",
                "role": "owner",
                "requires_auth": True,
                "fields": {"order_id": "1", "payment_method": "card"},
                "sink": "payment service",
            }
        ],
        "identity_matrix": [{"role": "owner"}],
    }


def test_identity_matrix_is_bounded_and_does_not_claim_missing_accounts():
    model = build_application_intent_model(_sample("https://app.test/orders/1"))

    assert [item.role for item in model.identities] == [
        "anonymous",
        "owner",
        "foreign_user",
        "tenant_admin",
        "global_admin",
    ]
    assert model.identities[1].disposition == "observed"
    assert model.identities[2].disposition == "not_observed"
    assert model.bounded is True
    assert model.passive_only is True


def test_semantic_intent_fingerprint_survives_route_renaming():
    first = build_application_intent_model(_sample("https://app.test/orders/1"))
    renamed = build_application_intent_model(_sample("https://app.test/checkout/opaque"))

    assert [node.node_id for node in first.state_transitions] == [
        node.node_id for node in renamed.state_transitions
    ]
    assert [node.label for node in first.objects] == [node.label for node in renamed.objects]


def test_graph_redacts_secret_like_input_and_exposes_causal_edges():
    data = _sample("https://app.test/orders/1?token=super-secret")
    data["requests"][0]["fields"]["api_key"] = "should-not-appear"
    model = build_application_intent_model(data)
    serialized = model.model_dump_json()

    assert "super-secret" not in serialized
    assert "should-not-appear" not in serialized
    assert model.edges
    assert any(edge.relation == "has_field" for edge in model.edges)


def test_surface_summary_contains_additive_typed_intent_model():
    summary = analyze_security_surface(_sample("https://app.test/orders/1"), "https://app.test")

    assert summary["application_intent_model"]["schema_version"] == "application-intent-v1"
    assert summary["application_intent_model"]["passive_only"] is True
    assert summary["application_intent"]


def test_surface_graph_is_typed_bounded_and_has_disposition_for_each_node():
    data = _sample("https://app.test/orders/1")
    data["xhr_requests"] = [{"route": "/api/orders", "method": "POST"}]
    data["openapi_routes"] = [{"route": "/api/orders", "name": "create_order"}]
    data["graphql_operations"] = [{"name": "OrderQuery"}]
    data["service_fingerprints"] = [{"service": "redis"}]

    summary = analyze_security_surface(data, "https://app.test")
    graph = summary["surface_graph"]
    node_ids = {node["node_id"] for node in graph["nodes"]}
    queue_ids = {item["node_id"] for item in graph["disposition_queue"]}

    assert graph["schema_version"] == "surface-evidence-graph-v1"
    assert graph["passive_only"] is True
    assert node_ids <= queue_ids
    assert all(item["disposition"] == "needs_validator" for item in graph["disposition_queue"])
    assert any(node["node_type"] == "graphql_operation" for node in graph["nodes"])
    assert any(node["node_type"] == "service_fingerprint" for node in graph["nodes"])


def test_surface_graph_redacts_query_values():
    data = {"endpoints": ["https://app.test/export?token=secret-value"]}
    summary = analyze_security_surface(data, "https://app.test")
    serialized = str(summary["surface_graph"])

    assert "secret-value" not in serialized
    assert "[REDACTED]" in serialized
