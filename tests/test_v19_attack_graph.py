"""Contract tests for the additive Attack Graph projection."""

import json

from webpent.shared.attack_graph import build_attack_graph


def test_attack_graph_projects_relational_evidence_without_raw_secrets() -> None:
    state = {
        "nodes": {
            "endpoint-legacy": {
                "id": "endpoint-legacy",
                "kind": "endpoint",
                "identity_key": "https://lab.local/orders",
                "discovery_source": "crawler",
                "in_scope": True,
                "criticality": "low",
                "metadata": {"method": "GET"},
            }
        },
        "edges": [],
    }
    relational = [
        {
            "from_identity": "buyer-session-secret",
            "to_identity": "support-session-secret",
            "owner_identity": "buyer-session-secret",
            "resource_url": "https://lab.local/orders/42?token=should-not-persist",
            "differential": True,
            "from_accessible": True,
            "to_accessible": True,
            "evidence_refs": ["obs:bac:42"],
            "authorization": "Bearer raw-secret-must-not-persist",
        }
    ]

    result = build_attack_graph(state, relational_evidence=relational)
    serialized = json.dumps(result, sort_keys=True)

    assert result["version"] == "1"
    assert any(node["kind"] == "endpoint" for node in result["nodes"].values())
    assert any(node["kind"] == "identity" for node in result["nodes"].values())
    assert any(edge["kind"] == "identity_resource_access" for edge in result["edges"])
    assert any(edge["confidence"] == "relational_differential" for edge in result["edges"])
    assert "should-not-persist" not in serialized
    assert "raw-secret-must-not-persist" not in serialized
    assert "buyer-session-secret" not in serialized


def test_attack_graph_is_deterministic_and_does_not_create_findings() -> None:
    state = {"nodes": {}, "edges": []}
    relational = [
        {
            "from_identity": "user-a",
            "resource_url": "https://lab.local/profile",
            "evidence_refs": ["obs:one"],
        }
    ]

    first = build_attack_graph(state, relational_evidence=relational)
    second = build_attack_graph(state, relational_evidence=relational)

    assert first == second
    assert not any(node["kind"] == "finding" for node in first["nodes"].values())
    assert first["edges"]
