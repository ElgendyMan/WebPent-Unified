from __future__ import annotations

from webpent.config.settings import get_settings
from webpent.graph.builder import build_graph
from webpent.shared.attack_graph import _mental_node_id, build_attack_graph


def _clear_settings_cache() -> None:
    get_settings.cache_clear()


def test_attack_graph_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ENABLE_ATTACK_GRAPH", raising=False)
    _clear_settings_cache()
    graph = build_graph(auto_approve=True)
    assert "attack_graph" not in graph.nodes


def test_attack_graph_node_is_registered_only_when_enabled(monkeypatch):
    monkeypatch.setenv("ENABLE_ATTACK_GRAPH", "true")
    _clear_settings_cache()
    graph = build_graph(auto_approve=True)
    assert "attack_graph" in graph.nodes
    assert "strategist" in graph.nodes


def test_hypothesis_target_edge_uses_existing_endpoint_id():
    endpoint_id = _mental_node_id(
        "endpoint", "https://example.test/items?id=1"
    )
    mental_model = {
        "nodes": {
            endpoint_id: {
                "id": endpoint_id,
                "kind": "endpoint",
                "identity_key": "https://example.test/items?id=1",
                "discovery_source": "crawler_node",
                "in_scope": True,
                "metadata": {},
            }
        },
        "edges": [],
    }
    graph = build_attack_graph(
        mental_model,
        hypotheses=[
            {
                "id": "h-1",
                "title": "Bounded workflow hypothesis",
                "url": "https://example.test/items?id=1",
                "status": "unexplored",
                "priority": "medium",
                "origin": "workflow_understanding",
            }
        ],
    )
    assert any(
        edge["kind"] == "hypothesis_targets"
        and edge["source_id"] == "hypothesis:h-1"
        for edge in graph["edges"]
    )


def teardown_module():
    _clear_settings_cache()
