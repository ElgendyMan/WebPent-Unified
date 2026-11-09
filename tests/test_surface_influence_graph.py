"""Project Zero-tier item 2 — Attack surface dependency graph.

Pins:
  * parameter VALUES never appear anywhere in the output, only names
    (the core security property of this module — verified against the
    raw JSON-serialised output, not just individual fields),
  * a parameter observed on N>1 distinct endpoints produces an
    InfluenceEdge for every pair of those endpoints,
  * a parameter observed on only 1 endpoint produces no influence
    edges,
  * low-signal boilerplate names (page, csrf token, ...) are flagged
    low_signal=True and excluded from shared_parameters even when they
    do recur across endpoints,
  * endpoint identity collapses query string into METHOD+path (so the
    same path hit with different parameter values is one endpoint,
    not many),
  * confidence scales with parameter-name specificity (longer/more
    specific names score higher than short generic ones),
  * parameters can be supplied via params dict, body_params/form_fields
    list, or the endpoint URL's own query string — all three paths
    are exercised.
"""

from __future__ import annotations

import json

from webpent.shared.surface_influence_graph import (
    build_surface_influence_graph,
)


def test_empty_input_returns_empty_graph() -> None:
    graph = build_surface_influence_graph(None)
    assert graph.endpoint_labels == []
    assert graph.parameters == []
    assert graph.influence_edges == []


def test_single_endpoint_no_shared_params() -> None:
    crawled = {"endpoints": [{"url": "https://x.test/a?foo=1", "method": "GET"}]}
    graph = build_surface_influence_graph(crawled)
    assert len(graph.endpoint_labels) == 1
    assert graph.influence_edges == []
    assert graph.shared_parameters == []


def test_shared_parameter_across_two_endpoints_produces_edge() -> None:
    crawled = {
        "endpoints": [
            {"url": "https://x.test/a?account_token=secret1", "method": "GET"},
            {"url": "https://x.test/b?account_token=secret2", "method": "GET"},
        ]
    }
    graph = build_surface_influence_graph(crawled)
    assert len(graph.influence_edges) == 1
    edge = graph.influence_edges[0]
    assert edge.param_name == "account_token"
    assert {edge.source_endpoint, edge.target_endpoint} == {
        "GET /a", "GET /b",
    }


def test_shared_parameter_across_three_endpoints_produces_three_edges() -> None:
    crawled = {
        "endpoints": [
            {"url": "https://x.test/a?account_token=v1", "method": "GET"},
            {"url": "https://x.test/b?account_token=v2", "method": "GET"},
            {"url": "https://x.test/c?account_token=v3", "method": "GET"},
        ]
    }
    graph = build_surface_influence_graph(crawled)
    # C(3,2) = 3 pairs
    assert len(graph.influence_edges) == 3


def test_no_parameter_values_ever_appear_in_output() -> None:
    crawled = {
        "endpoints": [
            {"url": "https://x.test/a?token=SUPERSECRETVALUE123", "method": "GET"},
            {"url": "https://x.test/b?token=ANOTHERSECRETVALUE456", "method": "GET"},
        ]
    }
    graph = build_surface_influence_graph(crawled)
    serialised = json.dumps(graph.as_dict())
    assert "SUPERSECRETVALUE123" not in serialised
    assert "ANOTHERSECRETVALUE456" not in serialised


def test_low_signal_param_flagged_and_excluded_from_shared() -> None:
    crawled = {
        "endpoints": [
            {"url": "https://x.test/a?page=1", "method": "GET"},
            {"url": "https://x.test/b?page=2", "method": "GET"},
        ]
    }
    graph = build_surface_influence_graph(crawled)
    page_param = next(p for p in graph.parameters if p.name == "page")
    assert page_param.low_signal is True
    assert page_param.endpoint_count == 2
    assert graph.shared_parameters == []
    assert graph.influence_edges == []


def test_csrf_token_variants_are_low_signal() -> None:
    crawled = {
        "endpoints": [
            {"url": "https://x.test/a", "method": "POST", "params": {"csrfmiddlewaretoken": "x"}},
            {"url": "https://x.test/b", "method": "POST", "params": {"csrfmiddlewaretoken": "y"}},
        ]
    }
    graph = build_surface_influence_graph(crawled)
    param = next(p for p in graph.parameters if p.name == "csrfmiddlewaretoken")
    assert param.low_signal is True


def test_same_path_different_query_values_is_one_endpoint() -> None:
    crawled = {
        "endpoints": [
            {"url": "https://x.test/search?q=cats", "method": "GET"},
            {"url": "https://x.test/search?q=dogs", "method": "GET"},
        ]
    }
    graph = build_surface_influence_graph(crawled)
    assert len(graph.endpoint_labels) == 1
    assert graph.endpoint_labels[0] == "GET /search"


def test_different_methods_same_path_are_distinct_endpoints() -> None:
    crawled = {
        "endpoints": [
            {"url": "https://x.test/resource", "method": "GET"},
            {"url": "https://x.test/resource", "method": "POST"},
        ]
    }
    graph = build_surface_influence_graph(crawled)
    assert len(graph.endpoint_labels) == 2
    assert "GET /resource" in graph.endpoint_labels
    assert "POST /resource" in graph.endpoint_labels


def test_params_supplied_via_dict_field() -> None:
    crawled = {
        "endpoints": [
            {"url": "https://x.test/a", "method": "POST", "params": {"invoice_ref": "x"}},
            {"url": "https://x.test/b", "method": "POST", "params": {"invoice_ref": "y"}},
        ]
    }
    graph = build_surface_influence_graph(crawled)
    assert any(p.name == "invoice_ref" and p.endpoint_count == 2 for p in graph.parameters)


def test_params_supplied_via_form_fields_list_of_dicts() -> None:
    crawled = {
        "endpoints": [
            {"url": "https://x.test/a", "method": "POST", "form_fields": [{"name": "invoice_ref"}]},
            {"url": "https://x.test/b", "method": "POST", "form_fields": [{"name": "invoice_ref"}]},
        ]
    }
    graph = build_surface_influence_graph(crawled)
    assert any(p.name == "invoice_ref" and p.endpoint_count == 2 for p in graph.parameters)


def test_params_supplied_via_body_params_list_of_strings() -> None:
    crawled = {
        "endpoints": [
            {"url": "https://x.test/a", "method": "POST", "body_params": ["invoice_ref"]},
            {"url": "https://x.test/b", "method": "POST", "body_params": ["invoice_ref"]},
        ]
    }
    graph = build_surface_influence_graph(crawled)
    assert any(p.name == "invoice_ref" and p.endpoint_count == 2 for p in graph.parameters)


def test_confidence_higher_for_specific_names_than_generic() -> None:
    crawled = {
        "endpoints": [
            {"url": "https://x.test/a?id=1&pending_invoice_reference_number=2", "method": "GET"},
            {"url": "https://x.test/b?id=1&pending_invoice_reference_number=2", "method": "GET"},
        ]
    }
    graph = build_surface_influence_graph(crawled)
    id_edge = next(e for e in graph.influence_edges if e.param_name == "id")
    specific_edge = next(
        e for e in graph.influence_edges if e.param_name == "pending_invoice_reference_number"
    )
    assert specific_edge.confidence > id_edge.confidence


def test_surface_records_key_also_consumed() -> None:
    crawled = {
        "surface_records": [
            {"url": "https://x.test/a?account_token=1", "method": "GET"},
            {"url": "https://x.test/b?account_token=2", "method": "GET"},
        ]
    }
    graph = build_surface_influence_graph(crawled)
    assert len(graph.endpoint_labels) == 2
    assert len(graph.influence_edges) == 1


def test_max_endpoints_bound_is_respected() -> None:
    crawled = {
        "endpoints": [
            {"url": f"https://x.test/e{i}?shared_id={i}", "method": "GET"}
            for i in range(10)
        ]
    }
    graph = build_surface_influence_graph(crawled, max_endpoints=3)
    assert len(graph.endpoint_labels) == 3


def test_malformed_endpoint_entries_are_skipped_not_crashed() -> None:
    crawled = {"endpoints": [None, 123, {}, "", {"url": ""}]}
    graph = build_surface_influence_graph(crawled)
    assert graph.endpoint_labels == []


def test_alternate_endpoint_keys_urls_links_pages_not_consumed() -> None:
    # Documents a deliberate scope boundary: this module matches
    # build_surface_evidence_graph's key set exactly (endpoints +
    # the 3 surface_records variants), NOT the broader key set some
    # other crawled_data consumers accept (urls/links/pages/resources
    # in agents/target_understanding/agent.py). A caller populating
    # only one of those broader keys gets an empty graph, not a crash.
    crawled = {
        "urls": [{"url": "https://x.test/a?account_token=1"}],
        "links": [{"url": "https://x.test/b?account_token=2"}],
    }
    graph = build_surface_influence_graph(crawled)
    assert graph.endpoint_labels == []
    assert graph.parameters == []


def test_as_dict_shape() -> None:
    crawled = {
        "endpoints": [
            {"url": "https://x.test/a?account_token=1", "method": "GET"},
            {"url": "https://x.test/b?account_token=2", "method": "GET"},
        ]
    }
    graph = build_surface_influence_graph(crawled)
    d = graph.as_dict()
    assert d["endpoint_count"] == 2
    assert d["shared_parameter_count"] == 1
    assert isinstance(d["influence_edges"], list)
