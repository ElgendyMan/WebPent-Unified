"""Project Zero-tier item 4 — Attack surface drift detection.

Pins:
  * a node present in both snapshots with the same disposition
    produces NO drift entry at all (silence == unchanged),
  * a brand-new node is classified "appeared" and gets HIGH priority
    for directly-attackable surface types (endpoint/form/xhr/
    openapi_route/graphql_operation/multipart_field) and MEDIUM for
    supporting-evidence types (service_fingerprint/browser_context/
    workflow_ref),
  * a node missing from the current snapshot is classified
    "disappeared" and keeps its type's base priority,
  * a node present in both but with a different disposition is
    classified "disposition_changed",
  * high_priority_nodes aggregates across appeared/disappeared/
    disposition_changed in encounter order,
  * matching is by node_id, not by position/order.
"""

from __future__ import annotations

from webpent.models.surface_graph import SurfaceEvidenceGraph, SurfaceNode
from webpent.shared.surface_drift import (
    DriftPriority,
    detect_surface_drift,
)
from webpent.shared.surface_evidence_graph import build_surface_evidence_graph


def _node(node_id: str, node_type: str = "endpoint", label: str = "/x", disposition: str = "observed") -> SurfaceNode:
    return SurfaceNode(node_id=node_id, node_type=node_type, label=label, disposition=disposition)


def test_identical_snapshots_produce_no_drift() -> None:
    graph = SurfaceEvidenceGraph(nodes=[_node("endpoint_aaaaaaaa")])
    report = detect_surface_drift(graph, graph)
    assert report.has_drift is False
    assert report.appeared == []
    assert report.disappeared == []
    assert report.disposition_changed == []


def test_new_endpoint_is_high_priority() -> None:
    baseline = SurfaceEvidenceGraph(nodes=[])
    current = SurfaceEvidenceGraph(nodes=[_node("endpoint_aaaaaaaa", node_type="endpoint")])
    report = detect_surface_drift(baseline, current)
    assert len(report.appeared) == 1
    assert report.appeared[0].change == "appeared"
    assert report.appeared[0].priority == DriftPriority.HIGH


def test_new_service_fingerprint_is_medium_priority() -> None:
    baseline = SurfaceEvidenceGraph(nodes=[])
    current = SurfaceEvidenceGraph(
        nodes=[_node("svc_aaaaaaaa", node_type="service_fingerprint")]
    )
    report = detect_surface_drift(baseline, current)
    assert len(report.appeared) == 1
    assert report.appeared[0].priority == DriftPriority.MEDIUM


def test_all_high_priority_node_types() -> None:
    high_types = [
        "endpoint", "form", "xhr", "openapi_route",
        "graphql_operation", "multipart_field",
    ]
    baseline = SurfaceEvidenceGraph(nodes=[])
    current = SurfaceEvidenceGraph(
        nodes=[_node(f"n_{t}aaaa", node_type=t) for t in high_types]
    )
    report = detect_surface_drift(baseline, current)
    assert len(report.appeared) == len(high_types)
    assert all(n.priority == DriftPriority.HIGH for n in report.appeared)


def test_all_medium_priority_node_types() -> None:
    medium_types = ["service_fingerprint", "browser_context", "workflow_ref"]
    baseline = SurfaceEvidenceGraph(nodes=[])
    current = SurfaceEvidenceGraph(
        nodes=[_node(f"n_{t}aaaa", node_type=t) for t in medium_types]
    )
    report = detect_surface_drift(baseline, current)
    assert len(report.appeared) == len(medium_types)
    assert all(n.priority == DriftPriority.MEDIUM for n in report.appeared)


def test_disappeared_endpoint_detected() -> None:
    baseline = SurfaceEvidenceGraph(nodes=[_node("endpoint_aaaaaaaa")])
    current = SurfaceEvidenceGraph(nodes=[])
    report = detect_surface_drift(baseline, current)
    assert len(report.disappeared) == 1
    assert report.disappeared[0].change == "disappeared"
    assert report.disappeared[0].previous_disposition == "observed"
    assert report.disappeared[0].current_disposition is None


def test_disappeared_endpoint_keeps_high_priority() -> None:
    baseline = SurfaceEvidenceGraph(nodes=[_node("endpoint_aaaaaaaa", node_type="endpoint")])
    current = SurfaceEvidenceGraph(nodes=[])
    report = detect_surface_drift(baseline, current)
    assert report.disappeared[0].priority == DriftPriority.HIGH


def test_disposition_change_detected() -> None:
    baseline = SurfaceEvidenceGraph(
        nodes=[_node("endpoint_aaaaaaaa", disposition="needs_validator")]
    )
    current = SurfaceEvidenceGraph(
        nodes=[_node("endpoint_aaaaaaaa", disposition="blocked")]
    )
    report = detect_surface_drift(baseline, current)
    assert len(report.disposition_changed) == 1
    entry = report.disposition_changed[0]
    assert entry.previous_disposition == "needs_validator"
    assert entry.current_disposition == "blocked"
    assert entry.change == "disposition_changed"


def test_same_disposition_is_not_flagged_as_change() -> None:
    baseline = SurfaceEvidenceGraph(
        nodes=[_node("endpoint_aaaaaaaa", disposition="observed")]
    )
    current = SurfaceEvidenceGraph(
        nodes=[_node("endpoint_aaaaaaaa", disposition="observed")]
    )
    report = detect_surface_drift(baseline, current)
    assert report.disposition_changed == []


def test_matching_is_by_node_id_not_position() -> None:
    baseline = SurfaceEvidenceGraph(
        nodes=[_node("endpoint_aaaaaaaa"), _node("endpoint_bbbbbbbb")]
    )
    # Reversed order in the current snapshot.
    current = SurfaceEvidenceGraph(
        nodes=[_node("endpoint_bbbbbbbb"), _node("endpoint_aaaaaaaa")]
    )
    report = detect_surface_drift(baseline, current)
    assert report.has_drift is False


def test_high_priority_nodes_aggregates_across_categories() -> None:
    baseline = SurfaceEvidenceGraph(
        nodes=[
            _node("endpoint_aaaaaaaa", disposition="observed"),  # will disappear
            _node("endpoint_bbbbbbbb", disposition="needs_validator"),  # disposition change
        ]
    )
    current = SurfaceEvidenceGraph(
        nodes=[
            _node("endpoint_bbbbbbbb", disposition="blocked"),
            _node("endpoint_cccccccc", disposition="observed"),  # new
        ]
    )
    report = detect_surface_drift(baseline, current)
    ids = {n.node_id for n in report.high_priority_nodes}
    assert ids == {"endpoint_aaaaaaaa", "endpoint_bbbbbbbb", "endpoint_cccccccc"}
    assert len(report.high_priority_nodes) == 3


def test_node_counts_reflect_each_snapshot() -> None:
    baseline = SurfaceEvidenceGraph(nodes=[_node("endpoint_aaaaaaaa")])
    current = SurfaceEvidenceGraph(
        nodes=[_node("endpoint_aaaaaaaa"), _node("endpoint_bbbbbbbb")]
    )
    report = detect_surface_drift(baseline, current)
    assert report.baseline_node_count == 1
    assert report.current_node_count == 2


def test_as_dict_is_json_safe_shape() -> None:
    baseline = SurfaceEvidenceGraph(nodes=[])
    current = SurfaceEvidenceGraph(nodes=[_node("endpoint_aaaaaaaa")])
    report = detect_surface_drift(baseline, current)
    d = report.as_dict()
    assert d["has_drift"] is True
    assert d["high_priority_count"] == 1
    assert isinstance(d["appeared"], list)
    assert d["appeared"][0]["priority"] == "high"


def test_empty_both_snapshots_no_drift() -> None:
    baseline = SurfaceEvidenceGraph(nodes=[])
    current = SurfaceEvidenceGraph(nodes=[])
    report = detect_surface_drift(baseline, current)
    assert report.has_drift is False
    assert report.baseline_node_count == 0
    assert report.current_node_count == 0


def test_integration_against_real_build_surface_evidence_graph() -> None:
    # Regression/integration test: exercises detect_surface_drift
    # against the ACTUAL production build_surface_evidence_graph()
    # output, not a hand-constructed SurfaceEvidenceGraph fixture —
    # verifies the real _node_id hashing scheme (node_type|label|method)
    # behaves as this module assumes (stable across unrelated crawls,
    # unique per genuinely-new endpoint).
    baseline_crawl = {
        "endpoints": [
            {"url": "https://x.test/login", "method": "POST"},
            {"url": "https://x.test/dashboard", "method": "GET"},
        ]
    }
    current_crawl = {
        "endpoints": [
            {"url": "https://x.test/login", "method": "POST"},
            {"url": "https://x.test/dashboard", "method": "GET"},
            {"url": "https://x.test/admin/new-feature", "method": "GET"},
        ]
    }
    baseline_graph = build_surface_evidence_graph(baseline_crawl)
    current_graph = build_surface_evidence_graph(current_crawl)

    report = detect_surface_drift(baseline_graph, current_graph)
    assert report.has_drift is True
    assert len(report.appeared) == 1
    assert report.appeared[0].label == "https://x.test/admin/new-feature"
    assert len(report.high_priority_nodes) == 1
    assert report.disappeared == []
    assert report.disposition_changed == []


def test_integration_identical_crawl_produces_no_drift() -> None:
    crawl = {
        "endpoints": [
            {"url": "https://x.test/login", "method": "POST"},
        ]
    }
    graph_a = build_surface_evidence_graph(crawl)
    graph_b = build_surface_evidence_graph(crawl)
    report = detect_surface_drift(graph_a, graph_b)
    assert report.has_drift is False
