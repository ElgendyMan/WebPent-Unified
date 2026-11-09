# tests/test_finding_relation_graph.py
"""Track 12 item 4 — finding relation graph (redaction-first, no
exploitation-instruction surface)."""

from __future__ import annotations

import json
import uuid as uuid_mod

UID = lambda n: str(uuid_mod.uuid5(uuid_mod.NAMESPACE_URL, n))

from webpent.models.findings import Finding
from webpent.production.finding_relation_graph import (
    build_finding_graph,
    graph_to_dot,
    graph_to_json,
    render_html,
)

F1 = Finding(
    id=UID("f-1"),
    title="Reflected XSS in search",
    severity="high",
    description="Script reflected in the q parameter.",
    tool_name="validator",
    url="https://app.example.com/search?q=x",
    vuln_class="xss",
    evidence={"evidence_hash": "a" * 64, "business_impact": "session theft"},
)
F2 = Finding(
    id=UID("f-2"),
    title="SQLi in item",
    severity="critical",
    description="Database error surfaced in item response.",
    tool_name="validator",
    url="https://api.example.com/item/1",
    vuln_class="sqli",
    evidence={"evidence_hash": "b" * 64},
)
# dict-shaped finding (reporter annotation path)
F3 = {
    "id": "f-3",
    "title": "Chained via f-1",
    "severity": "medium",
    "vuln_class": "xss",
    "url": "https://app.example.com/search?q=y",
    "evidence": {"related_findings": [UID("f-1")]},
}


class TestBuild:
    def test_deterministic_and_sorted(self):
        g1 = build_finding_graph([F1, F2, F3], engagement_id="e1")
        g2 = build_finding_graph([F3, F2, F1], engagement_id="e1")
        assert graph_to_json(g1) == graph_to_json(g2)

    def test_node_kinds_and_edges(self):
        graph = build_finding_graph([F1, F2, F3], engagement_id="e1")
        kinds = {n.kind for n in graph.nodes}
        assert kinds == {"asset", "finding", "evidence", "impact"}
        relations = {e.relation for e in graph.edges}
        assert {"targets", "evidences", "impacts", "related_to"} <= relations
        assert graph.summary()["nodes_by_kind"]["finding"] == 3

    def test_shared_origin_merges_asset_nodes(self):
        graph = build_finding_graph(
            [
                F1,
                Finding(
                    id=UID("f-9"),
                    title="Same origin",
                    severity="low",
                    description="Info on shared origin.",
                    tool_name="validator",
                    url="https://app.example.com/other",
                    vuln_class="info_disclosure",
                ),
            ]
        )
        assets = [n for n in graph.nodes if n.kind == "asset"]
        assert len(assets) == 1
        assert assets[0].label == "https://app.example.com"

    def test_empty_and_malformed_inputs(self):
        graph = build_finding_graph([])
        assert graph.nodes == [] and graph.edges == []
        # A finding without id is skipped, not fatal.
        graph = build_finding_graph([{"title": "no id", "severity": "low"}])
        assert graph.nodes == []


class TestRedactionFirst:
    def test_payload_never_enters_graph(self):
        payload = "<script>alert('PWN')</script>"
        finding = Finding(
            id=UID("f-x"),
            title="XSS",
            severity="high",
            description="Payload-bearing finding.",
            tool_name="validator",
            url="https://app.example.com/x",
            vuln_class="xss",
            evidence={"evidence_hash": "c" * 64, "request": payload},
        )
        blob = graph_to_json(build_finding_graph([finding]))
        assert payload not in blob
        assert "PWN" not in blob
        # Only the hash identifier is carried.
        assert "c" * 64 in blob

    def test_html_escapes_labels(self):
        finding = Finding(
            id=UID("f-evil"),
            title='Title with <tags> & "quotes" and <img src=x>', 
            severity="low",
            description="HTML-escaping check.",
            tool_name="validator",
            url="https://app.example.com/",
            vuln_class="xss",
        )
        page = render_html(build_finding_graph([finding]))
        assert "<img src=x>" not in page
        assert "&amp;" in page and "&lt;" in page


class TestExporters:
    def test_json_stable_shape(self):
        blob = graph_to_json(build_finding_graph([F1]))
        data = json.loads(blob)
        assert set(data) == {"engagement_id", "nodes", "edges"}
        assert all(set(n) == {"id", "kind", "label", "severity", "class", "ref", "meta"} for n in data["nodes"])

    def test_dot_contains_nodes_and_edges(self):
        dot = graph_to_dot(build_finding_graph([F1, F2]))
        assert dot.startswith("digraph webpent_findings {")
        assert "->" in dot
        assert "xss" in dot

    def test_html_selfcontained_no_network(self):
        page = render_html(build_finding_graph([F1, F2]))
        assert page.startswith("<!doctype html>")
        assert "<script src=" not in page and "<link " not in page
        assert "src=\"http" not in page and "href=\"http" not in page
        assert "svg" in page
        assert "evidence payloads" in page  # guardrail statement rendered
