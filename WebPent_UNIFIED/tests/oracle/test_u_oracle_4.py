"""U-ORACLE-4 — the Attack Graph Builder (v88, plan 2026-10-17-v88-oracle.md)."""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from webpent.oracle.graph_builder import GraphBuilder
from webpent.oracle.models import OracleLawError
from webpent.oracle.osint import OsintFinding, OsintReport
from webpent.oracle.signal_aggregator import OracleSignal
from webpent.oracle.stack_inferrer import Component, ComponentCVE, TechStackProfile

WORK = Path(__file__).resolve().parents[2]
RULES = WORK / "config" / "oracle" / "graph_rules.yaml"


def _finding(source: str, category: str, raw: dict, conf: float = 0.9):
    return OsintFinding(
        source=source, category=category, raw_data=raw, confidence=conf,
        extracted_at=datetime.now(timezone.utc),
        evidence_hash="0" * 64, core_hash="0" * 64,
    )


def _report(findings: list) -> OsintReport:
    return OsintReport(
        target_id="target.test", sources_used=[], findings=findings,
        duration_seconds=0.0, coverage={},
    )


def _signal(signal_type: str, strength: float = 0.9) -> OracleSignal:
    return OracleSignal(
        signal_id="sig-takeover-1", signal_type=signal_type, source="crtsh",
        strength=strength, target_id="target.test",
        extracted_at=datetime.now(timezone.utc),
        evidence_hash="0" * 64, hints=["check dns"],
    )


# -- spec test 1: build from findings ---------------------------------------------

def test_build_from_findings() -> None:
    graph = GraphBuilder(RULES).build(
        _report([
            _finding("github_secret_scanning", "credential",
                     {"repo": "o/x", "api_key": {"sha256": "h"}}),
            _finding("crtsh", "subdomain", {"subdomain": "dev.target.test"}),
        ])
    )
    types = {n.node_type for n in graph.nodes.values()}
    assert {"host", "credential", "subdomain"} <= types
    edge_types = {e.edge_type for e in graph.edges}
    assert {"authenticates_with", "same_owner"} <= edge_types


# -- spec test 2: criticality defaults -----------------------------------------------

def test_criticality_defaults() -> None:
    graph = GraphBuilder(RULES).build(
        _report([
            _finding("github_secret_scanning", "credential",
                     {"repo": "o/x", "api_key": {"sha256": "h"}}, conf=1.0),
            _finding("crtsh", "subdomain",
                     {"subdomain": "dev.target.test"}, conf=1.0),
        ])
    )
    cred = [n for n in graph.nodes.values() if n.node_type == "credential"][0]
    sub = [n for n in graph.nodes.values() if n.node_type == "subdomain"
           and n.node_id.startswith("subdomain:")][0]
    assert cred.criticality >= 0.8
    assert sub.criticality < 0.6


# -- spec test 3: edge types valid ------------------------------------------------------

def test_edge_types_valid() -> None:
    graph = GraphBuilder(RULES).build(
        _report([
            _finding("github_secret_scanning", "credential",
                     {"repo": "o/x", "api_key": {"sha256": "h"}}),
            _finding("cloud_buckets", "data_leak", {"bucket": "s3://x"}),
            _finding("wayback", "endpoint", {"url": "u"}),
            _finding("crtsh", "subdomain", {"subdomain": "d.target.test"}),
            _finding("shodan", "tech", {"banner": "nginx"}),
        ])
    )
    valid = set(yaml.safe_load(RULES.read_text())["edge_weights"])
    assert graph.edges
    for edge in graph.edges:
        assert edge.edge_type in valid
        assert 0.0 <= edge.weight <= 1.0


# -- spec test 4: entry and target nodes ---------------------------------------------------

def test_entry_and_target_nodes() -> None:
    graph = GraphBuilder(RULES).build(
        _report([
            _finding("github_secret_scanning", "credential",
                     {"repo": "o/x", "api_key": {"sha256": "h"}}, conf=1.0),
            _finding("crtsh", "subdomain",
                     {"subdomain": "dev.target.test"}, conf=0.9),
        ])
    )
    rules = yaml.safe_load(RULES.read_text())
    entries = graph.entry_nodes(rules)
    targets = graph.target_nodes(rules)
    assert any(n.node_type == "subdomain" for n in entries)
    assert any(n.node_type == "credential" for n in targets)


# -- spec test 5: DOT export ------------------------------------------------------------------

def test_export_dot() -> None:
    graph = GraphBuilder(RULES).build(
        _report([
            _finding("github_secret_scanning", "credential",
                     {"repo": "o/x", "api_key": {"sha256": "h"}}),
        ])
    )
    dot = graph.export_dot()
    assert dot.startswith("digraph ")
    assert dot.rstrip().endswith("}")
    assert '"host:target.test"' in dot
    for line in dot.splitlines():
        assert "->" not in line or line.strip().startswith('"')


# -- spec test 6: merge preserves structure ------------------------------------------------------

def test_merge_preserves_structure() -> None:
    builder = GraphBuilder(RULES)
    graph_a = builder.build(
        _report([
            _finding("github_secret_scanning", "credential",
                     {"repo": "o/x", "api_key": {"sha256": "h"}}, conf=1.0),
        ])
    )
    graph_b = builder.build(
        _report([
            _finding("crtsh", "subdomain", {"subdomain": "dev.target.test"}),
        ])
    )
    before_edges = len(graph_a.edges)
    merged = graph_a.merge(graph_b)
    assert "subdomain" in {n.node_type for n in merged.nodes.values()}
    assert len(merged.edges) >= before_edges
    # a duplicate edge (same endpoints+type) is deduped, not duplicated
    graph_c = builder.build(
        _report([
            _finding("crtsh", "subdomain", {"subdomain": "dev.target.test"}),
        ])
    )
    dup = graph_a.merge(graph_c)
    same = [
        e for e in dup.edges if e.edge_type == "same_owner"
        and e.target_id == "host:target.test"
    ]
    assert len(same) == 1


# -- spec test 7: zero requests --------------------------------------------------------------------

def test_no_target_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_socket(*args, **kwargs):
        raise AssertionError("graph builder opened a socket")

    monkeypatch.setattr(socket, "socket", _no_socket)
    profile = TechStackProfile(target_id="target.test")
    profile.components = [Component(name="nginx", version="1.18.0",
                                    confidence=0.9)]
    profile.cves["nginx"] = [
        ComponentCVE(cve="CVE-2021-23017", severity="high", summary="s")
    ]
    graph = GraphBuilder(RULES).build(
        _report([
            _finding("shodan", "tech", {"banner": "nginx/1.18.0"}),
        ]),
        stack_profile=profile,
        signals=[_signal("subdomain_takeover_candidate")],
    )
    assert any(n.node_type == "outdated_component" for n in graph.nodes.values())


# -- guards

def test_dangling_edge_rejected() -> None:
    from webpent.oracle.graph_builder import AttackGraph, GraphEdge, GraphNode

    graph = AttackGraph()
    graph.add_node(GraphNode("a", "tech", "a", 0.3, 0.9))
    with pytest.raises(OracleLawError):
        graph.add_edge(
            GraphEdge(source_id="a", target_id="missing",
                      edge_type="deploy_on", weight=0.5)
        )


def test_missing_rules_section_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "rules.yaml"
    bad.write_text("edge_weights: {}\n", encoding="utf-8")
    with pytest.raises(OracleLawError):
        GraphBuilder(bad)


@pytest.mark.parametrize(
    "edge_type,weight",
    yaml.safe_load(RULES.read_text())["edge_weights"].items(),
    ids=list(yaml.safe_load(RULES.read_text())["edge_weights"]),
)
def test_every_edge_weight_in_range(edge_type: str, weight: float) -> None:
    assert 0.0 < weight <= 1.0
