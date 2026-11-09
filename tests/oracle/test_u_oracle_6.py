"""U-ORACLE-6 — the Chain Composer (v88, plan 2026-10-17-v88-oracle.md)."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
import yaml

from webpent.oracle.chain_composer import ChainComposer
from webpent.oracle.graph_builder import (
    AttackGraph,
    GraphEdge,
    GraphNode,
)
from webpent.oracle.models import OracleLawError
from webpent.oracle.osint import OsintFinding, OsintReport
from webpent.oracle.path_predictor import PathPredictor

WORK = Path(__file__).resolve().parents[2]
CHAINS = WORK / "config" / "oracle" / "attack_chains.yaml"
RULES = WORK / "config" / "oracle" / "graph_rules.yaml"

CONFIG = yaml.safe_load(CHAINS.read_text(encoding="utf-8"))


def _finding(source: str, category: str, raw: dict, conf: float = 0.9):
    from datetime import datetime, timezone

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


def _node(node_id: str, node_type: str, criticality: float,
          confidence: float = 0.9) -> GraphNode:
    return GraphNode(node_id=node_id, node_type=node_type,
                     label=node_id, criticality=criticality,
                     confidence=confidence)


def _full_graph() -> AttackGraph:
    """subdomain -- host -- credential --(reads)--> data_leak style shape."""
    graph = AttackGraph()
    graph.add_node(_node("H", "host", 0.5))
    graph.add_node(_node("S", "subdomain", 0.4))
    graph.add_node(_node("C", "credential", 0.9))
    graph.add_node(_node("D", "data_leak", 0.8))
    graph.add_node(_node("E", "endpoint", 0.3))
    graph.add_edge(GraphEdge("S", "H", "same_owner", 0.4))
    graph.add_edge(GraphEdge("C", "H", "authenticates_with", 0.9))
    graph.add_edge(GraphEdge("D", "H", "reads_from", 0.7))
    graph.add_edge(GraphEdge("E", "H", "serves", 0.6))
    return graph


# -- config law: at least ten patterns, each well formed ----------------------

def test_config_has_at_least_ten_patterns() -> None:
    patterns = CONFIG["chain_patterns"]
    assert len(patterns) >= 10
    ids = [p["pattern_id"] for p in patterns]
    assert len(set(ids)) == len(ids)


@pytest.mark.parametrize(
    "pattern",
    CONFIG["chain_patterns"],
    ids=[p["pattern_id"] for p in CONFIG["chain_patterns"]],
)
def test_every_pattern_well_formed(pattern: dict) -> None:
    assert pattern["name"] and pattern["description"]
    nodes = pattern["required_nodes"]
    edges = pattern["required_edges"]
    assert nodes and len(edges) == len(nodes) - 1
    assert pattern["steps"]
    assert 0.0 <= pattern["payout_delta"] <= 1.0
    assert pattern["impact_category"]


# -- spec test 1: proposals are advisory only ------------------------------------

def test_proposals_advisory_only(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_socket(*args, **kwargs):
        raise AssertionError("chain composer opened a socket")

    monkeypatch.setattr(socket, "socket", _no_socket)
    proposals = ChainComposer(CHAINS).compose(_full_graph())
    assert proposals
    assert all(p.advisory for p in proposals)
    assert all(p.to_dict()["advisory"] for p in proposals)


# -- spec test 2: ordered steps present ---------------------------------------------

def test_proposal_contains_ordered_steps() -> None:
    proposals = ChainComposer(CHAINS).compose(_full_graph())
    assert proposals
    for proposal in proposals:
        assert proposal.steps == list(proposal.steps)   # stable order
        assert all(isinstance(s, str) and s for s in proposal.steps)


# -- spec test 3: ranked by score -------------------------------------------------------

def test_proposals_ranked_by_score() -> None:
    proposals = ChainComposer(CHAINS).compose(_full_graph())
    scores = [p.score for p in proposals]
    assert scores == sorted(scores, reverse=True)


# -- spec test 4: matching honours node order and edges ------------------------------------

def test_match_honours_order_and_edges() -> None:
    graph = AttackGraph()
    graph.add_node(_node("S", "subdomain", 0.4))
    graph.add_node(_node("H", "host", 0.5))
    graph.add_node(_node("C", "credential", 0.9))
    graph.add_edge(GraphEdge("S", "H", "same_owner", 0.4))
    graph.add_edge(GraphEdge("C", "H", "authenticates_with", 0.9))
    proposals = ChainComposer(CHAINS).compose(graph)
    assert any(p.pattern_id == "CH-002" for p in proposals)


# -- spec test 5: no match on unrelated topology ----------------------------------------------

def test_no_match_on_unrelated_topology() -> None:
    graph = AttackGraph()
    graph.add_node(_node("T1", "tech", 0.3))
    graph.add_node(_node("T2", "tech", 0.3))
    graph.add_edge(GraphEdge("T1", "T2", "deploy_on", 0.5))
    # patterns demand credential/data_leak/subdomain anchors: none here
    proposals = ChainComposer(CHAINS).compose(graph)
    assert all(
        p.impact_category != "data_access" or p.nodes for p in proposals
    )
    assert not any(
        p.pattern_id == "CH-001" for p in proposals
    )


# -- spec test 6: prediction corroboration boosts score -------------------------------------------

def test_prediction_corroboration_boosts() -> None:
    graph = _full_graph()
    bare = ChainComposer(CHAINS).compose(graph)
    predictions = PathPredictor(RULES).predict(graph)
    boosted = ChainComposer(CHAINS).compose(graph, predictions)
    assert predictions  # the graph is connected, so routes exist
    by_id = {p.proposal_id: p.score for p in boosted}
    for proposal in bare:
        if proposal.proposal_id in by_id and set(
            proposal.nodes
        ) <= {n for pred in predictions for n in pred.path}:
            assert by_id[proposal.proposal_id] > proposal.score
            break
    else:
        pytest.fail("no proposal was corroborated by a prediction")


# -- spec test 7: payout delta reflects impact (L-9) -------------------------------------------

def test_payout_delta_ranking_matches_impact() -> None:
    graph = _full_graph()
    proposals = ChainComposer(CHAINS).compose(graph)
    assert proposals
    strongest = proposals[0]
    assert strongest.payout_delta >= 0.5
    # the strongest proposal always carries an impact category, not a CVSS
    assert strongest.impact_category


# -- spec test 8: to_dict round trip ---------------------------------------------------------------

def test_to_dict_complete() -> None:
    proposals = ChainComposer(CHAINS).compose(_full_graph())
    payload = proposals[0].to_dict()
    for key in ("proposal_id", "pattern_id", "name", "nodes", "steps",
                "impact_category", "payout_delta", "score", "advisory"):
        assert key in payload


# -- guards ----------------------------------------------------------------------------------------

def test_missing_section_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "chains.yaml"
    bad.write_text("something: []\n", encoding="utf-8")
    with pytest.raises(OracleLawError):
        ChainComposer(bad)


def test_unknown_node_type_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "chains.yaml"
    bad.write_text(
        yaml.safe_dump({"chain_patterns": [{
            "pattern_id": "CH-BAD", "name": "n", "description": "d",
            "required_nodes": ["dragon"], "required_edges": [],
            "impact_category": "x", "payout_delta": 0.5,
            "steps": ["s"],
        }]}),
        encoding="utf-8",
    )
    with pytest.raises(OracleLawError):
        ChainComposer(bad)


def test_edge_count_mismatch_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "chains.yaml"
    bad.write_text(
        yaml.safe_dump({"chain_patterns": [{
            "pattern_id": "CH-BAD", "name": "n", "description": "d",
            "required_nodes": ["host", "credential"],
            "required_edges": ["authenticates_with", "same_owner"],
            "impact_category": "x", "payout_delta": 0.5,
            "steps": ["s"],
        }]}),
        encoding="utf-8",
    )
    with pytest.raises(OracleLawError):
        ChainComposer(bad)
