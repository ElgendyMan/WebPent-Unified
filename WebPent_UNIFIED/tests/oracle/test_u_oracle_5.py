"""U-ORACLE-5 — the Path Predictor (v88, plan 2026-10-17-v88-oracle.md)."""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from webpent.oracle.graph_builder import (
    AttackGraph,
    GraphBuilder,
    GraphEdge,
    GraphNode,
)
from webpent.oracle.models import OracleLawError
from webpent.oracle.osint import OsintFinding, OsintReport
from webpent.oracle.path_predictor import PathPredictor

WORK = Path(__file__).resolve().parents[2]
RULES = WORK / "config" / "oracle" / "graph_rules.yaml"

RULES_DATA = yaml.safe_load(RULES.read_text(encoding="utf-8"))


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


def _node(node_id: str, node_type: str, criticality: float) -> GraphNode:
    return GraphNode(node_id=node_id, node_type=node_type,
                     label=node_id, criticality=criticality, confidence=0.9)


def _two_path_graph() -> AttackGraph:
    """Two structurally identical routes that differ only in edge type,
    hence only in detection risk: E→A→T (quiet) vs E→B→T (loud)."""
    graph = AttackGraph()
    graph.add_node(_node("E", "endpoint", 0.5))
    graph.add_node(_node("A", "tech", 0.7))
    graph.add_node(_node("B", "tech", 0.7))
    graph.add_node(_node("T", "credential", 0.9))
    graph.add_edge(GraphEdge("E", "A", "same_owner", 0.8))
    graph.add_edge(GraphEdge("A", "T", "reads_from", 0.8))
    graph.add_edge(GraphEdge("E", "B", "serves", 0.8))
    graph.add_edge(GraphEdge("B", "T", "authenticates_with", 0.8))
    return graph


# -- spec test 1: ranked paths ------------------------------------------------------

def test_predict_returns_ranked_paths() -> None:
    graph = GraphBuilder(RULES).build(
        _report([
            _finding("github_secret_scanning", "credential",
                     {"repo": "o/x", "api_key": {"sha256": "h"}}, conf=1.0),
            _finding("crtsh", "subdomain", {"subdomain": "dev.target.test"}),
            _finding("cloud_buckets", "data_leak", {"bucket": "s3://x"}),
        ])
    )
    predictions = PathPredictor(RULES).predict(graph)
    assert predictions
    scores = [p.score for p in predictions]
    assert scores == sorted(scores, reverse=True)
    for pred in predictions:
        assert pred.path[0] and pred.path[-1]
        assert pred.path[-1] != pred.path[0]


# -- spec test 2: scoring formula -----------------------------------------------------

def test_dijkstra_modified_correctly() -> None:
    graph = _two_path_graph()
    predictions = PathPredictor(RULES).predict(graph)
    assert predictions
    quiet = [p for p in predictions if p.path == ["E", "A", "T"]][0]
    cfg = RULES_DATA["path_predictor"]
    risk = RULES_DATA["detection_risk"]
    # scoring rule: each hop contributes edge weight x criticality of the
    # node arrived at (the entry point is the attacker's start, not a hop)
    expected = (
        (0.7 * 0.9)                # criticality product over hops
        * (0.8 * 0.8)              # weight product
        * (cfg["length_penalty"] ** 1)   # hops - 1
    ) / ((1.0 + risk["same_owner"] + risk["reads_from"]) ** 2)
    assert quiet.score == pytest.approx(expected, rel=1e-6)


# -- spec test 3: detection risk penalizes ----------------------------------------------

def test_detection_risk_penalizes() -> None:
    predictions = PathPredictor(RULES).predict(_two_path_graph())
    assert len(predictions) >= 2
    first, second = predictions[0], predictions[1]
    # identical structure: the quieter route must win
    assert first.path == ["E", "A", "T"]
    assert second.path == ["E", "B", "T"]
    assert first.detection_risk < second.detection_risk
    assert first.score > second.score


# -- spec test 4: no path when disconnected ------------------------------------------------

def test_no_path_when_disconnected() -> None:
    graph = AttackGraph()
    graph.add_node(_node("E", "endpoint", 0.5))
    graph.add_node(_node("T", "credential", 0.9))
    # no edges at all
    assert PathPredictor(RULES).predict(graph) == []


# -- spec test 5: top_k limit ------------------------------------------------------------------

def test_top_k_limit() -> None:
    graph = AttackGraph()
    graph.add_node(_node("T", "credential", 0.9))
    for i in range(7):
        graph.add_node(_node(f"S{i}", "subdomain", 0.4))
        graph.add_edge(GraphEdge(f"S{i}", "T", "same_owner", 0.8))
    top_k = int(RULES_DATA["path_predictor"]["top_k"])
    predictions = PathPredictor(RULES).predict(graph)
    assert len(predictions) == top_k


# -- spec test 6: readable explanation ------------------------------------------------------------

def test_explain_produces_readable_output() -> None:
    graph = GraphBuilder(RULES).build(
        _report([
            _finding("github_secret_scanning", "credential",
                     {"repo": "o/x", "api_key": {"sha256": "h"}}, conf=1.0),
            _finding("crtsh", "subdomain", {"subdomain": "dev.target.test"}),
        ])
    )
    predictor = PathPredictor(RULES)
    predictions = predictor.predict(graph)
    assert predictions
    text = predictor.explain_path(graph, predictions[0])
    assert "predicted route" in text
    assert "->" in text
    assert "score" in text and "detection risk" in text
    # validate_path agrees on its own prediction
    assert predictor.validate_path(graph, predictions[0].path)
    assert not predictor.validate_path(graph, ["host:target.test", "nowhere"])


# -- spec test 7: deterministic ranking

def test_deterministic_ranking() -> None:
    graph = _two_path_graph()
    graph.add_node(_node("S", "subdomain", 0.4))
    graph.add_edge(GraphEdge("S", "T", "same_owner", 0.8))
    a = PathPredictor(RULES).predict(graph)
    b = PathPredictor(RULES).predict(graph)
    assert [p.to_dict() for p in a] == [p.to_dict() for p in b]


# -- guards

def test_missing_detection_risk_section_rejected(tmp_path: Path) -> None:
    data = {k: v for k, v in RULES_DATA.items() if k != "detection_risk"}
    bad = tmp_path / "rules.yaml"
    bad.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(OracleLawError):
        PathPredictor(bad)


def test_missing_path_predictor_section_rejected(tmp_path: Path) -> None:
    data = {k: v for k, v in RULES_DATA.items() if k != "path_predictor"}
    bad = tmp_path / "rules.yaml"
    bad.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(OracleLawError):
        PathPredictor(bad)


def test_prediction_is_passive_only(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_socket(*args, **kwargs):
        raise AssertionError("path predictor opened a socket")

    monkeypatch.setattr(socket, "socket", _no_socket)
    graph = GraphBuilder(RULES).build(
        _report([
            _finding("github_secret_scanning", "credential",
                     {"repo": "o/x", "api_key": {"sha256": "h"}}, conf=1.0),
            _finding("crtsh", "subdomain", {"subdomain": "dev.target.test"}),
        ])
    )
    assert PathPredictor(RULES).predict(graph) is not None


@pytest.mark.parametrize(
    "edge_type,risk",
    RULES_DATA["detection_risk"].items(),
    ids=list(RULES_DATA["detection_risk"]),
)
def test_every_detection_risk_in_range(edge_type: str, risk: float) -> None:
    assert 0.0 <= risk <= 1.0
