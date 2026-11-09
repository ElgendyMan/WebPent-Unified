"""U-ORACLE-9 — the Impact Maximizer (v88, plan 2026-10-17-v88-oracle.md)."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
import yaml

from webpent.oracle.chain_composer import ChainProposal
from webpent.oracle.graph_builder import AttackGraph, GraphEdge, GraphNode
from webpent.oracle.impact_maximizer import ImpactMaximizer
from webpent.oracle.models import OracleLawError

WORK = Path(__file__).resolve().parents[2]
STRATS = WORK / "config" / "oracle" / "impact_strategies.yaml"

CONFIG = yaml.safe_load(STRATS.read_text(encoding="utf-8"))


def _node(node_id: str, node_type: str, criticality: float,
          confidence: float = 0.9) -> GraphNode:
    return GraphNode(node_id=node_id, node_type=node_type,
                     label=node_id, criticality=criticality,
                     confidence=confidence)


def _graph(node_type: str) -> AttackGraph:
    graph = AttackGraph()
    graph.add_node(_node("H", "host", 0.5))
    graph.add_node(_node("X", node_type, 0.8))
    graph.add_edge(GraphEdge("X", "H", "reads_from", 0.7))
    return graph


def _proposal(node_id: str = "X", payout: float = 0.6,
              impact: str = "data_access") -> ChainProposal:
    return ChainProposal(
        proposal_id="CH-TEST", pattern_id="CH-TEST", name="n",
        description="d", nodes=[node_id, "H"], steps=["s"],
        impact_category=impact, payout_delta=payout, score=payout,
    )


# -- parametrized law checks ------------------------------------------------------

def test_config_has_at_least_eight_strategies() -> None:
    assert len(CONFIG["impact_strategies"]) >= 8
    ids = [s["strategy_id"] for s in CONFIG["impact_strategies"]]
    assert len(set(ids)) == len(ids)


@pytest.mark.parametrize(
    "strategy",
    CONFIG["impact_strategies"],
    ids=[s["strategy_id"] for s in CONFIG["impact_strategies"]],
)
def test_every_strategy_well_formed(strategy: dict) -> None:
    assert strategy["name"] and strategy["description"]
    assert float(strategy["payout_multiplier"]) > 0.0
    assert strategy["condition"]["kind"] in {
        "always", "category_present", "min_nodes", "payout_above",
    }


# -- spec test 1: strategies raise the payout ---------------------------------------

def test_strategies_raise_payout() -> None:
    estimate = ImpactMaximizer(STRATS).maximize(
        _graph("data_leak"), [_proposal()]
    )[0]
    assert estimate.base_payout > 0
    assert estimate.adjusted_payout > estimate.base_payout
    assert estimate.strategies_applied


# -- spec test 2: payout bounded within [0, 1] ------------------------------------------

def test_payout_bounded() -> None:
    strong = _proposal(payout=0.95)
    estimate = ImpactMaximizer(STRATS).maximize(
        _graph("data_leak"), [strong]
    )[0]
    assert 0.0 <= estimate.adjusted_payout <= 1.0


# -- spec test 3: impact over severity (L-9) -----------------------------------------------

def test_impact_over_severity() -> None:
    # same confidence, same payout shape: the data-bearing chain must be
    # valued above the mere fingerprint chain, whatever a CVSS would say
    data_est = ImpactMaximizer(STRATS).maximize(
        _graph("data_leak"), [_proposal(impact="data_access")]
    )[0]
    tech_est = ImpactMaximizer(STRATS).maximize(
        _graph("tech"), [_proposal(impact="reconnaissance")]
    )[0]
    assert data_est.adjusted_payout > tech_est.adjusted_payout


# -- spec test 4: strategy gating --------------------------------------------------------------

def test_strategy_applicability_gating() -> None:
    # a tech-only chain must not receive the data-volume frame (ST-002)
    estimate = ImpactMaximizer(STRATS).maximize(
        _graph("tech"), [_proposal(impact="reconnaissance")]
    )[0]
    assert "ST-002" not in estimate.strategies_applied
    assert "ST-001" in estimate.strategies_applied   # always applies


# -- spec test 5: ranked deterministically ---------------------------------------------------------

def test_ranked_deterministic() -> None:
    graph = _graph("data_leak")
    proposals = [_proposal("X", 0.6), _proposal("X", 0.3, "reconnaissance")]
    maximizer = ImpactMaximizer(STRATS)
    first = maximizer.maximize(graph, proposals)
    second = maximizer.maximize(graph, proposals)
    payouts = [e.adjusted_payout for e in first]
    assert payouts == sorted(payouts, reverse=True)
    assert [e.to_dict() for e in first] == [e.to_dict() for e in second]


# -- spec test 6: rationale records which frames applied

def test_rationale_records_strategies() -> None:
    estimate = ImpactMaximizer(STRATS).maximize(
        _graph("credential"), [_proposal(impact="credential_access")]
    )[0]
    assert estimate.rationale
    assert len(estimate.rationale) == len(estimate.strategies_applied)
    assert all(r.split(" ")[0].startswith("ST-") for r in estimate.rationale)


# -- spec test 7: passive only

def test_passive_only(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_socket(*args, **kwargs):
        raise AssertionError("impact maximizer opened a socket")

    monkeypatch.setattr(socket, "socket", _no_socket)
    ImpactMaximizer(STRATS).maximize(_graph("data_leak"), [_proposal()])


# -- guards

def test_missing_section_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "s.yaml"
    bad.write_text("strategies: []\n", encoding="utf-8")
    with pytest.raises(OracleLawError):
        ImpactMaximizer(bad)


def test_bad_condition_rejected(tmp_path: Path) -> None:
    bad_strategy = dict(CONFIG["impact_strategies"][0])
    bad_strategy["condition"] = {"kind": "teleport"}
    bad = tmp_path / "s.yaml"
    bad.write_text(
        yaml.safe_dump({"impact_strategies": [bad_strategy]}),
        encoding="utf-8",
    )
    with pytest.raises(OracleLawError):
        ImpactMaximizer(bad)


def test_negative_multiplier_rejected(tmp_path: Path) -> None:
    bad_strategy = dict(CONFIG["impact_strategies"][0])
    bad_strategy["payout_multiplier"] = -1.0
    bad = tmp_path / "s.yaml"
    bad.write_text(
        yaml.safe_dump({"impact_strategies": [bad_strategy]}),
        encoding="utf-8",
    )
    with pytest.raises(OracleLawError):
        ImpactMaximizer(bad)
