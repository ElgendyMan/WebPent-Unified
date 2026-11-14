"""U-ORACLE-7 — the Kill Chain Simulator (v88, plan 2026-10-17-v88-oracle.md)."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
import yaml

from webpent.oracle.chain_composer import ChainComposer, ChainProposal
from webpent.oracle.graph_builder import AttackGraph, GraphEdge, GraphNode
from webpent.oracle.kill_chain import KillChainSimulator
from webpent.oracle.models import OracleLawError

WORK = Path(__file__).resolve().parents[2]
KILL = WORK / "config" / "oracle" / "kill_chain.yaml"
CHAINS = WORK / "config" / "oracle" / "attack_chains.yaml"

CONFIG = yaml.safe_load(KILL.read_text(encoding="utf-8"))


def _node(node_id: str, node_type: str, criticality: float,
          confidence: float = 0.9) -> GraphNode:
    return GraphNode(node_id=node_id, node_type=node_type,
                     label=node_id, criticality=criticality,
                     confidence=confidence)


def _graph(confidence: float = 0.95) -> AttackGraph:
    graph = AttackGraph()
    graph.add_node(_node("S", "subdomain", 0.4, confidence))
    graph.add_node(_node("H", "host", 0.5, confidence))
    graph.add_node(_node("C", "credential", 0.9, confidence))
    graph.add_edge(GraphEdge("S", "H", "same_owner", 0.4))
    graph.add_edge(GraphEdge("C", "H", "authenticates_with", 0.9))
    return graph


def _proposal() -> ChainProposal:
    return ChainProposal(
        proposal_id="CH-002:S->H->C",
        pattern_id="CH-002",
        name="subdomain takeover to credential harvest",
        description="d",
        nodes=["S", "H", "C"],
        steps=["a", "b"],
        impact_category="credential_access",
        payout_delta=0.9,
        score=0.8,
        matched_edges=["same_owner", "authenticates_with"],
    )


# -- parametrized law checks ------------------------------------------------------

def test_config_defines_seven_phases() -> None:
    assert len(CONFIG["phases"]) == 7


@pytest.mark.parametrize(
    "phase",
    CONFIG["phases"],
    ids=[p["phase_id"] for p in CONFIG["phases"]],
)
def test_every_phase_well_formed(phase: dict) -> None:
    assert phase["name"] and phase["abort_reason"]
    assert 0.0 <= phase["min_confidence"] <= 1.0


# -- spec test 1: full chain completes all seven phases -----------------------------

def test_simulates_seven_phases() -> None:
    trace = KillChainSimulator(KILL).simulate(_graph(), _proposal())
    assert len(trace.phases) == 7
    assert trace.completed
    assert not trace.abort_phase
    assert [p.status for p in trace.phases] == ["passed"] * 7


# -- spec test 2: abort on weak evidence -----------------------------------------------

def test_aborts_on_missing_evidence() -> None:
    weak_graph = _graph(confidence=0.2)
    trace = KillChainSimulator(KILL).simulate(weak_graph, _proposal())
    assert not trace.completed
    assert trace.abort_phase
    assert trace.abort_reason
    assert trace.phases[-1].status == "aborted"
    # nothing was marked passed beyond the abort point
    statuses = [p.status for p in trace.phases]
    assert "aborted" in statuses


# -- spec test 3: abort names the phase and reason -----------------------------------------

def test_abort_reports_phase_and_reason() -> None:
    trace = KillChainSimulator(KILL).simulate(_graph(0.2), _proposal())
    aborting = [p for p in trace.phases if p.status == "aborted"][0]
    assert trace.abort_phase == aborting.phase_id
    assert trace.abort_reason == aborting.detail
    assert trace.abort_reason in {
        p["abort_reason"] for p in CONFIG["phases"]
    }


# -- spec test 4: passive only, nothing executed ----------------------------------------------

def test_no_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_socket(*args, **kwargs):
        raise AssertionError("kill chain simulator opened a socket")

    monkeypatch.setattr(socket, "socket", _no_socket)
    trace = KillChainSimulator(KILL).simulate(_graph(), _proposal())
    assert trace.executed is False
    assert trace.to_dict()["executed"] is False


# -- spec test 5: phase outcomes recorded in order -------------------------------------------

def test_phase_outcomes_recorded() -> None:
    trace = KillChainSimulator(KILL).simulate(_graph(), _proposal())
    config_ids = [p["phase_id"] for p in CONFIG["phases"]]
    assert [p.phase_id for p in trace.phases] == config_ids
    for outcome in trace.phases:
        assert outcome.status in {"passed", "aborted"}
        assert outcome.detail


# -- spec test 6: deterministic replay -----------------------------------------------------------

def test_deterministic_replay() -> None:
    graph = _graph()
    proposal = _proposal()
    a = KillChainSimulator(KILL).simulate(graph, proposal)
    b = KillChainSimulator(KILL).simulate(graph, proposal)
    assert a.to_dict() == b.to_dict()


# -- guards ------------------------------------------------------------------------------------

def test_missing_phases_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "kc.yaml"
    bad.write_text("abort_policy: {}\n", encoding="utf-8")
    with pytest.raises(OracleLawError):
        KillChainSimulator(bad)


def test_wrong_phase_count_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "kc.yaml"
    bad.write_text(
        yaml.safe_dump({"phases": [dict(CONFIG["phases"][0])]}),
        encoding="utf-8",
    )
    with pytest.raises(OracleLawError):
        KillChainSimulator(bad)


def test_phase_missing_field_rejected(tmp_path: Path) -> None:
    phase = {k: v for k, v in CONFIG["phases"][0].items()
             if k != "abort_reason"}
    bad = tmp_path / "kc.yaml"
    bad.write_text(yaml.safe_dump({"phases": [phase]}), encoding="utf-8")
    with pytest.raises(OracleLawError):
        KillChainSimulator(bad)


def test_end_to_end_with_composer() -> None:
    graph = _graph()
    proposals = ChainComposer(CHAINS).compose(graph)
    assert proposals
    trace = KillChainSimulator(KILL).simulate(graph, proposals[0])
    assert trace.phases
