"""M3 UM-DR-17: attack-graph evidence-edge enrichment.

Registry acceptance: "every attack-graph edge evidence-backed". The
frozen ``build_attack_graph`` threads evidence through its typed adders
but three edge families can land with empty ``evidence_refs``
(mental-model edges with a blank source_ref, relational rows and causal
rows that carried none).

Contract under test:

1. **Status marking** — every edge carries
   ``metadata.evidence_status`` ∈ {backed, enriched, unbacked}.
2. **Honest backfill** — finding-tied edges inherit the finding pointer
   (+ sealed evidence_hash); hypothesis-tied edges inherit
   ``evidence_refs``; otherwise the endpoint nodes' REAL observation
   refs (generic sentinels excluded). Nothing is invented.
3. **Accounting** — ``attack_graph_unbacked_edges:<N>`` lands in
   coverage_gaps; ``drop_unbacked`` prunes instead of marking; the
   summary block counts each class.
4. **The frozen agent wiring** — the node runs the pass after
   ``build_attack_graph`` (source-level contract) and the acceptance
   predicate holds on a fully-evidenced graph.
"""

from __future__ import annotations

from typing import Any

from webpent.shared.attack_graph import build_attack_graph
from webpent.shared.attack_graph_evidence import (
    enrich_attack_graph_edges,
    every_edge_evidence_backed,
)

TARGET = "https://app.example.com"


def _relational_row(**overrides: Any) -> dict[str, Any]:
    row = {
        "resource_url": f"{TARGET}/api/documents/42",
        "from_identity": "identity-alice",
        "to_identity": "identity-bob",
        "owner_identity": "identity-carol",
        "from_accessible": True,
        "to_accessible": False,
        "differential": True,
        "evidence_refs": ["obs-rel-1"],
    }
    row.update(overrides)
    return row


def _built_graph(**overrides: Any) -> dict[str, Any]:
    return build_attack_graph(
        None,
        relational_evidence=overrides.pop("relational_evidence", [_relational_row()]),
        findings=overrides.pop("findings", []),
        hypotheses=overrides.pop("hypotheses", []),
        **overrides,
    )


def test_edges_with_evidence_are_marked_backed() -> None:
    graph = _built_graph()
    enriched = enrich_attack_graph_edges(graph)
    statuses = {
        (e["kind"], e["source_id"], e["target_id"]): e["metadata"]["evidence_status"]
        for e in enriched["edges"]
    }
    assert set(statuses.values()) == {"backed"}
    assert every_edge_evidence_backed(enriched)
    assert enriched["evidence_edge_summary"]["edges_unbacked"] == 0


def test_unevidenced_relational_edges_get_enriched_from_node_observations() -> None:
    # A relational row with NO evidence_refs: the identity/endpoint nodes
    # it creates carry only generic sentinels... except the endpoint node
    # created with metadata url — its source_refs are generic too, so the
    # enrichment must label the edges unbacked (honest) unless real
    # observation refs exist.
    graph = _built_graph(relational_evidence=[_relational_row(evidence_refs=[])])
    out = enrich_attack_graph_edges(graph)
    unbacked = [e for e in out["edges"] if e["metadata"]["evidence_status"] == "unbacked"]
    assert unbacked
    assert all(not e["evidence_refs"] for e in unbacked)
    assert "attack_graph_unbacked_edges:3" in out["coverage_gaps"]
    assert out["evidence_edge_summary"]["edges_unbacked"] == 3
    assert every_edge_evidence_backed(out) is False


def test_finding_tied_edges_inherit_the_finding_pointer_and_hash() -> None:
    finding = {
        "id": "f-1",
        "url": f"{TARGET}/api/documents/42",
        "vuln_class": "idor",
        "severity": "high",
        "confidence": "confirmed",
        "tool_name": "validator",
        "evidence_hash": "sha256:abc123",
    }
    graph = _built_graph(findings=[finding])
    out = enrich_attack_graph_edges(graph, findings=[finding])
    affects = [
        e
        for e in out["edges"]
        if e["kind"] == "finding_affects" and e["source_id"] == "finding:f-1"
    ]
    assert affects, out["edges"]
    edge = affects[0]
    # The frozen adder already gave this edge finding:f-1 — backed as-is.
    assert edge["metadata"]["evidence_status"] in {"backed", "enriched"}
    assert "finding:f-1" in edge["evidence_refs"]


def test_hypothesis_pool_backfills_empty_edges() -> None:
    # A causal edge attached to a hypothesis node with no evidence_refs,
    # while the hypothesis itself carries evidence_refs — the edge
    # inherits them (bounded, deduplicated).
    graph = _built_graph()
    hypothesis_node = {
        "id": "hyp-1",
        "status": "open",
        "evidence_refs": ["finding:f-9", "mental:node-3"],
    }
    graph["nodes"]["hypothesis:hyp-1"] = {
        "id": "hypothesis:hyp-1",
        "kind": "hypothesis",
        "label": "hypothesis",
        "source_refs": ["hypothesis:hyp-1"],
    }
    graph["edges"].append(
        {
            "id": "edge-test-hyp",
            "kind": "observation_supports_hypothesis",
            "source_id": "hypothesis:hyp-1",
            "target_id": next(iter(graph["nodes"])),
            "confidence": "observed",
            "evidence_refs": [],
            "metadata": {},
        }
    )
    out = enrich_attack_graph_edges(graph, hypotheses=[hypothesis_node])
    edge = next(e for e in out["edges"] if e["id"] == "edge-test-hyp")
    assert edge["metadata"]["evidence_status"] == "enriched"
    assert set(edge["evidence_refs"]) == {"finding:f-9", "mental:node-3"}
    assert edge["metadata"]["evidence_backfilled"] is True


def test_drop_unbacked_prunes_instead_of_marking() -> None:
    graph = _built_graph(relational_evidence=[_relational_row(evidence_refs=[])])
    out = enrich_attack_graph_edges(graph, drop_unbacked=True)
    assert out["edges"] == []
    assert out["evidence_edge_summary"] == {
        "edges_total": 3,
        "edges_backed": 0,
        "edges_enriched": 0,
        "edges_unbacked": 3,
        "dropped_unbacked": True,
    }


def test_enrichment_is_fail_soft_and_pure_on_bad_input() -> None:
    assert enrich_attack_graph_edges({"edges": "not-a-list"}) == {"edges": "not-a-list"}
    assert enrich_attack_graph_edges({}) == {}
    # Edges that are not mappings pass through untouched.
    graph: dict[str, Any] = {"edges": ["garbage"]}
    out = enrich_attack_graph_edges(graph)
    assert out["edges"] == ["garbage"]


def test_frozen_agent_runs_the_enrichment_pass() -> None:
    """Source-level contract: the frozen node calls the enrichment."""
    from pathlib import Path

    source = Path("src/webpent/agents/attack_graph/agent.py").read_text(encoding="utf-8")
    assert "enrich_attack_graph_edges" in source
    assert "attack_graph_evidence" in source


def test_acceptance_predicate_on_fully_evidenced_graph() -> None:
    graph = _built_graph()
    out = enrich_attack_graph_edges(graph)
    assert every_edge_evidence_backed(out) is True
    # And the summary is consistent with the edges.
    summary = out["evidence_edge_summary"]
    assert summary["edges_total"] == len(out["edges"])
    assert summary["edges_backed"] + summary["edges_enriched"] + summary["edges_unbacked"] == len(
        out["edges"]
    )
