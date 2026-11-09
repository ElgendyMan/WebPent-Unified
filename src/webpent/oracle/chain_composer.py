"""THE ORACLE — U-ORACLE-6, the Chain Composer (v88).

Composes attack-chain hypotheses by matching config-driven patterns
against the attack graph. Every proposal is advisory-only: a pattern the
operator reviews, never an action the framework performs (ORACLE-L-10).
Patterns come from config/oracle/attack_chains.yaml; nothing is invented
in code (ORACLE-L-11).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from webpent.oracle.graph_builder import AttackGraph
from webpent.oracle.models import OracleLawError
from webpent.oracle.path_predictor import PathPrediction

VALID_NODE_TYPES = {
    "host", "credential", "data_leak", "endpoint", "subdomain",
    "tech", "outdated_component",
}


@dataclass
class ChainProposal:
    proposal_id: str
    pattern_id: str
    name: str
    description: str
    nodes: list[str]                       # node ids along the matched path
    steps: list[str]
    impact_category: str
    payout_delta: float
    score: float
    advisory: bool = True                  # ORACLE-L-10: proposals never execute
    matched_edges: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "pattern_id": self.pattern_id,
            "name": self.name,
            "description": self.description,
            "nodes": list(self.nodes),
            "steps": list(self.steps),
            "impact_category": self.impact_category,
            "payout_delta": round(self.payout_delta, 3),
            "score": round(self.score, 4),
            "advisory": self.advisory,
            "matched_edges": list(self.matched_edges),
        }


def _validate_pattern(raw: Any, index: int) -> dict:
    if not isinstance(raw, dict):
        raise OracleLawError(f"chain pattern #{index} must be a mapping")
    required = ("pattern_id", "name", "required_nodes", "required_edges",
                "impact_category", "payout_delta", "steps")
    for key in required:
        if key not in raw:
            raise OracleLawError(
                f"chain pattern {raw.get('pattern_id', index)} missing {key!r}"
            )
    nodes = list(raw["required_nodes"])
    edges = list(raw["required_edges"])
    if not nodes:
        raise OracleLawError(f"{raw['pattern_id']}: required_nodes is empty")
    if len(edges) != len(nodes) - 1:
        raise OracleLawError(
            f"{raw['pattern_id']}: required_edges must have exactly "
            f"len(required_nodes) - 1 entries"
        )
    for node_type in nodes:
        if node_type not in VALID_NODE_TYPES:
            raise OracleLawError(
                f"{raw['pattern_id']}: unknown node type {node_type!r}"
            )
    payout = float(raw["payout_delta"])
    if not 0.0 <= payout <= 1.0:
        raise OracleLawError(
            f"{raw['pattern_id']}: payout_delta must be within [0, 1]"
        )
    if not list(raw["steps"]):
        raise OracleLawError(f"{raw['pattern_id']}: steps must not be empty")
    return raw


class ChainComposer:
    def __init__(self, chains_path: Path) -> None:
        data = yaml.safe_load(
            Path(chains_path).read_text(encoding="utf-8")
        ) or {}
        if "chain_patterns" not in data:
            raise OracleLawError(
                "attack_chains.yaml missing 'chain_patterns'"
            )
        self._patterns = [
            _validate_pattern(raw, i)
            for i, raw in enumerate(data["chain_patterns"])
        ]

    # -- path enumeration (bounded, over the graph only) ----------------------

    def _walk(
        self, graph: AttackGraph, max_depth: int = 6,
    ) -> list[tuple[list[str], list[str]]]:
        """All simple paths (node ids + edge types) up to max_depth hops,
        starting from every node. Graph-local; no requests."""
        adj: dict[str, list[tuple[str, str]]] = {n: [] for n in graph.nodes}
        for edge in graph.edges:
            adj.setdefault(edge.source_id, []).append(
                (edge.target_id, edge.edge_type)
            )
            adj.setdefault(edge.target_id, []).append(
                (edge.source_id, edge.edge_type)
            )
        paths: list[tuple[list[str], list[str]]] = []

        def walk(node_id: str, nodes: list[str], edges: list[str]) -> None:
            if len(nodes) > max_depth:
                return
            paths.append((list(nodes), list(edges)))
            for next_id, edge_type in sorted(adj.get(node_id, [])):
                if next_id in nodes:
                    continue
                nodes.append(next_id)
                edges.append(edge_type)
                walk(next_id, nodes, edges)
                nodes.pop()
                edges.pop()

        for start in sorted(graph.nodes):
            walk(start, [start], [])
        return paths

    def _match(self, node_types: list[str], edge_types: list[str],
               pattern: dict) -> tuple[int, list[str]] | None:
        """Return (start_index, matched_edges) of the first contiguous
        window matching the pattern, else None."""
        width = len(pattern["required_nodes"])
        want_edges = list(pattern["required_edges"])
        if width > len(node_types):
            return None
        for start in range(len(node_types) - width + 1):
            window_types = node_types[start:start + width]
            window_edges = edge_types[start:start + width - 1]
            if window_types != [str(t) for t in pattern["required_nodes"]]:
                continue
            if width == 1 or window_edges == want_edges:
                return start, list(window_edges)
        return None

    # -- public surface -------------------------------------------------------

    def compose(
        self,
        graph: AttackGraph,
        predictions: list[PathPrediction] | None = None,
    ) -> list[ChainProposal]:
        paths = self._walk(graph)
        predicted_nodes: set[str] = set()
        for pred in predictions or []:
            predicted_nodes.update(pred.path)

        proposals: dict[tuple[str, tuple[str, ...]], ChainProposal] = {}
        for node_ids, edge_ids in paths:
            node_types = [
                graph.nodes[n].node_type for n in node_ids if n in graph.nodes
            ]
            if len(node_types) != len(node_ids):
                continue
            for pattern in self._patterns:
                hit = self._match(node_types, edge_ids, pattern)
                if hit is None:
                    continue
                start, matched_edges = hit
                window = node_ids[start:start + len(pattern["required_nodes"])]
                key = (pattern["pattern_id"], tuple(window))
                window_nodes = [graph.nodes[n] for n in window]
                confidence = sum(n.confidence for n in window_nodes) / len(
                    window_nodes
                )
                score = float(pattern["payout_delta"]) * confidence
                if predicted_nodes and set(window) <= predicted_nodes:
                    score *= 1.15   # corroborated by a predicted route
                proposal = ChainProposal(
                    proposal_id=(
                        f"{pattern['pattern_id']}:" + "->".join(window)
                    ),
                    pattern_id=pattern["pattern_id"],
                    name=pattern["name"],
                    description=pattern["description"],
                    nodes=window,
                    steps=[str(s) for s in pattern["steps"]],
                    impact_category=pattern["impact_category"],
                    payout_delta=float(pattern["payout_delta"]),
                    score=score,
                    matched_edges=matched_edges,
                )
                existing = proposals.get(key)
                if existing is None or proposal.score > existing.score:
                    proposals[key] = proposal
        ranked = sorted(
            proposals.values(),
            key=lambda p: (-p.score, p.proposal_id),
        )
        return ranked


__all__ = ["ChainComposer", "ChainProposal"]
