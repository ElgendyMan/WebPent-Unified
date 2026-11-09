"""THE ORACLE — U-ORACLE-5, the Path Predictor (v88).

A modified Dijkstra over the attack graph: from every entry point to
every crown jewel, enumerating simple paths (bounded depth) and scoring
them by relation strength, node criticality, length and — decisively —
detection risk. The score is deterministic: the same graph always
produces the same ranked paths. Prediction only; nothing is executed
(ORACLE-L-10).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from webpent.oracle.graph_builder import AttackGraph
from webpent.oracle.models import OracleLawError


@dataclass
class PathPrediction:
    path: list[str]                       # node ids, entry → target
    score: float
    detection_risk: float
    edge_types: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": list(self.path),
            "score": round(self.score, 4),
            "detection_risk": round(self.detection_risk, 3),
            "edge_types": list(self.edge_types),
        }


class PathPredictor:
    def __init__(self, graph_rules_path: Path) -> None:
        data = yaml.safe_load(
            Path(graph_rules_path).read_text(encoding="utf-8")
        ) or {}
        for key in ("entry_rules", "target_rules", "detection_risk",
                    "path_predictor"):
            if key not in data:
                raise OracleLawError(
                    f"graph_rules.yaml missing {key!r} for prediction"
                )
        self._rules = data
        self._risk = {k: float(v) for k, v in data["detection_risk"].items()}
        cfg = data["path_predictor"]
        self._length_penalty = float(cfg.get("length_penalty", 0.85))
        self._max_depth = int(cfg.get("max_depth", 5))
        self._top_k = int(cfg.get("top_k", 5))

    # -- adjacency (relations traverse both ways: influence is symmetric) ----

    def _adjacency(self, graph: AttackGraph) -> dict[str, list[tuple[str, str, float]]]:
        adj: dict[str, list[tuple[str, str, float]]] = {
            node_id: [] for node_id in graph.nodes
        }
        for edge in graph.edges:
            w = edge.weight
            adj.setdefault(edge.source_id, []).append(
                (edge.target_id, edge.edge_type, w)
            )
            adj.setdefault(edge.target_id, []).append(
                (edge.source_id, edge.edge_type, w)
            )
        return adj

    # -- enumeration ---------------------------------------------------------

    def _simple_paths(
        self, graph: AttackGraph, start: str, end: str,
        adj: dict[str, list[tuple[str, str, float]]],
    ) -> list[list[tuple[str, str, float]]]:
        results: list[list[tuple[str, str, float]]] = []

        def walk(node_id: str, visited: set[str],
                 trail: list[tuple[str, str, float]]) -> None:
            if len(visited) > self._max_depth:
                return
            if node_id == end:
                results.append(list(trail))
                return
            for next_id, edge_type, weight in sorted(adj.get(node_id, [])):
                if next_id in visited:
                    continue
                visited.add(next_id)
                trail.append((next_id, edge_type, weight))
                walk(next_id, visited, trail)
                trail.pop()
                visited.discard(next_id)

        walk(start, {start}, [])
        return results

    def _score(
        self, graph: AttackGraph, start: str,
        trail: list[tuple[str, str, float]],
    ) -> tuple[float, float]:
        from webpent.oracle.graph_builder import GraphNode

        weight_product = 1.0
        criticality_product = 1.0
        risk_total = 0.0
        for next_id, edge_type, weight in trail:
            weight_product *= weight
            node = graph.nodes.get(next_id)
            if isinstance(node, GraphNode):
                criticality_product *= max(node.criticality, 0.1)
            risk_total += self._risk.get(edge_type, 0.2)
        hops = len(trail)
        score = (
            criticality_product
            * weight_product
            * (self._length_penalty ** max(hops - 1, 0))
        ) / ((1.0 + risk_total) ** 2)
        return score, risk_total

    # -- public surface -----------------------------------------------------------

    def predict(self, graph: AttackGraph) -> list[PathPrediction]:
        rules = self._rules
        entries = [
            n.node_id for n in graph.entry_nodes(rules)
        ]
        targets = {
            n.node_id for n in graph.target_nodes(rules)
        }
        adj = self._adjacency(graph)
        scored: list[PathPrediction] = []
        for entry in sorted(entries):
            for end in sorted(targets):
                if entry == end:
                    continue
                for trail in self._simple_paths(graph, entry, end, adj):
                    if not trail:
                        continue
                    score, risk = self._score(graph, entry, trail)
                    scored.append(
                        PathPrediction(
                            path=[entry] + [t[0] for t in trail],
                            score=score,
                            detection_risk=risk,
                            edge_types=[t[1] for t in trail],
                        )
                    )
        scored.sort(key=lambda p: (-p.score, tuple(p.path)))
        return scored[: self._top_k]

    # -- validation + explanation (no execution) -----------------------------------

    def validate_path(self, graph: AttackGraph, path: list[str]) -> bool:
        if len(path) < 2 or any(n not in graph.nodes for n in path):
            return False
        edges_by_pair = {
            (e.source_id, e.target_id) for e in graph.edges
        } | {(e.target_id, e.source_id) for e in graph.edges}
        return all(
            (a, b) in edges_by_pair
            for a, b in zip(path, path[1:], strict=False)
        )

    def explain_path(
        self, graph: AttackGraph, prediction: PathPrediction
    ) -> str:
        steps = [graph.nodes[p].label for p in prediction.path]
        relations = [
            f"{a} --{t}--> {b}"
            for a, t, b in zip(
                steps, prediction.edge_types, steps[1:], strict=False
            )
        ]
        return (
            "predicted route: "
            + " -> ".join(steps)
            + " | via: "
            + "; ".join(relations)
            + f" | score {prediction.score:.3f}, "
            f"detection risk {prediction.detection_risk:.2f}"
        )


__all__ = ["PathPrediction", "PathPredictor"]
