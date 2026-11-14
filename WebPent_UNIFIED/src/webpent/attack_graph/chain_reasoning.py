"""Evidence-aware vulnerability chain reasoning.

A chain is a bounded reasoning artifact.  It can prioritize a validation path,
but it cannot become a finding or a confirmed exploit without the existing
causal oracle and proof gates.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from webpent.models.attack_graph import AttackGraph


@dataclass(frozen=True)
class ChainStep:
    """One explicit graph edge in a potential chain."""

    edge_id: str
    source_id: str
    target_id: str
    relation: str
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class VulnerabilityChain:
    """A potential chain that still requires validation."""

    chain_id: str
    node_ids: tuple[str, ...]
    steps: tuple[ChainStep, ...]
    reasoning: str
    evidence_refs: tuple[str, ...]
    status: str = "potential"
    validation_required: bool = True

    @property
    def eligible_for_validation(self) -> bool:
        return bool(self.steps and self.evidence_refs and self.status == "potential")

    def as_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "node_ids": list(self.node_ids),
            "steps": [
                {
                    "edge_id": step.edge_id,
                    "source_id": step.source_id,
                    "target_id": step.target_id,
                    "relation": step.relation,
                    "evidence_refs": list(step.evidence_refs),
                }
                for step in self.steps
            ],
            "reasoning": self.reasoning,
            "evidence_refs": list(self.evidence_refs),
            "status": self.status,
            "validation_required": self.validation_required,
            "eligible_for_validation": self.eligible_for_validation,
        }


class VulnerabilityChainReasoner:
    """Enumerate short, evidence-backed directed paths as potential chains."""

    def __init__(self, *, max_hops: int = 4, max_chains: int = 32) -> None:
        self.max_hops = max(1, min(int(max_hops), 8))
        self.max_chains = max(1, min(int(max_chains), 128))

    def derive(self, graph: AttackGraph | Mapping[str, Any]) -> tuple[VulnerabilityChain, ...]:
        nodes, edges, errors = self._normalize(graph)
        if errors:
            return ()
        adjacency: dict[str, list[dict[str, Any]]] = {}
        for edge in edges:
            if not edge["evidence_refs"]:
                continue
            adjacency.setdefault(edge["source_id"], []).append(edge)
        for values in adjacency.values():
            values.sort(key=lambda item: item["id"])

        chains: list[VulnerabilityChain] = []

        def walk(current: str, path: list[dict[str, Any]], visited: set[str]) -> None:
            if len(path) >= self.max_hops:
                return
            for edge in adjacency.get(current, []):
                target = edge["target_id"]
                if target in visited:
                    continue
                next_path = [*path, edge]
                node_ids = (next_path[0]["source_id"],) + tuple(
                    item["target_id"] for item in next_path
                )
                if len(next_path) >= 2:
                    steps = tuple(
                        ChainStep(
                            edge_id=item["id"],
                            source_id=item["source_id"],
                            target_id=item["target_id"],
                            relation=item["kind"],
                            evidence_refs=tuple(item["evidence_refs"]),
                        )
                        for item in next_path
                    )
                    evidence = tuple(
                        dict.fromkeys(ref for item in steps for ref in item.evidence_refs)
                    )
                    chain_id = (
                        "chain:"
                        + hashlib.sha256(
                            "|".join(item.edge_id for item in steps).encode()
                        ).hexdigest()[:20]
                    )
                    labels = [self._label(nodes, node_id) for node_id in node_ids]
                    relations = [item.relation for item in steps]
                    chains.append(
                        VulnerabilityChain(
                            chain_id=chain_id,
                            node_ids=node_ids,
                            steps=steps,
                            reasoning=" -> ".join([*labels, f"relations={','.join(relations)}"]),
                            evidence_refs=evidence[:32],
                        )
                    )
                walk(target, next_path, visited | {target})

        for source in sorted(adjacency):
            walk(source, [], {source})
        unique = {chain.chain_id: chain for chain in chains}
        return tuple(
            sorted(unique.values(), key=lambda chain: (-len(chain.steps), chain.chain_id))[
                : self.max_chains
            ]
        )

    @staticmethod
    def _label(nodes: Mapping[str, Any], node_id: str) -> str:
        node = nodes.get(node_id)
        if isinstance(node, Mapping):
            return str(node.get("label") or node_id)[:120]
        return str(getattr(node, "label", node_id))[:120]

    @staticmethod
    def _normalize(
        graph: AttackGraph | Mapping[str, Any],
    ) -> tuple[Mapping[str, Any], list[dict[str, Any]], tuple[str, ...]]:
        if isinstance(graph, AttackGraph):
            nodes: Mapping[str, Any] = graph.nodes
            raw_edges: Any = graph.edges
            errors = tuple(graph.consistency_errors)
        elif isinstance(graph, Mapping):
            nodes = graph.get("nodes") or {}
            raw_edges = graph.get("edges") or []
            raw_errors = graph.get("consistency_errors") or []
            errors = tuple(str(item) for item in raw_errors if str(item).strip())
        else:
            return {}, [], ("graph_not_mapping",)
        edges: list[dict[str, Any]] = []
        for raw in raw_edges:
            item = dict(raw) if isinstance(raw, Mapping) else raw.model_dump(mode="json")
            source = str(item.get("source_id") or "")
            target = str(item.get("target_id") or "")
            edge_id = str(item.get("id") or "")
            refs = tuple(str(ref) for ref in item.get("evidence_refs") or () if str(ref).strip())
            if source not in nodes or target not in nodes:
                errors = (*errors, f"edge_endpoint_missing:{edge_id or source}")
                continue
            edges.append(
                {
                    "id": edge_id or f"edge:{source}:{target}",
                    "kind": str(item.get("kind") or "related"),
                    "source_id": source,
                    "target_id": target,
                    "evidence_refs": refs,
                }
            )
        return nodes, edges, tuple(dict.fromkeys(errors))


__all__ = ["ChainStep", "VulnerabilityChain", "VulnerabilityChainReasoner"]
