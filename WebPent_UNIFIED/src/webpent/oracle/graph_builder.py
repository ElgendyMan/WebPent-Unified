"""THE ORACLE — U-ORACLE-4, the Attack Graph Builder (v88).

Builds the relational picture: who trusts whom, who reads from whom,
who influences whom. The builder is pure data transformation over
already-gathered evidence — it performs no requests whatsoever
(ORACLE-L-1/L-2/L-6). Node criticality and edge types come from
config/oracle/graph_rules.yaml; nothing is invented here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from webpent.oracle.models import OracleLawError, sha256_text
from webpent.oracle.osint import OsintReport
from webpent.oracle.signal_aggregator import OracleSignal
from webpent.oracle.stack_inferrer import TechStackProfile


def _stable_id(node_type: str, kind: str, label: str,
               evidence_hash: str) -> str:
    """RT-05: uuid4 churned node ids on every rebuild, so prediction ids
    hashed from node ids churned too and `oracle predict` re-recorded the
    same logical prediction on every run. Derive the id from the node's
    own stable content so the same logical node always gets the same id
    (ORACLE-L-6/L-8)."""
    digest = sha256_text("|".join((node_type, kind, label, evidence_hash)))
    return f"{node_type}:{digest[:12]}"

# evidence category → edge type toward the host node
CATEGORY_EDGE = {
    "credential": "authenticates_with",
    "data_leak": "reads_from",
    "endpoint": "serves",
    "subdomain": "same_owner",
    "tech": "deploy_on",
}


@dataclass
class GraphNode:
    node_id: str
    node_type: str
    label: str
    criticality: float
    confidence: float
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "label": self.label,
            "criticality": round(self.criticality, 3),
            "confidence": round(self.confidence, 3),
            "data": self.data,
        }


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    edge_type: str
    weight: float
    evidence_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type,
            "weight": round(self.weight, 3),
            "evidence_hash": self.evidence_hash,
        }


@dataclass
class AttackGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> GraphNode:
        self.nodes[node.node_id] = node
        return node

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
            raise OracleLawError(
                "edge endpoints must be nodes of this graph "
                "(ORACLE-L-6: graph from truth, no dangling relations)"
            )
        self.edges.append(edge)
        return edge

    def neighbors(self, node_id: str) -> list[GraphNode]:
        ids = {
            e.target_id for e in self.edges if e.source_id == node_id
        } | {e.source_id for e in self.edges if e.target_id == node_id}
        return [self.nodes[i] for i in sorted(ids) if i in self.nodes]

    def entry_nodes(self, rules: dict) -> list[GraphNode]:
        categories = set(rules.get("entry_rules", {}).get(
            "entry_categories", []
        ))
        max_crit = float(
            rules.get("entry_rules", {}).get("max_criticality", 1.0)
        )
        return [
            n for n in self.nodes.values()
            # RT-06: `and` bound tighter than `or` here, which let ANY node
            # with criticality <= max become an attack entry regardless of
            # category (a low-confidence credential node at 0.54 started
            # the kill chain). Both entry rules must constrain together,
            # mirroring target_nodes below.
            if n.node_type in categories and n.criticality <= max_crit
        ]

    def target_nodes(self, rules: dict) -> list[GraphNode]:
        categories = set(rules.get("target_rules", {}).get(
            "target_categories", []
        ))
        min_crit = float(
            rules.get("target_rules", {}).get("min_criticality", 1.0)
        )
        return [
            n for n in self.nodes.values()
            if n.node_type in categories and n.criticality >= min_crit
        ]

    def merge(self, other: AttackGraph) -> AttackGraph:
        """Union of nodes (higher criticality wins) and edges (deduped by
        endpoints + type, stronger weight wins)."""
        for node in other.nodes.values():
            mine = self.nodes.get(node.node_id)
            if mine is None:
                self.nodes[node.node_id] = node
            else:
                mine.criticality = max(mine.criticality, node.criticality)
                mine.confidence = max(mine.confidence, node.confidence)
        seen: dict[tuple[str, str, str], GraphEdge] = {}
        for edge in self.edges + other.edges:
            # structural identity (endpoints+type) OR evidential identity
            # (same evidence hash pointing at the same target) — the same
            # finding must never appear as two parallel relations.
            key = (
                edge.evidence_hash or edge.source_id,
                edge.target_id,
                edge.edge_type,
            )
            existing = seen.get(key)
            if existing is None or edge.weight > existing.weight:
                seen[key] = edge
        self.edges = list(seen.values())
        return self

    def export_dot(self) -> str:
        def esc(text: str) -> str:
            # RT-09: raw operator data with a quote or backslash produced
            # invalid DOT; escape both before embedding in the label.
            return text.replace("\\", "\\\\").replace('"', '\\"')

        lines = ["digraph oracle_attack_graph {"]
        for node in self.nodes.values():
            lines.append(
                f'  "{esc(node.node_id)}" [label="{esc(node.label)} '
                f'({esc(node.node_type)})"];'
            )
        for edge in self.edges:
            lines.append(
                f'  "{esc(edge.source_id)}" -> "{esc(edge.target_id)}" '
                f'[label="{esc(edge.edge_type)}"];'
            )
        lines.append("}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }


class GraphBuilder:
    def __init__(self, graph_rules_path: Path) -> None:
        data = yaml.safe_load(
            Path(graph_rules_path).read_text(encoding="utf-8")
        ) or {}
        for key in ("node_criticality_defaults", "edge_weights",
                    "entry_rules", "target_rules"):
            if key not in data:
                raise OracleLawError(f"graph_rules.yaml missing {key!r}")
        self._rules = data
        self._defaults = {
            k: float(v)
            for k, v in data["node_criticality_defaults"].items()
        }
        self._edge_weights = {
            k: float(v) for k, v in data["edge_weights"].items()
        }

    def build(
        self,
        report: OsintReport,
        stack_profile: TechStackProfile | None = None,
        signals: list[OracleSignal] | None = None,
    ) -> AttackGraph:
        graph = AttackGraph()
        host_id = "host:" + report.target_id
        graph.add_node(
            GraphNode(
                node_id=host_id,
                node_type="host",
                label=report.target_id,
                criticality=0.5,
                confidence=1.0,
            )
        )
        for finding in report.findings:
            node_type = finding.category
            default = self._defaults.get(node_type, 0.3)
            criticality = min(1.0, default * max(finding.confidence, 0.5))
            label = str(
                finding.raw_data.get(
                    "repo",
                    finding.raw_data.get("subdomain",
                    finding.raw_data.get("url", node_type)),
                )
            )[:60]
            node = graph.add_node(
                GraphNode(
                    # RT-05: uuid4 made every rebuild a different graph,
                    # so prediction ids hashed from node ids churned and
                    # `oracle predict` re-recorded the same logical
                    # prediction on every run. Derive the id from the
                    # finding's own stable content instead.
                    node_id=_stable_id(node_type, node_type, label,
                                       finding.evidence_hash),
                    node_type=node_type,
                    label=label,
                    criticality=criticality,
                    confidence=finding.confidence,
                    data={"source": finding.source,
                          "evidence": finding.evidence_hash},
                )
            )
            edge_type = CATEGORY_EDGE.get(node_type)
            if edge_type:
                graph.add_edge(
                    GraphEdge(
                        source_id=node.node_id,
                        target_id=host_id,
                        edge_type=edge_type,
                        weight=self._edge_weights[edge_type],
                        evidence_hash=finding.evidence_hash,
                    )
                )
        if stack_profile is not None:
            for comp in stack_profile.components:
                node_type = (
                    "outdated_component" if comp.name in stack_profile.cves
                    else "tech"
                )
                node = graph.add_node(
                    GraphNode(
                        node_id=f"component:{comp.name}",
                        node_type=node_type,
                        label=f"{comp.name}"
                        + (f" {comp.version}" if comp.version else ""),
                        criticality=min(
                            1.0,
                            self._defaults.get(node_type, 0.3)
                            * max(comp.confidence, 0.5),
                        ),
                        confidence=comp.confidence,
                    )
                )
                graph.add_edge(
                    GraphEdge(
                        source_id=node.node_id,
                        target_id=host_id,
                        edge_type="deploy_on",
                        weight=self._edge_weights["deploy_on"],
                    )
                )
        if signals:
            for signal in signals:
                if signal.signal_type == "subdomain_takeover_candidate":
                    node = graph.add_node(
                        GraphNode(
                            # RT-05: same stable-content derivation as finding
                        # nodes — a rebuilt graph must be byte-identical.
                        node_id=_stable_id("subdomain", "takeover",
                                           signal.signal_id,
                                           signal.signal_id),
                            node_type="subdomain",
                            label=signal.signal_id,
                            criticality=0.6,
                            confidence=signal.strength,
                        )
                    )
                    graph.add_edge(
                        GraphEdge(
                            source_id=node.node_id,
                            target_id=host_id,
                            edge_type="same_owner",
                            weight=self._edge_weights["same_owner"],
                        )
                    )
        return graph


__all__ = [
    "AttackGraph",
    "GraphBuilder",
    "GraphEdge",
    "GraphNode",
]
