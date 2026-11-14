"""Advisory reasoning helpers for the redacted attack graph."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any


class AttackGraphReasoner:
    """Extract only explicit relationships from an attack graph."""

    _CONFIDENCE = {
        "observed": 1.0,
        "mental_model_observed": 2.0,
        "relational_observed": 3.0,
        "relational_differential": 4.0,
        "causal_observed": 5.0,
    }

    def explain_edge(self, graph: Mapping[str, Any], edge_id: str) -> dict[str, Any]:
        edges = graph.get("edges", []) if isinstance(graph, Mapping) else []
        for edge in edges:
            if isinstance(edge, Mapping) and str(edge.get("id")) == edge_id:
                return {
                    "edge_id": edge_id,
                    "kind": str(edge.get("kind", "")),
                    "source_id": str(edge.get("source_id", "")),
                    "target_id": str(edge.get("target_id", "")),
                    "confidence": str(edge.get("confidence", "unknown")),
                    "evidence_refs": list(edge.get("evidence_refs") or []),
                    "authoritative": False,
                }
        return {
            "edge_id": edge_id,
            "status": "unknown",
            "evidence_refs": [],
            "authoritative": False,
        }

    def gaps(self, graph: Mapping[str, Any]) -> tuple[str, ...]:
        raw = graph.get("coverage_gaps", []) if isinstance(graph, Mapping) else []
        return tuple(dict.fromkeys(str(item) for item in raw if str(item).strip()))

    def recommend_paths(
        self,
        graph: Mapping[str, Any],
        *,
        max_paths: int = 16,
        max_hops: int = 4,
    ) -> dict[str, Any]:
        """Rank explicit evidence-backed paths for planning telemetry.

        The method traverses only directed edges already present in ``graph``.
        Edges without evidence references are excluded, and no node, edge,
        finding, action, or proof object is synthesized.  The result is a
        report-safe advisory projection and is never an execution decision.
        """
        if not isinstance(graph, Mapping):
            return {
                "paths": [],
                "gaps": [],
                "authoritative": False,
                "proposal_only": True,
            }
        try:
            path_limit = max(1, min(int(max_paths), 64))
            hop_limit = max(1, min(int(max_hops), 8))
        except (TypeError, ValueError):
            path_limit, hop_limit = 16, 4

        edges_by_source: dict[str, list[dict[str, Any]]] = {}
        seen_edge_ids: set[str] = set()
        raw_edges = graph.get("edges", [])
        if not isinstance(raw_edges, (list, tuple)):
            raw_edges = []
        for index, raw_edge in enumerate(raw_edges):
            if not isinstance(raw_edge, Mapping):
                continue
            source_id = str(raw_edge.get("source_id") or "").strip()[:200]
            target_id = str(raw_edge.get("target_id") or "").strip()[:200]
            if not source_id or not target_id:
                continue
            raw_refs = raw_edge.get("evidence_refs")
            if not isinstance(raw_refs, (list, tuple)):
                continue
            evidence_refs = list(
                dict.fromkeys(
                    str(reference).strip()[:240] for reference in raw_refs if str(reference).strip()
                )
            )[:16]
            if not evidence_refs:
                continue
            edge_id = str(raw_edge.get("id") or "").strip()[:200]
            if not edge_id:
                digest = hashlib.sha256(
                    f"{source_id}|{target_id}|{raw_edge.get('kind', '')}|{index}".encode()
                ).hexdigest()[:16]
                edge_id = f"edge:{digest}"
            if edge_id in seen_edge_ids:
                continue
            seen_edge_ids.add(edge_id)
            edge = {
                "id": edge_id,
                "kind": str(raw_edge.get("kind") or "related")[:100],
                "source_id": source_id,
                "target_id": target_id,
                "confidence": str(raw_edge.get("confidence") or "observed")[:80],
                "evidence_refs": evidence_refs,
            }
            edges_by_source.setdefault(source_id, []).append(edge)

        for candidates in edges_by_source.values():
            candidates.sort(key=lambda item: item["id"])

        paths: list[dict[str, Any]] = []

        def walk(
            current: str,
            edge_path: list[dict[str, Any]],
            visited_nodes: set[str],
        ) -> None:
            if len(edge_path) >= hop_limit:
                return
            for edge in edges_by_source.get(current, []):
                target = edge["target_id"]
                if target in visited_nodes:
                    continue
                next_edges = edge_path + [edge]
                edge_ids = [item["id"] for item in next_edges]
                node_ids = [next_edges[0]["source_id"]] + [item["target_id"] for item in next_edges]
                evidence_refs = list(
                    dict.fromkeys(
                        reference for item in next_edges for reference in item["evidence_refs"]
                    )
                )[:32]
                confidence_score = sum(
                    self._CONFIDENCE.get(item["confidence"], 0.0) for item in next_edges
                ) / len(next_edges)
                score = round(
                    min(1.0, (confidence_score / 5.0) + min(len(evidence_refs), 4) * 0.05),
                    3,
                )
                digest = hashlib.sha256("|".join(edge_ids).encode()).hexdigest()[:16]
                paths.append(
                    {
                        "path_id": f"path:{digest}",
                        "edge_ids": edge_ids,
                        "node_ids": node_ids,
                        "evidence_refs": evidence_refs,
                        "score": score,
                        "status": "advisory",
                        "authoritative": False,
                    }
                )
                walk(target, next_edges, visited_nodes | {target})

        sources = sorted(edges_by_source)
        for source in sources:
            walk(source, [], {source})

        paths.sort(
            key=lambda item: (
                -float(item["score"]),
                -len(item["edge_ids"]),
                item["path_id"],
            )
        )
        return {
            "paths": paths[:path_limit],
            "gaps": list(self.gaps(graph)),
            "authoritative": False,
            "proposal_only": True,
        }


__all__ = ["AttackGraphReasoner"]
