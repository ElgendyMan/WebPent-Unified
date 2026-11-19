# src/webpent/attack_graph/source_lane.py
"""Advisory source-code lane annotations for the attack graph.

Part of the Shannon→GOED protected integration (docs/integration/).
This module is the **additive wiring point** between
:mod:`webpent.integration.source_mapping` (source ↔ runtime join) and
GOED's native attack-graph projection
(:class:`~webpent.models.attack_graph.AttackGraph`). It adds a bounded
``source_lane`` annotation into the ``metadata`` of ENDPOINT nodes —
an additive field only; node identity, kinds, edges, and semantics are
never modified, and no FORBIDDEN file is touched (see
GOED_PROTECTED_INVENTORY.md §5, which designates ``attack_graph/`` as
RESTRICTED-additive).

Security contract:

* Purely **advisory annotation**: a source lane can enrich research
  and reporting; it can never confirm, score, or promote anything
  (CausalGuard remains the sole verdict authority, protocol §8).
* Locations carry paths/lines/symbols only — no source text, no file
  contents, no secrets (mirrors the source-mapping contract).
* Pure function: the input graph is never mutated; a NEW graph is
  returned. Unmatched mappings and unmatched nodes are left untouched
  (fail-silent-by-design for annotations, never for verdicts).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from webpent.integration.source_mapping import JoinedMapping
from webpent.models.attack_graph import AttackGraph, AttackGraphNode, AttackGraphNodeKind

SOURCE_LANE_VERSION = "integration-source-lane-1.0"
SOURCE_LANE_KEY = "source_lane"

# Deterministic caps for one node's annotation payload.
MAX_LOCATIONS = 16
MAX_HYPOTHESES = 16
MAX_EVIDENCE_REFS = 16
MAX_MAPPINGS_PER_NODE = 16


def _normalized(value: str) -> str:
    return "/" + "/".join(p for p in value.replace("\\", "/").split("/") if p not in ("", "."))


def _path_matches(node_path: str, mapping_path: str) -> bool:
    """Deterministic suffix path match (advisory heuristic).

    Two normalized paths are equivalent when identical, or when one is
    a whole-segment suffix of the other (e.g. the graph may carry the
    full origin path while the mapping carries the route path). Purely
    lexical: no network, no globbing, no case folding beyond exact
    normalized comparison.
    """
    a = _normalized(node_path)
    b = _normalized(mapping_path)
    if a == b:
        return True
    return a.endswith(b + "/") or b.endswith(a + "/")


def _node_endpoint_path(node: AttackGraphNode) -> str:
    """Best-effort deterministic endpoint path of a graph node."""
    meta_path = node.metadata.get("path") if isinstance(node.metadata, dict) else None
    return str(meta_path) if isinstance(meta_path, str) and meta_path.strip() else node.label


def _lane_payload(
    endpoint_path: str,
    http_method: str,
    joined: Sequence[JoinedMapping],
) -> dict[str, Any]:
    locations: list[dict[str, Any]] = []
    hypothesis_ids: list[str] = []
    evidence_refs: list[str] = []
    mapping_ids: list[str] = []
    for rec in joined[:MAX_MAPPINGS_PER_NODE]:
        for loc in rec.locations:
            if len(locations) >= MAX_LOCATIONS:
                break
            locations.append(
                {
                    "file": loc.normalized_file,
                    "start_line": loc.start_line,
                    "end_line": loc.end_line,
                    "role": loc.role.value,
                    "symbol": loc.symbol,
                }
            )
        for hid in rec.hypothesis_ids:
            if hid not in hypothesis_ids and len(hypothesis_ids) < MAX_HYPOTHESES:
                hypothesis_ids.append(hid)
        for ref in rec.evidence_refs:
            if ref not in evidence_refs and len(evidence_refs) < MAX_EVIDENCE_REFS:
                evidence_refs.append(ref)
        for mid in rec.mapping_ids:
            if mid not in mapping_ids and len(mapping_ids) < MAX_MAPPINGS_PER_NODE:
                mapping_ids.append(mid)
    return {
        "schema_version": SOURCE_LANE_VERSION,
        "endpoint_path": endpoint_path,
        "http_method": http_method,
        "locations": locations,
        "hypothesis_ids": hypothesis_ids,
        "evidence_refs": evidence_refs,
        "mapping_ids": mapping_ids,
    }


def attach_source_lane(
    graph: AttackGraph,
    joined: Sequence[JoinedMapping],
) -> AttackGraph:
    """Return a NEW graph with advisory ``source_lane`` annotations.

    Only ENDPOINT nodes are annotated, and only when a joined mapping
    matches the node's endpoint path (deterministic suffix match). The
    input graph object is never mutated. Annotations live under the
    additive ``metadata["source_lane"]`` key and are bounded by the
    module-level caps.
    """
    if not joined:
        return graph.model_copy(deep=True)
    ranked = sorted(joined, key=lambda j: (j.endpoint_path, j.http_method))
    new_nodes: dict[str, AttackGraphNode] = {}
    annotated = 0
    for node_id, node in graph.nodes.items():
        # use_enum_values=True: node.kind is stored as its string value.
        if node.kind != AttackGraphNodeKind.ENDPOINT.value:
            new_nodes[node_id] = node
            continue
        node_path = _node_endpoint_path(node)
        matches = [j for j in ranked if _path_matches(node_path, j.endpoint_path)]
        if not matches:
            new_nodes[node_id] = node
            continue
        method = matches[0].http_method
        lane = _lane_payload(node_path, method, matches)
        metadata = dict(node.metadata)
        # Idempotent: identical inputs always produce the identical lane.
        metadata[SOURCE_LANE_KEY] = lane
        new_nodes[node_id] = node.model_copy(update={"metadata": metadata})
        annotated += 1

    return graph.model_copy(update={"nodes": new_nodes})


def source_lane_summary(graph: AttackGraph) -> dict[str, Any]:
    """Audit view: which ENDPOINT nodes carry a source lane."""
    lanes: list[dict[str, Any]] = []
    for node_id, node in sorted(graph.nodes.items()):
        lane = node.metadata.get(SOURCE_LANE_KEY) if isinstance(node.metadata, dict) else None
        if isinstance(lane, dict) and lane.get("schema_version") == SOURCE_LANE_VERSION:
            lanes.append(
                {
                    "node_id": node_id,
                    "endpoint_path": lane.get("endpoint_path", ""),
                    "http_method": lane.get("http_method", ""),
                    "location_count": len(lane.get("locations", [])),
                    "hypothesis_ids": list(lane.get("hypothesis_ids", [])),
                    "evidence_refs": list(lane.get("evidence_refs", [])),
                }
            )
    return {
        "schema_version": SOURCE_LANE_VERSION,
        "annotated_nodes": len(lanes),
        "lanes": lanes,
    }


__all__ = [
    "SOURCE_LANE_KEY",
    "SOURCE_LANE_VERSION",
    "attach_source_lane",
    "source_lane_summary",
]
