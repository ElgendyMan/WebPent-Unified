"""webpent.shared.attack_graph_evidence — M3 UM-DR-17: evidence-edge
enrichment for the Attack Graph projection.

Registry contract (CANONICAL_PHASE_REGISTRY M3 acceptance): "every
attack-graph edge evidence-backed". ``build_attack_graph`` (frozen)
already threads evidence through its typed adders, but three edge
families can still land with EMPTY ``evidence_refs``:

* mental-model edges whose ``source_ref`` is blank;
* relational edges whose row carried no ``evidence_refs``;
* causal edges whose row carried none either.

This module is the post-pass (NEW file, outside the frozen gate; the
frozen attack_graph agent calls it after ``build_attack_graph``):

1. **Status marking** — every edge gets
   ``metadata["evidence_status"]`` ∈ {backed, enriched, unbacked}, so
   the acceptance claim is verifiable per edge, not asserted in bulk.
2. **Honest backfill** — an empty edge is enriched ONLY from real
   evidence that already exists:
   * a finding-tied edge inherits the finding's canonical pointer
     (``finding:<id>`` + its ``evidence_hash`` when sealed);
   * a hypothesis-tied edge inherits the hypothesis's ``evidence_refs``;
   * otherwise the union of the two endpoint NODES' ``source_refs``
     (the observations that put those nodes in the graph at all) —
     bounded, deduplicated, generic sentinels excluded.
3. **Accounting** — the unbacked count lands in ``coverage_gaps`` as
   ``attack_graph_unbacked_edges:<N>`` (never silently dropped; pass
   ``drop_unbacked=True`` to prune instead).

The pass is pure (dict-in/dict-out), fail-soft (any error returns the
input unchanged), and never invents evidence: an edge nothing supports
is labelled ``unbacked``, not decorated.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Mapping

logger = logging.getLogger(__name__)

_MAX_BACKFILL_REFS = 8
_GENERIC_NODE_REFS = frozenset(
    {
        "relational_evidence",
        "mental_model",
        "target_knowledge",
        "unknown",
        "",
    }
)

_STATUS_BACKED = "backed"
_STATUS_ENRICHED = "enriched"
_STATUS_UNBACKED = "unbacked"


def _model_get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _finding_evidence_pool(findings: Iterable[Any]) -> dict[str, list[str]]:
    pool: dict[str, list[str]] = {}
    for finding in findings:
        finding_id = _model_get(finding, "id")
        if not finding_id:
            continue
        refs = [f"finding:{finding_id}"]
        evidence_hash = _model_get(finding, "evidence_hash")
        if evidence_hash:
            refs.append(f"evidence_hash:{str(evidence_hash)[:64]}")
        pool[str(finding_id)] = refs
    return pool


def _hypothesis_evidence_pool(hypotheses: Iterable[Any]) -> dict[str, list[str]]:
    pool: dict[str, list[str]] = {}
    for hypothesis in hypotheses:
        hypothesis_id = _model_get(hypothesis, "id")
        if not hypothesis_id:
            continue
        refs = [
            str(ref)[:240]
            for ref in (_model_get(hypothesis, "evidence_refs") or [])
            if str(ref).strip()
        ][:_MAX_BACKFILL_REFS]
        pool[str(hypothesis_id)] = refs
    return pool


def _node_backfill(graph: Mapping[str, Any], node_id: str) -> list[str]:
    node = (graph.get("nodes") or {}).get(node_id)
    if not isinstance(node, Mapping):
        return []
    refs = [
        str(ref)[:240]
        for ref in (node.get("source_refs") or [])
        if str(ref).strip() and str(ref).strip().lower() not in _GENERIC_NODE_REFS
    ]
    return refs[:_MAX_BACKFILL_REFS]


def _entity_backfill(
    node_id: str,
    *,
    finding_pool: Mapping[str, list[str]],
    hypothesis_pool: Mapping[str, list[str]],
) -> list[str]:
    if node_id.startswith("finding:"):
        return list(finding_pool.get(node_id[len("finding:"):], []))
    if node_id.startswith("hypothesis:"):
        return list(hypothesis_pool.get(node_id[len("hypothesis:"):], []))
    return []


def enrich_attack_graph_edges(
    graph: dict[str, Any],
    *,
    findings: Iterable[Any] = (),
    hypotheses: Iterable[Any] = (),
    drop_unbacked: bool = False,
) -> dict[str, Any]:
    """Mark, backfill and account evidence on every attack-graph edge.

    Pure post-pass over ``build_attack_graph``'s dumped dict. Returns
    the (possibly same-object) graph dict; on any internal error the
    input is returned unchanged (fail-soft — the projection stays
    available even when enrichment cannot run).
    """
    try:
        edges = graph.get("edges")
        if not isinstance(edges, list) or not edges:
            return graph
        finding_pool = _finding_evidence_pool(findings)
        hypothesis_pool = _hypothesis_evidence_pool(hypotheses)

        kept_edges: list[Any] = []
        backed = enriched = unbacked = 0
        for edge in edges:
            if not isinstance(edge, Mapping):
                kept_edges.append(edge)
                continue
            metadata = dict(edge.get("metadata") or {})
            existing = [
                str(ref)[:240] for ref in (edge.get("evidence_refs") or []) if str(ref).strip()
            ]
            if existing:
                backed += 1
                metadata["evidence_status"] = _STATUS_BACKED
                kept_edges.append(_with_edge(edge, metadata=metadata))
                continue

            backfill: list[str] = []
            for node_id in (edge.get("source_id"), edge.get("target_id")):
                backfill.extend(
                    ref
                    for ref in _entity_backfill(
                        str(node_id),
                        finding_pool=finding_pool,
                        hypothesis_pool=hypothesis_pool,
                    )
                    if ref not in backfill
                )
            if not backfill:
                for node_id in (edge.get("source_id"), edge.get("target_id")):
                    backfill.extend(
                        ref
                        for ref in _node_backfill(graph, str(node_id))
                        if ref not in backfill
                    )
                    if len(backfill) >= _MAX_BACKFILL_REFS:
                        break
            backfill = backfill[:_MAX_BACKFILL_REFS]

            if backfill:
                enriched += 1
                metadata["evidence_status"] = _STATUS_ENRICHED
                metadata["evidence_backfilled"] = True
                kept_edges.append(
                    _with_edge(edge, evidence_refs=backfill, metadata=metadata)
                )
            else:
                unbacked += 1
                metadata["evidence_status"] = _STATUS_UNBACKED
                if drop_unbacked:
                    continue
                kept_edges.append(_with_edge(edge, metadata=metadata))

        graph["edges"] = kept_edges
        gaps = list(graph.get("coverage_gaps") or [])
        marker = f"attack_graph_unbacked_edges:{unbacked}"
        if unbacked and marker not in gaps:
            gaps.append(marker)
        graph["coverage_gaps"] = gaps
        graph["evidence_edge_summary"] = {
            "edges_total": backed + enriched + unbacked,
            "edges_backed": backed,
            "edges_enriched": enriched,
            "edges_unbacked": unbacked,
            "dropped_unbacked": bool(drop_unbacked) and unbacked > 0,
        }
        return graph
    except Exception as exc:  # noqa: BLE001 — fail-soft by contract
        logger.debug("attack-graph evidence enrichment skipped: %s", type(exc).__name__)
        return graph


def _with_edge(
    edge: Mapping[str, Any],
    *,
    evidence_refs: list[str] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    updated = dict(edge)
    if evidence_refs is not None:
        updated["evidence_refs"] = evidence_refs
    if metadata is not None:
        updated["metadata"] = dict(metadata)
    return updated


def every_edge_evidence_backed(graph: Mapping[str, Any]) -> bool:
    """The acceptance predicate: no edge carries evidence_status=unbacked."""
    edges = graph.get("edges") or []
    return all(
        isinstance(edge, Mapping)
        and (edge.get("evidence_refs") or [])
        and (edge.get("metadata") or {}).get("evidence_status") != _STATUS_UNBACKED
        for edge in edges
    )


__all__ = [
    "enrich_attack_graph_edges",
    "every_edge_evidence_backed",
]
