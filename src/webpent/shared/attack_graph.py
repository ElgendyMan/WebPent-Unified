"""Deterministic Attack Graph projection helpers.

This module is deliberately passive: it consumes observations already present
in state and never performs network requests, creates Findings, or authorizes
an exploit.  It is safe to run in offline mode and is designed to tolerate
checkpoint-restored dictionaries.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from webpent.models.attack_graph import (
    AttackGraph,
    AttackGraphEdge,
    AttackGraphNode,
    AttackGraphNodeKind,
)
from webpent.models.evidence import redact_sensitive
from webpent.models.findings import Confidence
from webpent.models.mental_model import (
    MentalModel,
    MentalModelNode,
    _coerce_to_mental_model,
)
from webpent.state.reducers import model_get

_SECRET_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
}


def _stable_ref(value: Any, *, prefix: str) -> str:
    """Return a deterministic non-reversible reference for a sensitive label."""

    digest = hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:20]
    return f"{prefix}:{digest}"


def _safe_url(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", ""))


def _endpoint_identity(value: Any) -> str | None:
    """Return Mental Model-compatible endpoint identity for ID resolution only."""

    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    path = (parsed.path or "/").rstrip("/") or "/"
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def _mental_node_id(prefix: str, identity_key: str) -> str:
    """Mirror Mental Model's deterministic ``<prefix>-<hash>`` IDs."""

    return f"{prefix}-{hashlib.sha256(identity_key.encode('utf-8')).hexdigest()[:16]}"


def _credential_node_id(prefix: str, raw_value: Any) -> str:
    identity_key = f"sha256:{hashlib.sha256(str(raw_value).encode('utf-8', 'replace')).hexdigest()}"
    return _mental_node_id(prefix, identity_key)


def _safe_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    safe: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key).strip().lower()
        if (
            not key
            or key in _SECRET_KEYS
            or any(marker in key for marker in ("token", "secret", "password"))
        ):
            continue
        if isinstance(raw_value, str):
            if _safe_url(raw_value):
                safe[key] = _safe_url(raw_value)
            else:
                safe[key] = raw_value[:200]
        elif isinstance(raw_value, (bool, int, float)) or raw_value is None:
            safe[key] = raw_value
        elif isinstance(raw_value, list):
            safe[key] = [str(item)[:120] for item in raw_value[:20]]
    return safe


_KNOWLEDGE_GAP_KEYS = (
    "gap_id",
    "kind",
    "status",
    "objective",
    "unknown",
    "target_ref",
    "affected_actor",
    "affected_object",
    "affected_tenant",
    "supporting_evidence",
    "contradicting_evidence",
    "expected_information_gain",
    "cost",
    "risk",
    "priority",
    "dependencies",
    "stopping_condition",
    "invalidation_condition",
)
_RUNTIME_GAP_KEYS = ("code", "component", "required_for", "recovery_action")


def _safe_gap_value(key: str, value: Any) -> Any:
    if key in {"supporting_evidence", "contradicting_evidence", "dependencies"}:
        if not isinstance(value, (list, tuple)):
            return []
        result: list[str] = []
        for item in value[:20]:
            clean, _ = redact_sensitive(str(item))
            if clean.strip():
                result.append(" ".join(clean.split())[:240])
        return result
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    clean, _ = redact_sensitive(str(value or ""))
    return " ".join(clean.split())[:320]


def _safe_gap(row: Any, *, keys: tuple[str, ...]) -> dict[str, Any] | None:
    if not isinstance(row, Mapping):
        return None
    safe = {
        key: _safe_gap_value(key, row[key])
        for key in keys
        if key in row and row[key] is not None
    }
    return safe or None


def _safe_gap_list(rows: Iterable[Any], *, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        safe = _safe_gap(row, keys=keys)
        if not safe:
            continue
        identity = str(safe.get("gap_id") or safe.get("code") or repr(sorted(safe.items())))
        if identity in seen:
            continue
        seen.add(identity)
        result.append(safe)
        if len(result) >= 100:
            break
    return result


def _node_from_mental_model(node_id: str, node: MentalModelNode) -> AttackGraphNode:
    kind = str(node.kind)
    try:
        graph_kind = AttackGraphNodeKind(kind)
    except ValueError:
        graph_kind = AttackGraphNodeKind.OBJECT
    metadata = _safe_metadata(node.metadata)
    label = {
        AttackGraphNodeKind.IDENTITY.value: "identity",
        AttackGraphNodeKind.OBJECT.value: "object",
        AttackGraphNodeKind.WORKFLOW.value: "workflow",
        AttackGraphNodeKind.ENDPOINT.value: "endpoint",
    }.get(kind, kind)
    return AttackGraphNode(
        id=node_id,
        kind=graph_kind,
        label=f"{label}:{node_id[-12:]}",
        status="observed",
        criticality=str(node.criticality),
        source_refs=[str(node.discovery_source)],
        metadata=metadata,
    )


def _add_edge(
    graph: AttackGraph,
    *,
    kind: str,
    source_id: str,
    target_id: str,
    evidence_refs: Iterable[Any] = (),
    confidence: str = "observed",
    metadata: Mapping[str, Any] | None = None,
) -> None:
    if source_id == target_id or source_id not in graph.nodes or target_id not in graph.nodes:
        return
    refs = [str(ref)[:240] for ref in evidence_refs if ref][:50]
    edge_id = _stable_ref(f"{kind}|{source_id}|{target_id}|{'|'.join(refs)}", prefix="edge")
    if any(edge.id == edge_id for edge in graph.edges):
        return
    graph.edges.append(
        AttackGraphEdge(
            id=edge_id,
            kind=kind,
            source_id=source_id,
            target_id=target_id,
            confidence=confidence,
            evidence_refs=refs,
            metadata=_safe_metadata(metadata or {}),
        )
    )


def _coerce_graph_node_id(value: Any, *, kind: str, graph: AttackGraph) -> str | None:
    if value is None:
        return None
    candidate = str(value)
    if candidate in graph.nodes:
        return candidate
    prefix = {
        "identity": "identity",
        "object": "object",
        "workflow": "workflow",
        "endpoint": "endpoint",
    }.get(kind)
    if prefix is None:
        return None
    generated = _credential_node_id(prefix, candidate)
    if generated not in graph.nodes:
        graph.nodes[generated] = AttackGraphNode(
            id=generated,
            kind=(
                AttackGraphNodeKind.IDENTITY
                if prefix == "identity"
                else AttackGraphNodeKind.OBJECT
            ),
            label=f"{prefix}:{generated[-12:]}",
            source_refs=["relational_evidence"],
            metadata={"redacted": True},
        )
    return generated


def _add_relational_edges(graph: AttackGraph, relational_evidence: Iterable[Any]) -> None:
    for row in relational_evidence:
        if not isinstance(row, Mapping):
            continue
        resource_url = _safe_url(row.get("resource_url"))
        resource_id = None
        if resource_url:
            resource_id = _mental_node_id("endpoint", resource_url)
            if resource_id not in graph.nodes:
                graph.nodes[resource_id] = AttackGraphNode(
                    id=resource_id,
                    kind=AttackGraphNodeKind.ENDPOINT,
                    label=f"endpoint:{resource_id[-12:]}",
                    source_refs=["relational_evidence"],
                    metadata={"url": resource_url},
                )
        object_id = row.get("object_id")
        if resource_id is None and object_id:
            resource_id = _credential_node_id("object", object_id)
            if resource_id not in graph.nodes:
                graph.nodes[resource_id] = AttackGraphNode(
                    id=resource_id,
                    kind=AttackGraphNodeKind.OBJECT,
                    label=f"object:{resource_id[-12:]}",
                    source_refs=["relational_evidence"],
                )
        if resource_id is None:
            continue
        from_id = _coerce_graph_node_id(row.get("from_identity"), kind="identity", graph=graph)
        to_id = _coerce_graph_node_id(row.get("to_identity"), kind="identity", graph=graph)
        owner_id = _coerce_graph_node_id(row.get("owner_identity"), kind="identity", graph=graph)
        refs = row.get("evidence_refs") or []
        differential = bool(row.get("differential"))
        confidence = "relational_differential" if differential else "relational_observed"
        if from_id:
            _add_edge(
                graph,
                kind="identity_resource_access",
                source_id=from_id,
                target_id=resource_id,
                evidence_refs=refs,
                confidence=confidence,
                metadata={"accessible": bool(row.get("from_accessible"))},
            )
        if to_id:
            _add_edge(
                graph,
                kind="identity_resource_access",
                source_id=to_id,
                target_id=resource_id,
                evidence_refs=refs,
                confidence=confidence,
                metadata={"accessible": bool(row.get("to_accessible"))},
            )
        if owner_id:
            _add_edge(
                graph,
                kind="ownership",
                source_id=owner_id,
                target_id=resource_id,
                evidence_refs=refs,
                confidence="owner_declared",
            )


def _add_finding_nodes(graph: AttackGraph, findings: Iterable[Any]) -> None:
    for finding in findings:
        finding_id = model_get(finding, "id")
        if finding_id is None:
            continue
        node_id = f"finding:{finding_id}"
        if node_id in graph.nodes:
            continue
        confidence = str(model_get(finding, "confidence", Confidence.TENTATIVE.value))
        graph.nodes[node_id] = AttackGraphNode(
            id=node_id,
            kind=AttackGraphNodeKind.FINDING,
            label="finding",
            status=confidence,
            criticality=str(model_get(finding, "severity", "info")),
            source_refs=[str(model_get(finding, "tool_name", "unknown"))],
            metadata={"vuln_class": str(model_get(finding, "vuln_class", "unknown"))},
        )
        endpoint_identity = _endpoint_identity(model_get(finding, "url"))
        if endpoint_identity:
            endpoint_id = _mental_node_id("endpoint", endpoint_identity)
            if endpoint_id in graph.nodes:
                _add_edge(
                    graph,
                    kind="finding_affects",
                    source_id=node_id,
                    target_id=endpoint_id,
                    evidence_refs=[f"finding:{finding_id}"],
                    confidence=confidence,
                )


def _add_novel_behavior_nodes(graph: AttackGraph, novel_behaviors: Iterable[Any]) -> dict[str, str]:
    """Project novel behavior observations into hypothesis-only nodes."""
    ids: dict[str, str] = {}
    for behavior in novel_behaviors:
        if not isinstance(behavior, Mapping):
            continue
        observation_id = str(behavior.get("observation_id") or "").strip()
        if not observation_id:
            continue
        node_id = _stable_ref(observation_id, prefix="novel")
        ids[observation_id] = node_id
        graph.nodes.setdefault(
            node_id,
            AttackGraphNode(
                id=node_id,
                kind=AttackGraphNodeKind.HYPOTHESIS,
                label="novel_behavior",
                status="causal_candidate" if behavior.get("causal_signal") else "candidate",
                criticality="medium",
                source_refs=[observation_id[:160]],
                metadata={
                    "behavior_kind": str(behavior.get("behavior_kind") or "unknown"),
                    "changed_dimensions": [
                        str(item)[:80]
                        for item in (behavior.get("changed_dimensions") or [])[:20]
                    ],
                    "causal_signal": bool(behavior.get("causal_signal")),
                    "negative_control_complete": bool(
                        behavior.get("negative_control_complete")
                    ),
                },
            ),
        )
        target_ref = _safe_url((behavior.get("metadata") or {}).get("target_ref"))
        if target_ref:
            endpoint_id = _mental_node_id("endpoint", _endpoint_identity(target_ref) or target_ref)
            if endpoint_id in graph.nodes:
                _add_edge(
                    graph,
                    kind="novel_behavior_targets",
                    source_id=node_id,
                    target_id=endpoint_id,
                    evidence_refs=[observation_id],
                    confidence="causal_candidate" if behavior.get("causal_signal") else "observed",
                )
    return ids


_ALLOWED_CAUSAL_EDGE_KINDS = {
    "causal_precondition",
    "causal_transition",
    "causal_signal",
    "negative_control",
    "observation_supports_hypothesis",
    "confirmed_finding_leads_to_next_action",
}


def _add_causal_edges(graph: AttackGraph, causal_edges: Iterable[Any]) -> None:
    """Add only typed, existing-node causal relationships."""
    for row in causal_edges:
        if not isinstance(row, Mapping):
            continue
        kind = str(row.get("kind") or "").strip()
        if kind not in _ALLOWED_CAUSAL_EDGE_KINDS:
            continue
        if kind in {"causal_signal", "confirmed_finding_leads_to_next_action"} and not (
            bool(row.get("causal_signal")) and bool(row.get("negative_control_complete"))
        ):
            continue
        source_id = str(row.get("source_id") or "")
        target_id = str(row.get("target_id") or "")
        if source_id not in graph.nodes or target_id not in graph.nodes:
            continue
        _add_edge(
            graph,
            kind=kind,
            source_id=source_id,
            target_id=target_id,
            evidence_refs=row.get("evidence_refs") or (),
            confidence=str(row.get("confidence") or "observed"),
            metadata={
                "negative_control_complete": bool(row.get("negative_control_complete")),
                "control_complete": bool(row.get("control_complete")),
                "target_backed": bool(row.get("target_backed")),
                "proof_bundle_sealed": bool(row.get("proof_bundle_sealed")),
            },
        )


def _add_hypothesis_nodes(graph: AttackGraph, hypotheses: Iterable[Any]) -> None:
    for hypothesis in hypotheses:
        hypothesis_id = model_get(hypothesis, "id")
        if hypothesis_id is None:
            continue
        node_id = f"hypothesis:{hypothesis_id}"
        if node_id in graph.nodes:
            continue
        graph.nodes[node_id] = AttackGraphNode(
            id=node_id,
            kind=AttackGraphNodeKind.HYPOTHESIS,
            label="hypothesis",
            status=str(model_get(hypothesis, "status", "unexplored")),
            criticality=str(model_get(hypothesis, "priority", "medium")),
            source_refs=[str(model_get(hypothesis, "origin", "unknown"))],
            metadata={"title": str(model_get(hypothesis, "title", ""))[:160]},
        )
        endpoint_identity = _endpoint_identity(model_get(hypothesis, "url"))
        if endpoint_identity:
            endpoint_id = _mental_node_id("endpoint", endpoint_identity)
            if endpoint_id in graph.nodes:
                _add_edge(
                    graph,
                    kind="hypothesis_targets",
                    source_id=node_id,
                    target_id=endpoint_id,
                    evidence_refs=[f"hypothesis:{hypothesis_id}"],
                    confidence="hypothesis",
                )


def _add_target_knowledge_nodes(
    graph: AttackGraph, target_knowledge: Any
) -> None:
    """Project typed target knowledge into graph nodes and evidence-backed edges."""
    if not isinstance(target_knowledge, Mapping):
        return
    engagement_id = str(target_knowledge.get("engagement_id") or "unscoped").strip()
    if not engagement_id:
        engagement_id = "unscoped"
    prefix = f"knowledge:{_stable_ref(engagement_id, prefix='engagement')}"
    raw_nodes = target_knowledge.get("nodes")
    if not isinstance(raw_nodes, Mapping):
        raw_nodes = {}
    kind_map = {
        "identity": AttackGraphNodeKind.IDENTITY,
        "role": AttackGraphNodeKind.IDENTITY,
        "endpoint": AttackGraphNodeKind.ENDPOINT,
        "workflow": AttackGraphNodeKind.WORKFLOW,
        "object": AttackGraphNodeKind.RESOURCE,
        "data_store": AttackGraphNodeKind.RESOURCE,
        "host": AttackGraphNodeKind.OBJECT,
        "service": AttackGraphNodeKind.OBJECT,
        "technology": AttackGraphNodeKind.OBJECT,
    }
    node_ids: dict[str, str] = {}
    for raw_id, raw_node in raw_nodes.items():
        if not isinstance(raw_node, Mapping):
            continue
        source_id = str(raw_id).strip()
        if not source_id:
            continue
        node_id = f"{prefix}:{source_id}"[:200]
        node_ids[source_id] = node_id
        raw_kind = str(raw_node.get("kind") or "object")
        graph_kind = kind_map.get(raw_kind, AttackGraphNodeKind.OBJECT)
        evidence_refs = [str(ref)[:240] for ref in raw_node.get("evidence_refs", []) if ref]
        metadata = _safe_metadata(raw_node.get("metadata"))
        metadata.update({"knowledge_kind": raw_kind, "engagement_ref": prefix})
        graph.nodes.setdefault(
            node_id,
            AttackGraphNode(
                id=node_id,
                kind=graph_kind,
                label=f"{raw_kind}:{node_id[-12:]}",
                status="observed",
                criticality="medium",
                source_refs=evidence_refs[:50] or ["target_knowledge"],
                metadata=metadata,
            ),
        )

    for raw_edge in target_knowledge.get("edges", []):
        if not isinstance(raw_edge, Mapping):
            continue
        source_id = node_ids.get(str(raw_edge.get("source_id") or ""))
        target_id = node_ids.get(str(raw_edge.get("target_id") or ""))
        if not source_id or not target_id:
            continue
        _add_edge(
            graph,
            kind=f"knowledge_{str(raw_edge.get('relation') or 'related_to')}",
            source_id=source_id,
            target_id=target_id,
            evidence_refs=raw_edge.get("evidence_refs") or (),
            confidence=str(raw_edge.get("confidence") or "observed"),
            metadata={"engagement_ref": prefix},
        )

    for raw_profile in target_knowledge.get("authorization_profiles", {}).values():
        if not isinstance(raw_profile, Mapping):
            continue
        identity = str(raw_profile.get("identity_id") or "").strip()
        if not identity:
            continue
        identity_id = node_ids.get(identity)
        if identity_id is None:
            identity_id = f"{prefix}:identity:{_stable_ref(identity, prefix='id')}"[:200]
            node_ids[identity] = identity_id
            graph.nodes.setdefault(
                identity_id,
                AttackGraphNode(
                    id=identity_id,
                    kind=AttackGraphNodeKind.IDENTITY,
                    label=f"identity:{identity_id[-12:]}",
                    status=str(raw_profile.get("authorization_status") or "unknown"),
                    source_refs=[
                        str(ref)[:240] for ref in raw_profile.get("evidence_refs", []) if ref
                    ]
                    or ["target_knowledge"],
                    metadata={"engagement_ref": prefix},
                ),
            )
        for capability in raw_profile.get("observed_capabilities", []):
            permission_id = f"{prefix}:permission:{_stable_ref(capability, prefix='perm')}"[:200]
            graph.nodes.setdefault(
                permission_id,
                AttackGraphNode(
                    id=permission_id,
                    kind=AttackGraphNodeKind.PERMISSION,
                    label="permission",
                    status="observed",
                    source_refs=[
                        str(ref)[:240] for ref in raw_profile.get("evidence_refs", []) if ref
                    ]
                    or ["target_knowledge"],
                    metadata={"engagement_ref": prefix},
                ),
            )
            _add_edge(
                graph,
                kind="identity_has_permission",
                source_id=identity_id,
                target_id=permission_id,
                evidence_refs=raw_profile.get("evidence_refs") or (),
                confidence="observed",
                metadata={"capability_observed": True, "engagement_ref": prefix},
            )

    for raw_flow in target_knowledge.get("data_flows", []):
        if not isinstance(raw_flow, Mapping):
            continue
        source_id = node_ids.get(str(raw_flow.get("source_id") or ""))
        target_id = node_ids.get(str(raw_flow.get("destination_id") or ""))
        if not source_id or not target_id or not raw_flow.get("observed"):
            continue
        _add_edge(
            graph,
            kind="observed_data_flow",
            source_id=source_id,
            target_id=target_id,
            evidence_refs=raw_flow.get("evidence_refs") or (),
            confidence="observed",
            metadata={"channel": str(raw_flow.get("channel") or "")[:80]},
        )


def build_attack_graph(
    mental_model_state: Any = None,
    *,
    relational_evidence: Iterable[Any] = (),
    findings: Iterable[Any] = (),
    hypotheses: Iterable[Any] = (),
    novel_behaviors: Iterable[Any] = (),
    causal_edges: Iterable[Any] = (),
    coverage_gaps: Iterable[Any] = (),
    knowledge_gaps: Iterable[Any] = (),
    runtime_capability_gaps: Iterable[Any] = (),
    target_knowledge: Any = None,
) -> dict[str, Any]:
    """Project current state into a deterministic, redacted Attack Graph."""

    model: MentalModel = _coerce_to_mental_model(mental_model_state)
    graph = AttackGraph(generated_from=["mental_model", "relational_evidence"])
    for node_id, node in model.nodes.items():
        graph.nodes[node_id] = _node_from_mental_model(node_id, node)

    for edge in model.edges:
        _add_edge(
            graph,
            kind=str(edge.kind),
            source_id=str(edge.source_id),
            target_id=str(edge.target_id),
            evidence_refs=[edge.source_ref],
            confidence="mental_model_observed",
        )

    _add_relational_edges(graph, relational_evidence)
    if isinstance(target_knowledge, Mapping):
        graph.generated_from.append("target_knowledge")
        _add_target_knowledge_nodes(graph, target_knowledge)
    _add_finding_nodes(graph, findings)
    _add_hypothesis_nodes(graph, hypotheses)
    _add_novel_behavior_nodes(graph, novel_behaviors)
    _add_causal_edges(graph, causal_edges)
    graph.coverage_gaps.extend(
        str(item)[:240]
        for item in coverage_gaps
        if isinstance(item, str) and item.strip()
    )
    graph.knowledge_gaps.extend(
        _safe_gap_list(knowledge_gaps, keys=_KNOWLEDGE_GAP_KEYS)
    )
    graph.runtime_capability_gaps.extend(
        _safe_gap_list(runtime_capability_gaps, keys=_RUNTIME_GAP_KEYS)
    )

    if not graph.nodes:
        graph.coverage_gaps.append("No typed target nodes were available for graph projection.")
    if not graph.edges:
        graph.coverage_gaps.append(
            "No evidence-backed relationships were available for graph projection."
        )
    return graph.model_dump(mode="json")


__all__ = ["build_attack_graph"]
