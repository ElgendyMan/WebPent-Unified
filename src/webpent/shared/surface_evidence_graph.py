"""Passive Surface Evidence Graph construction."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from webpent.models.evidence import redact_sensitive
from webpent.models.surface_graph import (
    SurfaceDispositionEntry,
    SurfaceEdge,
    SurfaceEvidenceGraph,
    SurfaceNode,
)


def _safe_url(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
        query = "&".join(f"{key}=[REDACTED]" for key, _ in parse_qsl(parts.query))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))[:1200]
    except Exception:
        return raw.split("?", 1)[0][:1200]


def _records(data: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    value = data.get(key)
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    if isinstance(value, Mapping):
        return [value]
    return []


def _endpoint(item: Any) -> tuple[str, str]:
    if isinstance(item, str):
        return _safe_url(item), "GET"
    if isinstance(item, Mapping):
        value = next(
            (item.get(key) for key in ("url", "endpoint", "route", "target") if item.get(key)),
            "",
        )
        return _safe_url(value), str(item.get("method") or "GET").upper()[:12]
    return "", "GET"


def _node_id(node_type: str, label: str, method: str) -> str:
    raw = f"{node_type}|{label}|{method}"
    return f"surface:{hashlib.sha256(raw.encode('utf-8', 'ignore')).hexdigest()[:16]}"


def _provenance(item: Any, fallback: str = "passive_observation") -> list[str]:
    """Return bounded, redacted source labels for graph traceability."""
    if not isinstance(item, Mapping):
        return [fallback]
    values: list[str] = []
    for key in ("source", "source_kind", "adapter", "discovery_kind", "identity", "workflow_state"):
        value = str(item.get(key) or "").strip().lower()
        if value and value not in values:
            values.append(value[:80])
    return values[:20] or [fallback]


def _surface_family(item: Any) -> str:
    if not isinstance(item, Mapping):
        return "web_page"
    path = str(item.get("path") or item.get("url") or "").lower()
    content_type = str(item.get("content_type") or "").lower()
    method = str(item.get("method") or "GET").upper()
    if "graphql" in path or "graphql" in content_type:
        return "graphql"
    if any(token in path for token in ("upload", "import", "csv")):
        return "upload_import_csv"
    if any(token in path for token in ("download", "export", "backup")):
        return "download_export_backup"
    if "xml" in content_type or any(token in path for token in ("xml", "xslt")):
        return "xml_parser"
    if "json" in content_type or method != "GET":
        return "api_or_form"
    if any(token in path for token in ("search", "query")):
        return "search"
    if any(token in path for token in ("login", "register", "otp", "auth")):
        return "authentication"
    return "web_page"


def _family_diverse(items: list[Any], limit: int) -> list[Any]:
    buckets: dict[str, list[Any]] = {}
    for item in items:
        family = _surface_family(item)
        buckets.setdefault(family, []).append(item)
    selected: list[Any] = []
    families = sorted(buckets)
    while families and len(selected) < max(0, limit):
        next_families: list[str] = []
        for family in families:
            bucket = buckets[family]
            selected.append(bucket.pop(0))
            if bucket:
                next_families.append(family)
            if len(selected) >= limit:
                break
        families = next_families
    return selected


def build_surface_evidence_graph(
    crawled_data: Mapping[str, Any] | None,
    *,
    target_url: str = "",
) -> SurfaceEvidenceGraph:
    """Build a bounded graph without network access or active validation."""
    data = crawled_data if isinstance(crawled_data, Mapping) else {}
    nodes: dict[str, SurfaceNode] = {}
    edges: dict[str, SurfaceEdge] = {}
    queue: dict[str, SurfaceDispositionEntry] = {}

    def add_node(
        node_type: str,
        label: str,
        method: str = "GET",
        metadata: Mapping[str, Any] | None = None,
        capability: str = "surface-review",
        reason: str = "Passive observation requires the corresponding bounded validator.",
    ) -> SurfaceNode:
        clean, _ = redact_sensitive(label)
        node_id = _node_id(node_type, str(clean), method)
        node = SurfaceNode(
            node_id=node_id,
            node_type=node_type,
            label=str(clean)[:240],
            method=method,
            metadata=dict(metadata or {}),
            evidence_refs=[f"obs:{hashlib.sha256(node_id.encode()).hexdigest()[:16]}"],
            provenance=_provenance(metadata),
            disposition="needs_validator",
        )
        nodes.setdefault(node_id, node)
        queue.setdefault(
            node_id,
            SurfaceDispositionEntry(
                node_id=node_id,
                disposition="needs_validator",
                required_capability=capability,
                reason=reason,
                provenance=_provenance(metadata),
            ),
        )
        return nodes[node_id]

    def add_edge(source: SurfaceNode, target: SurfaceNode, relation: str) -> None:
        raw = f"{source.node_id}|{target.node_id}|{relation}"
        edge_id = f"edge:{hashlib.sha256(raw.encode()).hexdigest()[:16]}"
        edges.setdefault(
            edge_id,
            SurfaceEdge(
                edge_id=edge_id,
                source_id=source.node_id,
                target_id=target.node_id,
                relation=relation,
                evidence_refs=source.evidence_refs[:1] + target.evidence_refs[:1],
                provenance=list(dict.fromkeys(source.provenance + target.provenance))[:20],
            ),
        )

    endpoint_nodes: list[SurfaceNode] = []
    raw_endpoints = list(data.get("endpoints") or [])
    raw_endpoints.extend(item for item in _records(data, "surface_records"))
    raw_endpoints.extend(item for item in _records(data, "autopentestx_surface_records"))
    raw_endpoints.extend(item for item in _records(data, "nettacker_surface_records"))
    family_counts: dict[str, int] = {}
    for item in _family_diverse(raw_endpoints, 250):
        label, method = _endpoint(item)
        if label:
            family = _surface_family(item)
            family_counts[family] = family_counts.get(family, 0) + 1
            metadata = {"target": target_url, "family": family}
            if isinstance(item, Mapping):
                metadata.update(dict(item))
            endpoint_nodes.append(
                add_node(
                    "endpoint",
                    label,
                    method,
                    metadata,
                    capability=f"{family}-validator",
                    reason=(
                        "Observed surface requires a family-specific validator and "
                        "safe workflow preconditions."
                    ),
                )
            )

    for key, node_type, capability in (
        ("xhr_requests", "xhr", "xhr-validator"),
        ("browser_requests", "browser_context", "browser-context-validator"),
        ("openapi_routes", "openapi_route", "api-schema-validator"),
        ("graphql_operations", "graphql_operation", "graphql-validator"),
        ("multipart_fields", "multipart_field", "multipart-validator"),
        ("service_fingerprints", "service_fingerprint", "service-validator"),
        ("autopentestx_service_fingerprints", "service_fingerprint", "autopentestx_observation"),
        ("nettacker_service_fingerprints", "service_fingerprint", "nettacker_observation"),
        ("workflow_observations", "workflow_ref", "workflow-validator"),
    ):
        for item in _records(data, key)[:60]:
            label = item.get("url") or item.get("route") or item.get("name") or item.get("service")
            if label:
                node = add_node(
                    node_type,
                    _safe_url(label) or str(label),
                    metadata=item,
                    capability=capability,
                )
                for endpoint_node in endpoint_nodes:
                    if str(label) in endpoint_node.label or node_type in {"xhr", "workflow_ref"}:
                        add_edge(node, endpoint_node, "describes")

    coverage_gaps = [str(item) for item in data.get("coverage_gaps") or []]
    coverage_gaps.extend(str(item) for item in data.get("surface_coverage_gaps") or [])
    coverage_blockers = [
        dict(item)
        for item in data.get("coverage_blockers") or []
        if isinstance(item, Mapping)
    ]
    return SurfaceEvidenceGraph(
        nodes=list(nodes.values())[:250],
        edges=list(edges.values())[:500],
        disposition_queue=list(queue.values())[:250],
        coverage_gaps=sorted(set(coverage_gaps)),
        coverage_blockers=coverage_blockers[:100],
        family_counts=family_counts,
    )


__all__ = ["build_surface_evidence_graph"]
