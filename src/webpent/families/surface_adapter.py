"""Surface-graph adapter — normalizes the project's real recon models into the
inventory shape consumed by the family analyzers.

Duck-typed: accepts any object with ``.nodes`` where each node has
``.method``, ``.label``, ``.metadata`` (e.g. SurfaceEvidenceGraph /
SurfaceNode). No hard import dependency on the optional layer.

Also improves capability detection beyond path keywords: uses method
(mutating), metadata flags (auth_required, stateful, rate_limited,
idempotent), and observed parameters — fixing the weak-keyword critique.
"""
from __future__ import annotations

from typing import Any


def _node_path(node: Any) -> str:
    label = str(getattr(node, "label", ""))
    # label often contains "METHOD /path" or just the path; extract last token.
    parts = label.split()
    return parts[-1] if parts else label


def _node_method(node: Any) -> str:
    m = getattr(node, "method", None)
    if m:
        return str(m).upper()
    label = str(getattr(node, "label", ""))
    parts = label.split()
    if parts and parts[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
        return parts[0].upper()
    return "GET"


def _node_metadata(node: Any) -> dict[str, Any]:
    md = getattr(node, "metadata", {}) or {}
    return dict(md) if isinstance(md, dict) else {}


def surface_graph_to_inventory(surface_graph: Any) -> list[dict[str, Any]]:
    """Convert a SurfaceEvidenceGraph-like object to the endpoint_inventory
    list consumed by all family analyzers."""
    inventory: list[dict[str, Any]] = []
    nodes = getattr(surface_graph, "nodes", None) or []
    for node in nodes:
        method = _node_method(node)
        path = _node_path(node)
        md = _node_metadata(node)
        params = list(md.get("params", []) or md.get("parameters", []) or [])
        headers = dict(md.get("headers", {}) or {})
        entry: dict[str, Any] = {
            "method": method,
            "path": path,
            "params": params,
            "headers": headers,
            "auth_required": bool(md.get("auth_required") or md.get("authenticated")),
            "stateful": bool(md.get("stateful") or md.get("mutates_state")),
            "rate_limited": bool(md.get("rate_limited")),
            "idempotent": bool(md.get("idempotent") or "Idempotency-Key" in headers),
            "object_reference": bool(md.get("object_reference") or md.get("resource_id")),
            "hostname_routed": bool(md.get("hostname_routed") or md.get("tenant_subdomain")),
            "roles": list(md.get("roles", []) or []),
        }
        inventory.append(entry)
    return inventory


def detect_capabilities(inventory: list[dict[str, Any]]) -> set[str]:
    """Improved capability detection: method + metadata + params, not just
    path keywords. Returns the observed-capability set fed to analyzers."""
    observed: set[str] = set()
    for ep in inventory:
        method = str(ep.get("method", "")).upper()
        path = str(ep.get("path", ""))
        params = set(str(p).lower() for p in ep.get("params", []))
        headers = {str(k).lower() for k in ep.get("headers", {})}
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            observed.add("mutating_endpoint")
        if ep.get("stateful") or any(k in path for k in ("balance", "transfer", "withdraw", "order", "checkout", "pay", "purchase")):
            observed.add("stateful_balance")
        if ep.get("rate_limited"):
            observed.add("rate_limited_endpoint")
        if ep.get("idempotent"):
            observed.add("idempotent_contract")
        if ep.get("object_reference"):
            observed.add("object_reference_in_url_or_body")
        if any(h in headers for h in ("x-tenant-id", "x-workspace-id", "x-organization-id")) or any(p in params for p in ("tenant", "tenant_id", "workspace", "org")):
            observed.add("tenant_context_header_or_param")
        if ep.get("hostname_routed"):
            observed.add("hostname_based_routing")
        if any(k in path for k in ("/search", "/feed", "/export", "/logs", "/webhook", "/global")):
            observed.add("shared_or_global_endpoint")
        if "tenant_admin" in ep.get("roles", []):
            observed.add("tenant_admin_role")
        if any(k in path for k in ("/admin", "/platform", "/tenants", "/users")):
            observed.add("platform_admin_endpoints")
        if any(k in path for k in ("/oauth", "/authorize", "/oidc", "/auth")):
            observed.add("oauth_authorize_endpoint")
        if "redirect_uri" in params:
            observed.add("redirect_uri_param")
        if "response_type" in params:
            observed.add("response_type_param")
        if "scope" in params:
            observed.add("scope_param")
        if any(k in path for k in ("/token", "/access_token")):
            observed.add("oauth_token_endpoint")
            observed.add("authorization_code_flow")
    return observed


__all__ = ["detect_capabilities", "surface_graph_to_inventory"]
