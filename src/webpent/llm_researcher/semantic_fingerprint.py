"""
Semantic experiment identity for research value tracking.

Captures research-relevant dimensions that distinguish whether an
experiment is likely to produce new information versus repeating
evidence already obtained.

Key principle:
- Same URL + different actor/query/branch = DIFFERENT semantic experiment
- Same URL + same actor + same query + same branch = SAME semantic experiment

The semantic fingerprint is MORE specific than CandidateAction.fingerprint()
which is intentionally coarse for deduplication safety. This fingerprint
is used for VALUE ADJUSTMENT, not for blocking.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any

from webpent.models.research import CandidateAction


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _normalize_path(path: str) -> str:
    """Strip scheme/host, keep path portion only."""
    if not path:
        return ""
    if "://" in path:
        parts = path.split("://", 1)[1].split("/", 1)
        if len(parts) > 1:
            return "/" + parts[1]
        return "/"
    if not path.startswith("/"):
        return "/" + path
    return path


def _normalize_query(query: Any) -> dict[str, str]:
    """Normalize query to a flat string-keyed dict."""
    if not query:
        return {}
    if isinstance(query, dict):
        return {str(k): str(v) for k, v in sorted(query.items())}
    return {}


@dataclass(frozen=True)
class SemanticDimensions:
    """Research-relevant dimensions of an experiment."""
    method: str
    path: str  # normalized (no host)
    query: tuple  # sorted tuple of (key, value) pairs
    actor_identity: str  # specific caller identity from metadata
    branch_id: str  # hypothesis branch
    capability: str = "http_read"
    resource_context: str = ""  # e.g., resource type from path

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def semantic_fingerprint(
    *,
    method: str,
    path: str,
    query: dict[str, Any] | None = None,
    actor_identity: str = "",
    branch_id: str = "",
    capability: str = "http_read",
    resource_context: str = "",
) -> str:
    """Compute a semantic experiment fingerprint.

    Captures dimensions that determine whether the experiment is likely
    to produce new information.
    """
    norm_path = _normalize_path(path)
    norm_query = _normalize_query(query)
    query_tuple = tuple(sorted(norm_query.items()))

    dims = SemanticDimensions(
        method=str(method).upper(),
        path=norm_path,
        query=query_tuple,
        actor_identity=str(actor_identity or ""),
        branch_id=str(branch_id or ""),
        capability=str(capability or "http_read"),
        resource_context=str(resource_context or ""),
    )

    payload = {
        "method": dims.method,
        "path": dims.path,
        "query": list(dims.query),
        "actor_identity": dims.actor_identity,
        "branch_id": dims.branch_id,
        "capability": dims.capability,
        "resource_context": dims.resource_context,
    }

    return hashlib.sha256(_canonical_json(payload).encode()).hexdigest()[:32]


def semantic_fingerprint_from_candidate(candidate: CandidateAction) -> str | None:
    """Extract semantic fingerprint from a CandidateAction.

    Uses metadata.request_details for query and caller_identity,
    metadata.branch_id for branch, and target_ref for path.
    Returns None if insufficient metadata is available.
    """
    metadata = candidate.metadata or {}
    request_details = metadata.get("request_details", {}) or {}

    path = request_details.get("path") or candidate.target_ref or ""
    if not path:
        return None

    query = request_details.get("query", {})
    actor_identity = request_details.get("caller_identity", "") or candidate.identity_context
    branch_id = metadata.get("branch_id", "") or candidate.hypothesis_id

    # Derive resource_context from path
    parts = [p for p in _normalize_path(path).strip("/").split("/") if p]
    resource_context = parts[1] if len(parts) >= 2 else ""

    return semantic_fingerprint(
        method=candidate.method,
        path=path,
        query=query,
        actor_identity=actor_identity,
        branch_id=branch_id,
        capability=candidate.capability,
        resource_context=resource_context,
    )
