"""UM-DR-46 Phase A — the SKG discriminating-questions engine.

Deterministic query API over the Security Knowledge Graph: pure
functions — same model in ⇒ same answer out, no mutation, no I/O, no
LLM. Every answer carries the evidence refs of the facts it rests on
and the weakest provenance along the chain, so a consumer can weigh it
honestly (advisory research prioritization only — never a finding, an
authorization, or a confirmation).

The five mission questions:

* ``get_all_paths_to(resource)``          — every evidence-backed path
  through the graph that reaches a resource (who/what can get there).
* ``ownership_changers()``                — endpoints that can change
  the OWNER of a resource (evidence: MODIFIES attribute=owner).
* ``reads_without_authz_marker()``        — endpoints that read/access
  a resource with NO observed authorization marker.
* ``workflow_skip_candidates(workflow)``  — observed transitions that
  bypass an observed intermediate state (workflow abuse candidates).
* ``ui_vs_api_permission_diff()``         — UI/API surface pairs of
  the same resource path that disagree on authorization markers.
"""

from __future__ import annotations

import re
from typing import Any

from webpent.appmodel.models import (
    ApplicationModel,
    AppModelRelation,
    DiscoveryProvenance,
)

__all__ = [
    "get_all_paths_to",
    "ownership_changers",
    "reads_without_authz_marker",
    "summarize_skg",
    "ui_vs_api_permission_diff",
    "workflow_skip_candidates",
]

_MAX_HOPS = 6
_MAX_PATHS = 64
_MAX_REFS = 16
_API_V_RE = re.compile(r"^v\d+$", re.IGNORECASE)


def _relation_key(relation: AppModelRelation) -> tuple[str, str, str]:
    return (str(relation.kind), relation.target_id, relation.id)


def _refs_union(references: list[list[str]]) -> list[str]:
    merged: list[str] = []
    for refs in references:
        for ref in refs:
            if ref and ref not in merged:
                merged.append(ref)
    return merged[:_MAX_REFS]


def _weakest_provenance(values: list[str]) -> str:
    order = [
        DiscoveryProvenance.CONTRADICTED,
        DiscoveryProvenance.UNKNOWN,
        DiscoveryProvenance.INFERRED,
        DiscoveryProvenance.OBSERVED,
        DiscoveryProvenance.DECLARED,
    ]
    present = set(values)
    for provenance in order:
        if provenance.value in present:
            return provenance.value
    return DiscoveryProvenance.UNKNOWN.value


# ---------------------------------------------------------------------------
# 1. get_all_paths_to
# ---------------------------------------------------------------------------


def get_all_paths_to(
    model: ApplicationModel,
    resource_id: str,
    *,
    max_hops: int = _MAX_HOPS,
    max_paths: int = _MAX_PATHS,
) -> dict[str, Any]:
    """All simple directed paths ending at ``resource_id``.

    Follows relation direction only (source→target); cycles are cut by
    the visited set; a path is recorded the moment it reaches the
    resource and is not extended further. Deterministic ordering:
    (length, node ids). Bounded by max_hops/max_paths.
    """
    adjacency: dict[str, list[AppModelRelation]] = {}
    for relation in model.relations:
        adjacency.setdefault(relation.source_id, []).append(relation)
    for edges in adjacency.values():
        edges.sort(key=_relation_key)

    paths: list[dict[str, Any]] = []
    truncated = False

    def record(chain_nodes: list[str], chain_edges: list[AppModelRelation]) -> None:
        nodes = [model.entities[node_id] for node_id in chain_nodes]
        paths.append({
            "node_ids": list(chain_nodes),
            "node_kinds": [str(node.kind) for node in nodes],
            "node_labels": [str(node.label) for node in nodes],
            "edge_kinds": [str(edge.kind) for edge in chain_edges],
            "evidence_refs": _refs_union(
                [edge.ref_list() for edge in chain_edges]
                + [node.ref_list() for node in nodes]
            ),
            "min_confidence": min(
                [edge.confidence for edge in chain_edges]
                + [node.confidence for node in nodes]
            ),
            "provenance_weakest": _weakest_provenance(
                [str(edge.provenance) for edge in chain_edges]
                + [str(node.provenance) for node in nodes]
            ),
        })

    def dfs(node_id: str, visited: tuple[str, ...], edges: tuple[AppModelRelation, ...]) -> None:
        nonlocal truncated
        if len(paths) >= max_paths:
            truncated = True
            return
        if node_id == resource_id:
            if edges:
                record(list(visited), list(edges))
            return
        if len(edges) >= max_hops:
            return
        for relation in adjacency.get(node_id, ()):
            target = relation.target_id
            if target in visited or target not in model.entities:
                continue
            dfs(target, visited + (target,), edges + (relation,))

    for start in sorted(model.entities):
        if start == resource_id:
            continue
        if len(paths) >= max_paths:
            truncated = True
            break
        dfs(start, (start,), ())
    paths.sort(key=lambda p: (len(p["node_ids"]), p["node_ids"]))
    for index, path in enumerate(paths):
        path["path_id"] = f"skg-path:{index:03d}"
    return {
        "resource_id": resource_id,
        "paths": paths,
        "path_count": len(paths),
        "truncated": truncated,
        "advisory_only": True,
    }


# ---------------------------------------------------------------------------
# 2. ownership_changers
# ---------------------------------------------------------------------------


def ownership_changers(model: ApplicationModel) -> list[dict[str, Any]]:
    """Endpoints that can change the OWNERSHIP of a resource.

    Evidence contract: a MODIFIES relation from an ENDPOINT to a
    RESOURCE whose metadata attribute is "owner" (or carries
    changes_ownership). No evidence ⇒ no entry — ever.
    """
    entries: list[dict[str, Any]] = []
    for relation in model.relations:
        if str(relation.kind) != "modifies":
            continue
        attribute = str(relation.metadata.get("attribute") or "")
        if attribute != "owner" and not relation.metadata.get("changes_ownership"):
            continue
        source = model.entities.get(relation.source_id)
        target = model.entities.get(relation.target_id)
        if source is None or target is None:
            continue
        if str(source.kind) != "endpoint" or str(target.kind) != "resource":
            continue
        entries.append({
            "endpoint_id": relation.source_id,
            "endpoint_label": str(source.label),
            "endpoint_path": str(source.metadata.get("path") or ""),
            "resource_id": relation.target_id,
            "resource_label": str(target.label),
            "attribute": attribute or "ownership",
            "actor": str(relation.metadata.get("actor") or "") or None,
            "evidence_refs": _refs_union(
                [relation.ref_list(), source.ref_list(), target.ref_list()]
            ),
        })
    entries.sort(key=lambda e: (e["endpoint_path"], e["resource_label"]))
    return entries


# ---------------------------------------------------------------------------
# 3. reads_without_authz_marker
# ---------------------------------------------------------------------------


def _permits_by_target(model: ApplicationModel) -> dict[str, list[AppModelRelation]]:
    permits: dict[str, list[AppModelRelation]] = {}
    for relation in model.relations:
        if str(relation.kind) == "permits":
            permits.setdefault(relation.target_id, []).append(relation)
    return permits


def _endpoint_has_authz_marker(
    model: ApplicationModel,
    endpoint_id: str,
    permits: dict[str, list[AppModelRelation]],
) -> bool:
    if endpoint_id in permits:
        return True
    metadata = model.entities[endpoint_id].metadata or {}
    return bool(metadata.get("authz_declared") or metadata.get("authz_enforced"))


def reads_without_authz_marker(model: ApplicationModel) -> list[dict[str, Any]]:
    """Endpoints reading/accessing a resource with NO authz marker.

    Scope: endpoints holding a READS or ACCESSES relation to a RESOURCE
    (an access with unknown operation still reads). Marker: a PERMITS
    relation targeting the endpoint, or endpoint metadata
    authz_declared/authz_enforced. Missing evidence IS the answer —
    the entry carries the access evidence so the gap is auditable.
    """
    permits = _permits_by_target(model)
    flagged: dict[str, dict[str, Any]] = {}
    for relation in model.relations:
        if str(relation.kind) not in {"reads", "accesses"}:
            continue
        source = model.entities.get(relation.source_id)
        target = model.entities.get(relation.target_id)
        if source is None or target is None:
            continue
        if str(source.kind) != "endpoint" or str(target.kind) != "resource":
            continue
        if _endpoint_has_authz_marker(model, relation.source_id, permits):
            continue
        entry = flagged.setdefault(relation.source_id, {
            "endpoint_id": relation.source_id,
            "endpoint_label": str(source.label),
            "path": str(source.metadata.get("path") or ""),
            "resource_ids": [],
            "resource_labels": [],
            "evidence_refs": [],
        })
        if relation.target_id not in entry["resource_ids"]:
            entry["resource_ids"].append(relation.target_id)
            entry["resource_labels"].append(str(target.label))
        for ref in relation.ref_list():
            if ref not in entry["evidence_refs"]:
                entry["evidence_refs"].append(ref)
    entries = sorted(flagged.values(), key=lambda e: e["path"])
    for entry in entries:
        entry["resource_ids"] = sorted(entry["resource_ids"])
        entry["resource_labels"] = sorted(entry["resource_labels"])
        entry["evidence_refs"] = entry["evidence_refs"][:_MAX_REFS]
    return entries


# ---------------------------------------------------------------------------
# 4. workflow_skip_candidates
# ---------------------------------------------------------------------------


def workflow_skip_candidates(
    model: ApplicationModel,
    workflow_key: str,
) -> list[dict[str, Any]]:
    """Observed transitions that bypass an observed intermediate state.

    Evidence contract: a direct TRANSITIONS edge A→C where the SAME
    workflow also observed A→B and B→C — B is named as the skipped
    state. Purely observational; no declared order is assumed.
    """
    edges: dict[tuple[str, str], AppModelRelation] = {}
    for relation in model.relations:
        if str(relation.kind) != "transitions":
            continue
        if str(relation.metadata.get("workflow_key") or "") != workflow_key:
            continue
        edges.setdefault(
            (relation.source_id, relation.target_id), relation)
    skips: list[dict[str, Any]] = []
    for (start, end), direct in sorted(edges.items()):
        intermediates = sorted({
            middle
            for (start2, middle) in edges
            if start2 == start
            for (middle2, end2) in edges
            if middle2 == middle and end2 == end
        })
        if not intermediates:
            continue
        state_label = lambda entity_id: str(  # noqa: E731
            model.entities[entity_id].metadata.get("state")
            or model.entities[entity_id].label
        ) if entity_id in model.entities else entity_id
        skipped_relations = [
            edges[(start, middle)] for middle in intermediates
            if (start, middle) in edges
        ] + [
            edges[(middle, end)] for middle in intermediates
            if (middle, end) in edges
        ]
        skips.append({
            "workflow_key": workflow_key,
            "from_state": state_label(start),
            "to_state": state_label(end),
            "skipped_states": [state_label(middle) for middle in intermediates],
            "evidence_refs": _refs_union(
                [direct.ref_list()]
                + [rel.ref_list() for rel in skipped_relations]
            ),
        })
    skips.sort(key=lambda s: (s["from_state"], s["to_state"]))
    return skips


# ---------------------------------------------------------------------------
# 5. ui_vs_api_permission_diff
# ---------------------------------------------------------------------------


def _normalize_path(path: str) -> tuple[str, bool]:
    """Strip a leading api / api/vN prefix → (normalized, had_api_prefix)."""
    segments = [seg for seg in path.split("/") if seg]
    if segments and segments[0].lower() == "api":
        rest = segments[1:]
        if rest and _API_V_RE.match(rest[0]):
            rest = rest[1:]
        return "/".join(rest), True
    return "/".join(segments), False


def ui_vs_api_permission_diff(model: ApplicationModel) -> list[dict[str, Any]]:
    """UI/API surface pairs of one resource path disagreeing on authz.

    Pairing rule (deterministic): endpoints whose paths normalize equal
    after stripping a leading api / api/vN prefix, one with the prefix
    (API surface) and one without (UI surface). A diff is recorded only
    when the marker presence DIFFERS between the pair.
    """
    permits = _permits_by_target(model)
    groups: dict[str, list[tuple[str, str, bool]]] = {}
    for entity_id, entity in model.entities.items():
        if str(entity.kind) != "endpoint":
            continue
        path = str(entity.metadata.get("path") or "")
        if not path:
            continue
        normalized, had_api = _normalize_path(path)
        if not normalized:
            continue
        groups.setdefault(normalized, []).append((entity_id, path, had_api))
    diffs: list[dict[str, Any]] = []
    for normalized in sorted(groups):
        members = sorted(groups[normalized])
        ui_members = [m for m in members if not m[2]]
        api_members = [m for m in members if m[2]]
        if not ui_members or not api_members:
            continue
        for ui_id, ui_path, _ in ui_members:
            for api_id, api_path, _ in api_members:
                ui_marker = _endpoint_has_authz_marker(model, ui_id, permits)
                api_marker = _endpoint_has_authz_marker(model, api_id, permits)
                if ui_marker == api_marker:
                    continue
                marker_refs: list[str] = []
                for endpoint_id in (ui_id, api_id):
                    for relation in permits.get(endpoint_id, ()):
                        for ref in relation.ref_list():
                            if ref not in marker_refs:
                                marker_refs.append(ref)
                diffs.append({
                    "normalized_path": normalized,
                    "ui_endpoint_id": ui_id,
                    "ui_path": ui_path,
                    "ui_authz": ui_marker,
                    "api_endpoint_id": api_id,
                    "api_path": api_path,
                    "api_authz": api_marker,
                    "evidence_refs": marker_refs[:_MAX_REFS],
                })
    diffs.sort(key=lambda d: (d["ui_path"], d["api_path"]))
    return diffs


# ---------------------------------------------------------------------------
# Node telemetry — bounded counts of the SKG layers + query answers.
# ---------------------------------------------------------------------------


def summarize_skg(model: ApplicationModel) -> dict[str, Any]:
    """Bounded telemetry for the appmodel node summary channel."""
    kind_counts: dict[str, int] = {}
    for entity in model.entities.values():
        kind_counts[str(entity.kind)] = (
            kind_counts.get(str(entity.kind), 0) + 1)
    workflow_keys = sorted(
        str(entity.metadata.get("workflow_key") or entity.label)
        for entity in model.entities.values()
        if str(entity.kind) == "workflow"
    )
    skip_count = sum(
        len(workflow_skip_candidates(model, key)) for key in workflow_keys
    )
    paths_sample: dict[str, int] = {}
    for resource_id in sorted(
        entity_id
        for entity_id, entity in model.entities.items()
        if str(entity.kind) == "resource"
    )[:8]:
        paths_sample[resource_id] = get_all_paths_to(model, resource_id)[
            "path_count"]
    return {
        "advisory_only": True,
        "resource_count": kind_counts.get("resource", 0),
        "role_count": kind_counts.get("role", 0),
        "session_count": kind_counts.get("session", 0),
        "state_count": kind_counts.get("state", 0),
        "workflow_count": kind_counts.get("workflow", 0),
        "parameter_count": kind_counts.get("parameter", 0),
        "trust_boundary_count": kind_counts.get("trust_boundary", 0),
        "ownership_changer_count": len(ownership_changers(model)),
        "reads_without_authz_count": len(reads_without_authz_marker(model)),
        "workflow_skip_candidate_count": skip_count,
        "ui_vs_api_diff_count": len(ui_vs_api_permission_diff(model)),
        "paths_by_resource_sample": paths_sample,
    }
