"""UM-DR-46 Phase E — advanced discovery intelligence (SKG-mined).

Mines the Security Knowledge Graph for DISCOVERY targets — what the
model itself says it has NOT observed yet. Deterministic kinds:

* ``unobserved_transition``   — two observed states of one workflow
  with NO observed transition edge between them (a candidate
  transition worth probing);
* ``parameter_sibling``       — a parameter entity's observed values
  imply deterministic sibling candidates (bounded numeric increments);
* ``single_path_resource``    — a resource reachable by exactly one
  evidence-backed path (a second path is worth discovering);
* ``unmarked_state_trigger``  — an endpoint that triggers a workflow
  transition but carries NO authorization marker.

All pure, bounded (64), evidence-carrying, advisory only — mining
produces no requests, no authorizations, no scope expansion.
"""
from __future__ import annotations

from typing import Any

from webpent.appmodel.models import ApplicationModel

__all__ = ["discovery_intel_summary", "mine_discovery_targets"]

_MAX_TARGETS = 64
_MAX_SIBLING_VALUES = 4


def _refs_union(groups: list[list[str]]) -> list[str]:
    merged: list[str] = []
    for refs in groups:
        for ref in refs:
            if ref and ref not in merged:
                merged.append(ref)
    return merged[:8]


def _state_name(model: ApplicationModel, entity_id: str) -> str:
    entity = model.entities.get(entity_id)
    if entity is None:
        return entity_id
    return str((entity.metadata or {}).get("state") or entity.label)


def mine_discovery_targets(model: ApplicationModel) -> list[dict[str, Any]]:
    """All SKG-mined discovery targets (bounded, deterministic order)."""
    targets: list[dict[str, Any]] = []

    # 1. unobserved transition pairs per workflow
    workflow_edges: dict[str, set[tuple[str, str]]] = {}
    workflow_refs: dict[str, list[str]] = {}
    for relation in model.relations:
        if str(relation.kind) != "transitions":
            continue
        workflow_key = str((relation.metadata or {}).get("workflow_key") or "")
        if not workflow_key:
            continue
        workflow_edges.setdefault(workflow_key, set()).add((
            _state_name(model, relation.source_id),
            _state_name(model, relation.target_id),
        ))
        workflow_refs.setdefault(workflow_key, []).extend(relation.ref_list())
    for workflow_key, edges in sorted(workflow_edges.items()):
        states = sorted({s for edge in edges for s in edge})
        refs = list(dict.fromkeys(workflow_refs.get(workflow_key, [])))[:8]
        for from_state in states:
            for to_state in states:
                if from_state == to_state or (from_state, to_state) in edges:
                    continue
                targets.append({
                    "kind": "unobserved_transition",
                    "workflow_key": workflow_key,
                    "from_state": from_state,
                    "to_state": to_state,
                    "evidence_refs": refs,
                    "advisory_only": True,
                })
                if len(targets) >= _MAX_TARGETS:
                    return targets

    # 2. parameter sibling candidates (deterministic numeric increments)
    for entity in sorted(
        (e for e in model.entities.values() if str(e.kind) == "parameter"),
        key=lambda e: e.id,
    ):
        values = sorted(str(v) for v in (
            entity.metadata.get("values_observed") or []))
        candidates: list[str] = []
        for value in values:
            if value.isdigit():
                bumped = str(int(value) + 1)
                if bumped not in values:
                    candidates.append(bumped)
        candidates = list(dict.fromkeys(candidates))[:_MAX_SIBLING_VALUES]
        if not candidates:
            continue
        targets.append({
            "kind": "parameter_sibling",
            "pattern": str(entity.metadata.get("pattern") or ""),
            "observed_values": values,
            "candidate_values": candidates,
            "parameter_id": entity.id,
            "evidence_refs": entity.ref_list(),
            "advisory_only": True,
        })
        if len(targets) >= _MAX_TARGETS:
            return targets

    # 3. single-path resources
    from webpent.appmodel.skg_queries import get_all_paths_to

    for entity in sorted(
        (e for e in model.entities.values() if str(e.kind) == "resource"),
        key=lambda e: e.id,
    ):
        path_count = get_all_paths_to(model, entity.id)["path_count"]
        if path_count != 1:
            continue
        targets.append({
            "kind": "single_path_resource",
            "resource_id": entity.id,
            "resource_label": str(entity.label),
            "path_count": path_count,
            "evidence_refs": entity.ref_list(),
            "advisory_only": True,
        })
        if len(targets) >= _MAX_TARGETS:
            return targets

    # 4. unmarked state-trigger endpoints
    transition_endpoints: dict[str, list[str]] = {}
    for relation in model.relations:
        if str(relation.kind) != "transitions":
            continue
        endpoint = str((relation.metadata or {}).get("endpoint") or "")
        if endpoint:
            transition_endpoints.setdefault(endpoint, []).extend(
                relation.ref_list())
    permits_targets = {
        r.target_id for r in model.relations if str(r.kind) == "permits"}
    for entity_id, entity in sorted(model.entities.items()):
        if str(entity.kind) != "endpoint":
            continue
        path = str(entity.metadata.get("path") or "")
        if path not in transition_endpoints:
            continue
        marked = entity_id in permits_targets or bool(
            (entity.metadata or {}).get("authz_declared")
            or (entity.metadata or {}).get("authz_enforced"))
        if marked:
            continue
        targets.append({
            "kind": "unmarked_state_trigger",
            "path": path,
            "endpoint_id": entity_id,
            "evidence_refs": _refs_union([
                transition_endpoints.get(path, []), entity.ref_list()]),
            "advisory_only": True,
        })
        if len(targets) >= _MAX_TARGETS:
            break
    return targets


def discovery_intel_summary(model: ApplicationModel) -> dict[str, Any]:
    targets = mine_discovery_targets(model)
    kinds: dict[str, int] = {}
    for target in targets:
        kinds[str(target["kind"])] = kinds.get(str(target["kind"]), 0) + 1
    return {
        "advisory_only": True,
        "target_count": len(targets),
        "unobserved_transition_count": kinds.get("unobserved_transition", 0),
        "parameter_sibling_count": kinds.get("parameter_sibling", 0),
        "single_path_resource_count": kinds.get("single_path_resource", 0),
        "unmarked_state_trigger_count": kinds.get(
            "unmarked_state_trigger", 0),
    }
