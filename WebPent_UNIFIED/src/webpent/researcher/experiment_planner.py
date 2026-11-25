"""UM-DR-46 Phase F — autonomous experimentation (SKG-driven plans).

Turns the Security Knowledge Graph's evidence-backed targets into
DETERMINISTIC EXPERIMENT PLANS bound to the registry's experiment
families (production/experiment_fabric.py: exp_idor_v1,
exp_privdiff_v1, …):

* a plan is emitted ONLY when the observed principal matrix is
  COMPLETE (a recorded owner + a recorded non-owner accessor) —
  incomplete matrices ABSTAIN (never invented);
* every plan carries the differential pair (owner leg vs non-owner
  leg), the negative control, the sealed-replay contract and the
  scope/guard preconditions;
* the planner PLANS ONLY — ResearchLoop remains the sole scheduler,
  execution stays inside ModernOrchestrator (ScopeLaw + ToolBoundary),
  CausalGuard stays the sole authority.

Pure functions, bounded (16), advisory only.
"""
from __future__ import annotations

import json
from hashlib import sha256
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from webpent.appmodel.models import ApplicationModel

__all__ = ["blocked_targets", "experiment_planner_summary", "plan_experiments"]

_MAX_PLANS = 16

_FAMILY_BY_KIND = {
    "access_differential": ("IDOR", "exp_idor_v1"),
    "ownership_target": ("IDOR", "exp_idor_v1"),
    "unmarked_read": ("IDOR", "exp_idor_v1"),
    "workflow_skip_target": ("PRIVILEGE_DIFFERENTIAL", "exp_privdiff_v1"),
}


def _plan_id(key: str) -> str:
    blob = json.dumps({"k": "plan", "c": key}, sort_keys=True,
                      separators=(",", ":"))
    digest = sha256(blob.encode("utf-8")).hexdigest()[:40]
    return str(uuid5(NAMESPACE_URL, f"webpent:umdr46f:{digest}"))


def _principal_matrix(
    model: ApplicationModel,
    resource_id: str,
) -> dict[str, str] | None:
    """The observed owner + one non-owner accessor, or None."""
    owner = None
    accessors: list[str] = []
    for relation in model.relations:
        if relation.target_id != resource_id:
            continue
        kind = str(relation.kind)
        source = model.entities.get(relation.source_id)
        if source is None or str(source.kind) != "identity":
            continue
        label = str(source.label)
        if kind == "owns" and owner is None:
            owner = label
        elif kind in {"accesses", "reads", "modifies"} and label != owner:
            accessors.append(label)
    if owner is None:
        return None
    secondary = next((a for a in sorted(set(accessors)) if a != owner), None)
    if secondary is None:
        return None
    return {"primary": owner, "secondary": secondary}


def _endpoint_for_resource(
    model: ApplicationModel,
    resource_id: str,
) -> dict[str, str] | None:
    """The evidence-backed endpoint operating on the resource."""
    for relation in model.relations:
        if (relation.target_id == resource_id
                and str(relation.kind) in {"accesses", "reads", "modifies"}):
            endpoint = model.entities.get(relation.source_id)
            if endpoint is not None and str(endpoint.kind) == "endpoint":
                return {
                    "endpoint_id": endpoint.id,
                    "endpoint_path": str(endpoint.metadata.get("path") or ""),
                }
    return None


def plan_experiments(model: ApplicationModel) -> list[dict[str, Any]]:
    """Deterministic experiment plans for modeled targets (≤16)."""
    plans: list[dict[str, Any]] = []
    from webpent.appmodel.skg_queries import (
        ownership_changers,
        reads_without_authz_marker,
        workflow_skip_candidates,
    )

    seen_targets: set[str] = set()

    def emit(kind: str, resource_id: str, resource_label: str,
             endpoint: dict[str, str] | None, matrix: dict[str, str],
             info_gain: float, evidence_refs: list[str],
             workflow: dict[str, Any] | None = None) -> None:
        if len(plans) >= _MAX_PLANS:
            return
        family, registry_id = _FAMILY_BY_KIND[kind]
        key = f"{kind}|{resource_id}|{endpoint['endpoint_id'] if endpoint else ''}"
        plan_id = _plan_id(key)
        if plan_id in seen_targets:
            return
        seen_targets.add(plan_id)
        if workflow is not None:
            differential = {
                "leg_a": (
                    f"as {matrix['secondary']}: trigger the observed "
                    f"shortcut {workflow['from_state']}→{workflow['to_state']} "
                    f"(bypassing {', '.join(workflow['skipped_states'])})"
                ),
                "leg_b": (
                    f"as {matrix['primary']} (the role-holding principal): "
                    f"the legitimate gated transition "
                    f"{workflow['gated_from']}→{workflow['gated_to']}"
                ),
            }
        else:
            differential = {
                "leg_a": (
                    f"as {matrix['secondary']}: access "
                    f"{resource_label} via "
                    f"{endpoint['endpoint_path'] if endpoint else 'the modeled access'}"
                ),
                "leg_b": (
                    f"as {matrix['primary']} (the recorded owner): the same "
                    f"access must succeed"
                ),
            }
        plans.append({
            "plan_id": plan_id,
            "experiment_family": family,
            "registry_experiment_id": registry_id,
            "target": {
                "resource_id": resource_id,
                "resource_label": resource_label,
                "endpoint_id": endpoint["endpoint_id"] if endpoint else None,
                "endpoint_path": (
                    endpoint["endpoint_path"] if endpoint else None),
                **({"workflow": workflow} if workflow else {}),
            },
            "principal_matrix": matrix,
            "differential": differential,
            "negative_control": (
                f"replay the legitimate leg ({matrix['primary']}) — it must "
                f"succeed; the differential must reproduce under sealed "
                f"replay"
            ),
            "replay_contract": "sealed replay, guard adjudicated",
            "preconditions": [
                "target within the engagement scope (ScopeLaw)",
                "CausalGuard adjudicates every leg; no bypass",
            ],
            "estimated_info_gain": max(0.0, min(1.0, float(info_gain))),
            "planner_kind": kind,
            "evidence_refs": evidence_refs[:8],
            "advisory_only": True,
            "scheduler_authority": "research_loop_only",
        })

    # 0. access-differential targets: a resource with a recorded owner
    #    AND a recorded non-owner accessor (the RC-2 finding projection)
    #    — the canonical IDOR differential experiment
    resource_entities = [
        (e.id, str(e.label))
        for e in model.entities.values()
        if str(e.kind) == "resource"
    ]
    for resource_id, resource_label in sorted(resource_entities):
        matrix = _principal_matrix(model, resource_id)
        if matrix is None:
            continue
        endpoint = _endpoint_for_resource(model, resource_id)
        emit(
            "access_differential", resource_id, resource_label,
            endpoint, matrix, 0.85,
            [ref
             for r in model.relations
             if r.target_id == resource_id
             for ref in r.ref_list()])

    # 1. ownership-change targets (the strongest object-authorization
    #    experiments) — complete matrices only
    for changer in ownership_changers(model):
        matrix = _principal_matrix(model, changer["resource_id"])
        if matrix is None:
            continue  # incomplete matrix → ABSTAIN (blocked_targets records it)
        endpoint = {
            "endpoint_id": changer["endpoint_id"],
            "endpoint_path": changer["endpoint_path"],
        }
        emit(
            "ownership_target", changer["resource_id"],
            changer["resource_label"], endpoint, matrix, 0.9,
            changer["evidence_refs"])
    if len(plans) >= _MAX_PLANS:
        return plans

    # 2. unmarked read targets
    for entry in reads_without_authz_marker(model):
        for resource_id, resource_label in zip(
            entry["resource_ids"], entry["resource_labels"], strict=False
        ):
            if _principal_matrix(model, resource_id) is None:
                continue  # ABSTAIN (blocked_targets records it)
            matrix = _principal_matrix(model, resource_id)
            emit(
                "unmarked_read", resource_id, resource_label,
                {"endpoint_id": entry["endpoint_id"],
                 "endpoint_path": entry["path"]},
                matrix, 0.8, entry["evidence_refs"])
            if len(plans) >= _MAX_PLANS:
                return plans

    # 3. workflow-skip targets (role-scoped gated transitions)
    workflow_keys = sorted({
        str((entity.metadata or {}).get("workflow_key") or entity.label)
        for entity in model.entities.values()
        if str(entity.kind) == "workflow"
    })
    for workflow_key in workflow_keys:
        for skip in workflow_skip_candidates(model, workflow_key):
            gated = next((
                r for r in model.relations
                if str(r.kind) == "transitions"
                and str((r.metadata or {}).get("workflow_key") or "")
                == workflow_key
                and str((r.metadata or {}).get(
                    "authorization_boundary") or "") == "role_scoped"
            ), None)
            if gated is None:
                continue
            gated_meta = gated.metadata or {}
            resource_entity = next((
                e for e in model.entities.values()
                if str(e.kind) == "workflow"
                and str((e.metadata or {}).get("workflow_key") or "")
                == workflow_key
            ), None)
            resource_id = resource_entity.id if resource_entity else workflow_key
            matrix = {
                "primary": "role-holding principal (declared PERMITS role)",
                "secondary": "non-role principal (observed accessor)",
            }
            emit(
                "workflow_skip_target", resource_id, f"workflow:{workflow_key}",
                None, matrix, 0.75,
                list(skip["evidence_refs"]) + list(gated.ref_list()),
                workflow={
                    "workflow_key": workflow_key,
                    "from_state": skip["from_state"],
                    "to_state": skip["to_state"],
                    "skipped_states": skip["skipped_states"],
                    "gated_from": str(
                        (model.entities.get(gated.source_id) or {})
                        .metadata.get("state") or ""),
                    "gated_to": str(
                        (model.entities.get(gated.target_id) or {})
                        .metadata.get("state") or ""),
                    "trigger_endpoint": str(
                        gated_meta.get("endpoint") or ""),
                })
            if len(plans) >= _MAX_PLANS:
                return plans
    plans.sort(key=lambda p: p["plan_id"])
    return plans


def blocked_targets(model: ApplicationModel) -> list[dict[str, Any]]:
    """Targets the planner ABSTAINED on, with the honest reason."""
    from webpent.appmodel.skg_queries import (
        ownership_changers,
        reads_without_authz_marker,
    )

    blocked: list[dict[str, Any]] = []
    seen: set[str] = set()
    for changer in ownership_changers(model):
        is_new_blocker = (
            _principal_matrix(model, changer["resource_id"]) is None
            and changer["resource_id"] not in seen
        )
        if is_new_blocker:
            seen.add(changer["resource_id"])
            blocked.append({
                "resource_id": changer["resource_id"],
                "reason": "incomplete_principal_matrix",
            })
    for entry in reads_without_authz_marker(model):
        for resource_id in entry["resource_ids"]:
            has_matrix = resource_id in seen or _principal_matrix(
                model, resource_id) is not None
            if not has_matrix:
                seen.add(resource_id)
                blocked.append({
                    "resource_id": resource_id,
                    "reason": "incomplete_principal_matrix",
                })
    return blocked


def experiment_planner_summary(model: ApplicationModel) -> dict[str, Any]:
    plans = plan_experiments(model)
    blocked = blocked_targets(model)
    families: dict[str, int] = {}
    for plan in plans:
        families[str(plan["experiment_family"])] = (
            families.get(str(plan["experiment_family"]), 0) + 1)
    return {
        "advisory_only": True,
        "plan_count": len(plans),
        "families": families,
        "blocked_count": len(blocked),
        "blocked_targets": blocked[:8],
        "scheduler_authority": "research_loop_only",
    }
