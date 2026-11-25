"""UM-DR-46 Phase B — the Researcher Brain.

Five deterministic understanding components over the Security
Knowledge Graph (mission Phase B: "مكونات الفهم حتمية 100%"): they
read ONLY evidence-backed entities/relations and produce:

1. ``classify_endpoint_behavior``  — per-endpoint behavioral profiles
   (reads / writes / state-trigger / authz-marked / accessed-by);
2. ``infer_business_rules``        — sequence, role-gate, ownership and
   parameter rules with causal-guard validation contracts;
3. ``transition_semantics``        — per state-transition: trigger
   endpoint, method, destructiveness, evidence;
4. ``discover_invariants``         — invariant candidates (sequence,
   ownership, role-gate) in the invariant-review vocabulary;
5. ``detect_contradictions``       — evidence-vs-evidence conflicts
   (UI-vs-API marker mismatch, workflow protocol bypass, ownership
   change without authorization evidence), recorded in the SSOT via
   ``ApplicationModel.mark_contradicted`` (both evidences KEPT).

Laws: pure functions (same model in ⇒ same answer out), bounded
everywhere, evidence-carrying, advisory only — no I/O, no network, no
authorization, no confirmation authority. The researcher-brain node
(`production/researcher_brain.py`) wires these into the graph and
feeds the canonical hypothesis engine.
"""

from __future__ import annotations

from typing import Any

from webpent.appmodel.models import ApplicationModel

__all__ = [
    "classify_endpoint_behavior",
    "detect_contradictions",
    "discover_invariants",
    "infer_business_rules",
    "transition_semantics",
]

_MAX_PROFILES = 256
_MAX_RULES = 128
_MAX_INVARIANTS = 64
_MAX_CONTRADICTIONS = 32
_MAX_REFS = 12
_WRITE_OPERATIONS = {"write", "update", "patch", "delete", "remove",
                     "create", "post", "put"}


def _refs_union(groups: list[list[str]]) -> list[str]:
    merged: list[str] = []
    for refs in groups:
        for ref in refs:
            if ref and ref not in merged:
                merged.append(ref)
    return merged[:_MAX_REFS]


def _kind(model: ApplicationModel, entity_id: str) -> str:
    entity = model.entities.get(entity_id)
    return str(entity.kind) if entity is not None else ""


def _label(model: ApplicationModel, entity_id: str) -> str:
    entity = model.entities.get(entity_id)
    return str(entity.label) if entity is not None else entity_id


# ---------------------------------------------------------------------------
# 1. Behavioral understanding
# ---------------------------------------------------------------------------


def classify_endpoint_behavior(
    model: ApplicationModel,
) -> dict[str, dict[str, Any]]:
    """Evidence-backed behavioral profile per endpoint.

    An endpoint appears ONLY when at least one evidence relation
    involves it (no profile is invented for unevidenced endpoints).
    Every profile carries the union evidence of the facts it states.
    """
    permits_by_target = {
        relation.target_id
        for relation in model.relations
        if str(relation.kind) == "permits"
    }
    transition_endpoints: set[str] = set()
    for relation in model.relations:
        if str(relation.kind) != "transitions":
            continue
        endpoint_ref = str(relation.metadata.get("endpoint") or "")
        if endpoint_ref:
            transition_endpoints.add(endpoint_ref)
    # principals observed acting on each resource (identity sources of
    # accesses/reads/modifies/owns onto resources) — an endpoint's
    # accessed_by is the union over the resources it operates on
    resource_principals: dict[str, set[str]] = {}
    for relation in model.relations:
        if str(relation.kind) not in {"accesses", "reads", "modifies", "owns"}:
            continue
        source = model.entities.get(relation.source_id)
        if source is None or str(source.kind) != "identity":
            continue
        if _kind(model, relation.target_id) != "resource":
            continue
        resource_principals.setdefault(relation.target_id, set()).add(
            str(source.label))

    profiles: dict[str, dict[str, Any]] = {}
    for entity_id, entity in model.entities.items():
        if str(entity.kind) != "endpoint":
            continue
        path = str(entity.metadata.get("path") or "")
        reads = writes = False
        accessed_by: set[str] = set()
        resource_targets: set[str] = set()
        evidence: list[list[str]] = []
        has_evidence = False
        for relation in model.relations:
            if relation.source_id == entity_id:
                target_kind = _kind(model, relation.target_id)
                if target_kind != "resource":
                    continue
                has_evidence = True
                evidence.append(relation.ref_list())
                resource_targets.add(relation.target_id)
                kind = str(relation.kind)
                if kind in {"reads", "accesses"}:
                    reads = True
                if kind == "modifies":
                    writes = True
            elif relation.target_id == entity_id and str(relation.kind) == "permits":
                has_evidence = True
                evidence.append(relation.ref_list())
        if (path and path in transition_endpoints) or entity_id in {
            r.source_id for r in model.relations if str(r.kind) == "exposes"
        }:
            has_evidence = True
            for relation in model.relations:
                if str(relation.kind) == "transitions" and str(
                    relation.metadata.get("endpoint") or ""
                ) == path:
                    evidence.append(relation.ref_list())
        for resource_id in resource_targets:
            accessed_by.update(resource_principals.get(resource_id, ()))
        marked = entity_id in permits_by_target or bool(
            (entity.metadata or {}).get("authz_declared")
            or (entity.metadata or {}).get("authz_enforced")
        )
        if not has_evidence:
            continue
        profiles[entity_id] = {
            "endpoint_id": entity_id,
            "endpoint_label": str(entity.label),
            "path": path,
            "reads": reads,
            "writes": writes,
            "state_trigger": bool(path and path in transition_endpoints),
            "authz_marked": marked,
            "accessed_by": sorted(accessed_by)[:8],
            "evidence_refs": _refs_union(evidence),
            "advisory_only": True,
        }
        if len(profiles) >= _MAX_PROFILES:
            break
    return profiles


# ---------------------------------------------------------------------------
# 2. Business-logic inference
# ---------------------------------------------------------------------------


def infer_business_rules(model: ApplicationModel) -> list[dict[str, Any]]:
    """Deterministic business rules from graph evidence.

    Kinds: ``sequence`` (observed transition chains), ``role_gate``
    (PERMITS), ``ownership`` (OWNS on resources), ``parameter``
    (observed parameter variance). Every rule names its causal-guard
    validation contract — a candidate signal, never a finding.
    """
    rules: list[dict[str, Any]] = []
    workflow_transitions: dict[str, list[tuple[str, str, list[str]]]] = {}
    for relation in model.relations:
        if str(relation.kind) != "transitions":
            continue
        workflow_key = str(relation.metadata.get("workflow_key") or "")
        if not workflow_key:
            continue
        workflow_transitions.setdefault(workflow_key, []).append((
            _state_name(model, relation.source_id),
            _state_name(model, relation.target_id),
            relation.ref_list(),
        ))
    for workflow_key, transitions in sorted(workflow_transitions.items()):
        chain = "; ".join(
            f"{src}→{dst}" for src, dst, _refs in sorted(transitions)
        )
        rules.append({
            "rule_id": f"skg-rule:sequence:{workflow_key}"[:200],
            "kind": "sequence",
            "statement": (
                f"workflow {workflow_key} observed transitions: {chain}"[:500]
            ),
            "evidence_refs": _refs_union(
                [refs for _src, _dst, refs in transitions]),
            "required_validation": "causal-guard differential",
        })
    for relation in model.relations:
        if str(relation.kind) == "permits":
            role = _label(model, relation.source_id)
            endpoint = model.entities.get(relation.target_id)
            path = str((endpoint.metadata or {}).get("path") or "") if endpoint else ""
            operation = str(relation.metadata.get("operation") or "any")
            rules.append({
                "rule_id": f"skg-rule:role_gate:{relation.id}"[:200],
                "kind": "role_gate",
                "statement": (
                    f"role {role} is permitted operation {operation} on {path}"[:500]
                ),
                "evidence_refs": relation.ref_list()[:_MAX_REFS],
                "required_validation": "causal-guard differential",
            })
        elif str(relation.kind) == "owns" and _kind(
            model, relation.target_id
        ) == "resource":
            rules.append({
                "rule_id": f"skg-rule:ownership:{relation.id}"[:200],
                "kind": "ownership",
                "statement": (
                    f"identity {_label(model, relation.source_id)} owns "
                    f"resource {_label(model, relation.target_id)}"[:500]
                ),
                "evidence_refs": relation.ref_list()[:_MAX_REFS],
                "required_validation": "causal-guard differential",
            })
        elif str(relation.kind) == "has_parameter" and len(rules) < _MAX_RULES:
            parameter = model.entities.get(relation.target_id)
            if parameter is not None and str(parameter.kind) == "parameter":
                values = parameter.metadata.get("values_observed") or []
                rules.append({
                    "rule_id": f"skg-rule:parameter:{relation.target_id}"[:200],
                    "kind": "parameter",
                    "statement": (
                        f"parameter {parameter.label} observed with values "
                        f"{sorted(str(v) for v in values[:8])}"[:500]
                    ),
                    "evidence_refs": _refs_union(
                        [relation.ref_list(), parameter.ref_list()]),
                    "required_validation": "causal-guard differential",
                })
        if len(rules) >= _MAX_RULES:
            break
    rules.sort(key=lambda r: (r["kind"], r["rule_id"]))
    return rules[:_MAX_RULES]


def _state_name(model: ApplicationModel, entity_id: str) -> str:
    entity = model.entities.get(entity_id)
    if entity is None:
        return entity_id
    return str((entity.metadata or {}).get("state") or entity.label)


# ---------------------------------------------------------------------------
# 3. State-transition semantics
# ---------------------------------------------------------------------------


def transition_semantics(model: ApplicationModel) -> list[dict[str, Any]]:
    """Per-transition semantics: trigger endpoint, method, destructiveness."""
    records: list[dict[str, Any]] = []
    for relation in model.relations:
        if str(relation.kind) != "transitions":
            continue
        metadata = relation.metadata or {}
        records.append({
            "workflow_key": str(metadata.get("workflow_key") or ""),
            "transition_key": str(metadata.get("transition_key") or ""),
            "from_state": _state_name(model, relation.source_id),
            "to_state": _state_name(model, relation.target_id),
            "trigger_endpoint": str(metadata.get("endpoint") or ""),
            "method": str(metadata.get("method") or ""),
            "destructive": bool(metadata.get("destructive")),
            "evidence_refs": relation.ref_list()[:_MAX_REFS],
        })
    records.sort(key=lambda r: (r["workflow_key"], r["from_state"], r["to_state"]))
    return records


# ---------------------------------------------------------------------------
# 4. Invariant discovery
# ---------------------------------------------------------------------------


def discover_invariants(model: ApplicationModel) -> list[dict[str, Any]]:
    """Invariant candidates from graph evidence.

    ``sequence_invariant`` (an observed intermediate state must not be
    bypassed), ``ownership_invariant`` (a resource's recorded owner) and
    ``role_gate_invariant`` (a write operation bound to a permitted
    role). Same candidate-signal vocabulary as the invariant review.
    """
    from webpent.appmodel.skg_queries import workflow_skip_candidates

    invariants: list[dict[str, Any]] = []
    workflow_keys = sorted({
        str((entity.metadata or {}).get("workflow_key") or entity.label)
        for entity in model.entities.values()
        if str(entity.kind) == "workflow"
    })
    for workflow_key in workflow_keys:
        for skip in workflow_skip_candidates(model, workflow_key):
            skipped = ", ".join(skip["skipped_states"])
            invariants.append({
                "invariant_id": (
                    f"skg-inv:sequence:{workflow_key}:"
                    f"{skip['from_state']}->{skip['to_state']}"[:200]
                ),
                "kind": "sequence_invariant",
                "statement": (
                    f"state {skipped} must not be bypassed between "
                    f"{skip['from_state']} and {skip['to_state']} in "
                    f"workflow {workflow_key}"[:500]
                ),
                "evidence_refs": skip["evidence_refs"][:_MAX_REFS],
                "required_validation": "causal-guard differential",
            })
    for relation in model.relations:
        kind = str(relation.kind)
        if kind == "owns" and _kind(model, relation.target_id) == "resource":
            invariants.append({
                "invariant_id": f"skg-inv:ownership:{relation.id}"[:200],
                "kind": "ownership_invariant",
                "statement": (
                    f"resource {_label(model, relation.target_id)} owner is "
                    f"identity {_label(model, relation.source_id)}"[:500]
                ),
                "evidence_refs": relation.ref_list()[:_MAX_REFS],
                "required_validation": "causal-guard differential",
            })
        elif kind == "permits":
            operation = str(relation.metadata.get("operation") or "").lower()
            if operation in _WRITE_OPERATIONS:
                endpoint = model.entities.get(relation.target_id)
                path = str((endpoint.metadata or {}).get("path") or "") if endpoint else ""
                invariants.append({
                    "invariant_id": f"skg-inv:role_gate:{relation.id}"[:200],
                    "kind": "role_gate_invariant",
                    "statement": (
                        f"write operation {operation} on {path} requires "
                        f"role {_label(model, relation.source_id)}"[:500]
                    ),
                    "evidence_refs": relation.ref_list()[:_MAX_REFS],
                    "required_validation": "causal-guard differential",
                })
        if len(invariants) >= _MAX_INVARIANTS:
            break
    invariants.sort(key=lambda i: (i["kind"], i["invariant_id"]))
    return invariants[:_MAX_INVARIANTS]


# ---------------------------------------------------------------------------
# 5. Contradiction detection
# ---------------------------------------------------------------------------

_CONTRADICTION_VULN_CLASS = {
    "surface_marker_mismatch": "auth_bypass",
    "workflow_protocol_bypass": "auth_bypass",
    "ownership_change_without_marker": "idor",
}


def contradiction_vuln_class(kind: str) -> str:
    """The VulnClass vocabulary entry for a contradiction kind."""
    return _CONTRADICTION_VULN_CLASS.get(kind, "auth_bypass")


def detect_contradictions(
    model: ApplicationModel,
    *,
    mark: bool = True,
) -> list[dict[str, Any]]:
    """Evidence-vs-evidence conflicts, recorded in the SSOT.

    Deterministic kinds:
    * ``surface_marker_mismatch`` — UI and API surfaces of one resource
      path disagree on authorization markers;
    * ``workflow_protocol_bypass`` — an observed transition bypasses an
      observed intermediate state;
    * ``ownership_change_without_marker`` — an ownership change through
      an endpoint carrying NO authorization evidence at all.

    With ``mark=True`` the involved endpoint entities flip to
    CONTRADICTED provenance via ``mark_contradicted`` — both the
    original and the contradicting evidence are KEPT (UM-DR-37 Part
    5.5). The returned records are identical across repeated calls on
    the same model; the SSOT mark may append on repeat calls, so
    callers mark once per model instance.
    """
    from webpent.appmodel.skg_queries import (
        ui_vs_api_permission_diff,
        workflow_skip_candidates,
    )

    contradictions: list[dict[str, Any]] = []

    def emit(contradiction_id: str, kind: str, statement: str,
             entity_ids: list[str], evidence_refs: list[str]) -> None:
        if len(contradictions) >= _MAX_CONTRADICTIONS:
            return
        if mark:
            for entity_id in entity_ids:
                if entity_id in model.entities:
                    model.mark_contradicted(
                        entity_id,
                        contradicting_evidence_ref=(
                            evidence_refs[0] if evidence_refs else "skg-contradiction"),
                        note=statement[:300],
                    )
        contradictions.append({
            "contradiction_id": contradiction_id[:200],
            "kind": kind,
            "statement": statement[:500],
            "entity_ids": entity_ids,
            "evidence_refs": evidence_refs[:_MAX_REFS],
        })

    # a) UI vs API marker disagreement
    for diff in ui_vs_api_permission_diff(model):
        unmarked_id = diff["ui_endpoint_id"] if not diff["ui_authz"] else diff[
            "api_endpoint_id"]
        marked_id = diff["api_endpoint_id"] if not diff["ui_authz"] else diff[
            "ui_endpoint_id"]
        emit(
            f"skg-con:surface:{diff['ui_path']}|{diff['api_path']}",
            "surface_marker_mismatch",
            (
                f"UI surface {diff['ui_path']} carries no authorization "
                f"marker while API surface {diff['api_path']} does — the "
                f"surfaces disagree about the same resource"
            ),
            [unmarked_id, marked_id],
            diff["evidence_refs"],
        )

    # b) workflow protocol bypass
    workflow_keys = sorted({
        str((entity.metadata or {}).get("workflow_key") or entity.label)
        for entity in model.entities.values()
        if str(entity.kind) == "workflow"
    })
    for workflow_key in workflow_keys:
        for skip in workflow_skip_candidates(model, workflow_key):
            trigger_entity = _endpoint_entity_for_path(
                model, _transition_endpoint(model, workflow_key,
                                            skip["from_state"],
                                            skip["to_state"]))
            emit(
                f"skg-con:workflow:{workflow_key}:"
                f"{skip['from_state']}->{skip['to_state']}",
                "workflow_protocol_bypass",
                (
                    f"workflow {workflow_key}: transition "
                    f"{skip['from_state']}→{skip['to_state']} bypasses the "
                    f"observed intermediate state "
                    f"{', '.join(skip['skipped_states'])}"
                ),
                ([trigger_entity] if trigger_entity else []),
                skip["evidence_refs"],
            )

    # c) ownership change without authorization evidence
    marked_ids = {
        relation.target_id
        for relation in model.relations
        if str(relation.kind) == "permits"
    }
    for entity_id, entity in list(model.entities.items()):
        if str(entity.kind) != "endpoint":
            continue
        if entity_id in marked_ids or bool(
            (entity.metadata or {}).get("authz_declared")
            or (entity.metadata or {}).get("authz_enforced")
        ):
            continue
        for relation in model.relations:
            if relation.source_id != entity_id or str(relation.kind) != "modifies":
                continue
            attribute = str(relation.metadata.get("attribute") or "")
            if attribute != "owner" or _kind(
                model, relation.target_id
            ) != "resource":
                continue
            actor = str(relation.metadata.get("actor") or "") or "unknown"
            emit(
                f"skg-con:ownership:{entity_id}:{relation.target_id}",
                "ownership_change_without_marker",
                (
                    f"ownership of {_label(model, relation.target_id)} changed "
                    f"by {actor} via {str(entity.metadata.get('path') or '')} "
                    f"with no authorization evidence on the endpoint"
                ),
                [entity_id],
                _refs_union([relation.ref_list(), entity.ref_list()]),
            )
    contradictions.sort(key=lambda c: c["contradiction_id"])
    return contradictions


def _transition_endpoint(model: ApplicationModel, workflow_key: str,
                         from_state: str, to_state: str) -> str:
    for relation in model.relations:
        if str(relation.kind) != "transitions":
            continue
        metadata = relation.metadata or {}
        if (str(metadata.get("workflow_key") or "") == workflow_key
                and _state_name(model, relation.source_id) == from_state
                and _state_name(model, relation.target_id) == to_state):
            return str(metadata.get("endpoint") or "")
    return ""


def _endpoint_entity_for_path(model: ApplicationModel, path: str) -> str | None:
    if not path:
        return None
    for entity_id, entity in model.entities.items():
        if str(entity.kind) == "endpoint" and str(
            entity.metadata.get("path") or ""
        ) == path:
            return entity_id
    return None
