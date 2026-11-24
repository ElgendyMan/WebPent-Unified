"""UM-DR-46 Phase D — cross-feature attack reasoning (SKG chains).

Composes the Security Knowledge Graph's evidence-backed facts into
multi-step attack-chain candidates BEFORE any finding exists — the
pre-finding analogue of production/chain_composer.py (which composes
FINDINGS). Deterministic chain kinds:

* ``info_authz_composition``  — an unmarked read/access on a resource
  COMPOSED with an unmarked ownership change on the SAME resource
  (the mission's "ثغرة معلومات + تحكم وصول = استغلال مركب") — the
  two legs are DIFFERENT evidence kinds, so one endpoint carrying
  both still composes;
* ``workflow_bypass_chain``   — an observed state-transition bypass
  through an UNMARKED trigger endpoint composed with the workflow's
  role-scoped gated transition;
* ``cross_surface_chain``     — a UI-vs-API authorization-marker
  disagreement composed with the observed parameter variance of the
  same path family.

Every chain: evidence-backed steps, deterministic id, causal-guard
validation contract, advisory only — a chain is a RESEARCH candidate
(never a finding, never a confirmation, never an authorization).
"""
from __future__ import annotations

import json
from hashlib import sha256
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from webpent.appmodel.models import ApplicationModel

__all__ = ["chain_hypotheses", "compose_attack_chains", "summarize_chains"]

_MAX_CHAINS = 24
_MAX_REFS = 12

_CHAIN_VULN_CLASS = {
    "info_authz_composition": "idor",
    "workflow_bypass_chain": "auth_bypass",
    "cross_surface_chain": "auth_bypass",
}


def _refs_union(groups: list[list[str]]) -> list[str]:
    merged: list[str] = []
    for refs in groups:
        for ref in refs:
            if ref and ref not in merged:
                merged.append(ref)
    return merged[:_MAX_REFS]


def _endpoint_marked(model: ApplicationModel, endpoint_id: str) -> bool:
    for relation in model.relations:
        if str(relation.kind) == "permits" and relation.target_id == endpoint_id:
            return True
    metadata = (model.entities.get(endpoint_id) or {}).metadata or {}
    return bool(metadata.get("authz_declared") or metadata.get("authz_enforced"))


def _chain_id(kind: str, key: str) -> str:
    blob = json.dumps({"k": kind, "c": key}, sort_keys=True,
                      separators=(",", ":"))
    digest = sha256(blob.encode("utf-8")).hexdigest()[:40]
    return str(uuid5(NAMESPACE_URL, f"webpent:umdr46d:{digest}"))


# ---------------------------------------------------------------------------
# Compositions
# ---------------------------------------------------------------------------


def _info_authz_chains(model: ApplicationModel) -> list[dict[str, Any]]:
    from webpent.appmodel.skg_queries import (
        ownership_changers,
        reads_without_authz_marker,
    )

    changers = ownership_changers(model)
    chains: list[dict[str, Any]] = []
    for read_entry in reads_without_authz_marker(model):
        for changer in changers:
            if changer["resource_id"] not in read_entry["resource_ids"]:
                continue
            if _endpoint_marked(model, changer["endpoint_id"]):
                continue  # marked change = governed, not a composition
            steps = [
                {
                    "step_index": 0,
                    "kind": "info_leg",
                    "path": read_entry["path"],
                    "endpoint_id": read_entry["endpoint_id"],
                    "resource_labels": read_entry["resource_labels"],
                    "evidence_refs": read_entry["evidence_refs"],
                },
                {
                    "step_index": 1,
                    "kind": "authz_leg_ownership_change",
                    "path": changer["endpoint_path"],
                    "endpoint_id": changer["endpoint_id"],
                    "resource_label": changer["resource_label"],
                    "attribute": changer["attribute"],
                    "actor": changer.get("actor"),
                    "evidence_refs": changer["evidence_refs"],
                },
            ]
            chains.append({
                "chain_id": _chain_id(
                    "info_authz_composition",
                    f"{read_entry['endpoint_id']}|{changer['endpoint_id']}|"
                    f"{changer['resource_id']}"),
                "kind": "info_authz_composition",
                "statement": (
                    f"unmarked read on "
                    f"{', '.join(read_entry['resource_labels'][:2])} via "
                    f"{read_entry['path']} composes with an unmarked "
                    f"ownership change on {changer['resource_label']} via "
                    f"{changer['endpoint_path']} — a cross-account "
                    f"information-and-control composition"
                ),
                "steps": steps,
                "preconditions": (
                    "both legs replayable under the engagement's scoped "
                    "principals; the differential is the composition, "
                    "not either leg alone"
                ),
                "evidence_refs": _refs_union([
                    read_entry["evidence_refs"], changer["evidence_refs"]]),
                "required_validation": "causal-guard differential",
                "advisory_only": True,
            })
            if len(chains) >= _MAX_CHAINS:
                return chains
    return chains


def _workflow_bypass_chains(model: ApplicationModel) -> list[dict[str, Any]]:
    from webpent.appmodel.skg_queries import workflow_skip_candidates

    chains: list[dict[str, Any]] = []
    for relation in model.relations:
        if str(relation.kind) != "transitions":
            continue
        metadata = relation.metadata or {}
        workflow_key = str(metadata.get("workflow_key") or "")
        if not workflow_key:
            continue
        boundary = str(metadata.get("authorization_boundary") or "")
        if boundary != "role_scoped":
            continue
        trigger_endpoint = str(metadata.get("endpoint") or "")
        gated = {
            "step_index": 1,
            "kind": "gated_target",
            "from_state": str((model.entities.get(relation.source_id)
                               or {}).metadata.get("state") or ""),
            "to_state": str((model.entities.get(relation.target_id)
                             or {}).metadata.get("state") or ""),
            "path": trigger_endpoint,
            "role_scoped": True,
            "evidence_refs": relation.ref_list(),
        }
        for skip in workflow_skip_candidates(model, workflow_key):
            bypass_entity = None
            for candidate in model.relations:
                if (str(candidate.kind) == "transitions"
                        and str((candidate.metadata or {}).get(
                            "workflow_key") or "") == workflow_key
                        and str((candidate.metadata or {}).get(
                            "endpoint") or "") != ""
                        and str((model.entities.get(candidate.source_id)
                                 or {}).metadata.get("state") or "")
                        == skip["from_state"]
                        and str((model.entities.get(candidate.target_id)
                                 or {}).metadata.get("state") or "")
                        == skip["to_state"]):
                    bypass_entity = candidate
                    break
            if bypass_entity is None:
                continue
            bypass_path = str((bypass_entity.metadata or {}).get(
                "endpoint") or "")
            bypass_endpoint_id = None
            for entity_id, entity in model.entities.items():
                if (str(entity.kind) == "endpoint"
                        and str(entity.metadata.get("path") or "")
                        == bypass_path):
                    bypass_endpoint_id = entity_id
                    break
            if bypass_endpoint_id is None or _endpoint_marked(
                model, bypass_endpoint_id
            ):
                continue  # a MARKED bypass is governed, not a chain
            steps = [
                {
                    "step_index": 0,
                    "kind": "bypass_leg",
                    "path": bypass_path,
                    "from_state": skip["from_state"],
                    "to_state": skip["to_state"],
                    "skipped_states": skip["skipped_states"],
                    "role_scoped": False,
                    "evidence_refs": skip["evidence_refs"],
                },
                gated,
            ]
            chains.append({
                "chain_id": _chain_id(
                    "workflow_bypass_chain",
                    f"{workflow_key}|{skip['from_state']}->{skip['to_state']}|"
                    f"{gated['from_state']}->{gated['to_state']}"),
                "kind": "workflow_bypass_chain",
                "statement": (
                    f"workflow {workflow_key}: the unmarked {skip['from_state']}"
                    f"→{skip['to_state']} shortcut (bypassing "
                    f"{', '.join(skip['skipped_states'])}) composes with the "
                    f"role-scoped {gated['from_state']}→{gated['to_state']} "
                    f"transition — a workflow-privilege composition"
                ),
                "steps": steps,
                "preconditions": (
                    "the bypass and the gated target replay under the "
                    "engagement's scoped principals; the composition is "
                    "the shortcut replacing the gated entry"
                ),
                "evidence_refs": _refs_union([
                    skip["evidence_refs"], relation.ref_list()]),
                "required_validation": "causal-guard differential",
                "advisory_only": True,
            })
            if len(chains) >= _MAX_CHAINS:
                return chains
    return chains


def _cross_surface_chains(model: ApplicationModel) -> list[dict[str, Any]]:
    from webpent.appmodel.skg_queries import ui_vs_api_permission_diff

    chains: list[dict[str, Any]] = []
    parameters = [
        (entity_id, entity)
        for entity_id, entity in model.entities.items()
        if str(entity.kind) == "parameter"
    ]
    for diff in ui_vs_api_permission_diff(model):
        normalized = diff["normalized_path"]
        segments = [seg for seg in normalized.split("/") if seg]
        matching = [
            (entity_id, entity)
            for entity_id, entity in parameters
            if segments and all(
                seg in str(entity.metadata.get("pattern") or "").split("/")
                for seg in segments
            )
        ]
        if not matching:
            continue
        entity_id, entity = matching[0]
        values = entity.metadata.get("values_observed") or []
        steps = [
            {
                "step_index": 0,
                "kind": "surface_marker_diff",
                "ui_path": diff["ui_path"],
                "api_path": diff["api_path"],
                "ui_authz": diff["ui_authz"],
                "api_authz": diff["api_authz"],
                "evidence_refs": diff["evidence_refs"],
            },
            {
                "step_index": 1,
                "kind": "parameter_variance",
                "parameter_id": entity_id,
                "pattern": str(entity.metadata.get("pattern") or ""),
                "values_observed": sorted(str(v) for v in values)[:8],
                "evidence_refs": entity.ref_list(),
            },
        ]
        chains.append({
            "chain_id": _chain_id(
                "cross_surface_chain",
                f"{diff['ui_path']}|{diff['api_path']}|{entity_id}"),
            "kind": "cross_surface_chain",
            "statement": (
                f"the /{normalized} UI/API marker disagreement composes "
                f"with the observed parameter variance "
                f"({entity.metadata.get('pattern')}) — cross-surface "
                f"object access candidates"
            ),
            "steps": steps,
            "preconditions": (
                "both surfaces reachable under the engagement's scoped "
                "principals; the differential is the marker disagreement "
                "applied to the varying objects"
            ),
            "evidence_refs": _refs_union([
                diff["evidence_refs"], entity.ref_list()]),
            "required_validation": "causal-guard differential",
            "advisory_only": True,
        })
        if len(chains) >= _MAX_CHAINS:
            return chains
    return chains


def compose_attack_chains(model: ApplicationModel) -> list[dict[str, Any]]:
    """All deterministic SKG chain candidates (bounded, sorted)."""
    chains = (
        _info_authz_chains(model)
        + _workflow_bypass_chains(model)
        + _cross_surface_chains(model)
    )
    chains.sort(key=lambda c: (c["kind"], c["chain_id"]))
    return chains[:_MAX_CHAINS]


# ---------------------------------------------------------------------------
# Canonical hypotheses (one per chain) + telemetry
# ---------------------------------------------------------------------------

_CHAIN_EXPECTED = {
    "info_authz_composition": (
        "the composition (read the foreign object, then act on its "
        "ownership/state) is denied for a non-owner while each leg "
        "alone may appear benign"
    ),
    "workflow_bypass_chain": (
        "the shortcut is rejected or lands the object in a state only "
        "the role-scoped transition could legitimately produce"
    ),
    "cross_surface_chain": (
        "the unmarked surface enforces the same authorization as the "
        "marked one for every varying object"
    ),
}
_CHAIN_CONTROL = {
    "info_authz_composition": (
        "owner-principal replay of the composition must succeed; "
        "foreign-principal replay must be denied; both sealed"
    ),
    "workflow_bypass_chain": (
        "the legitimate gated path must still succeed for the "
        "authorized role; the bypass must be isolated as the only "
        "difference, sealed"
    ),
    "cross_surface_chain": (
        "owner replay on both surfaces must succeed; foreign replay on "
        "both must be denied; both sealed"
    ),
}


def chain_hypotheses(
    model: ApplicationModel,
    target_url: str = "",
) -> list[Any]:
    """One canonical hypothesis per chain (deterministic uuid5 ids)."""
    from webpent.production.hypothesis_adapter import canonical_hypothesis

    hyps: list[Any] = []
    for chain in compose_attack_chains(model):
        kind = str(chain["kind"])
        hyps.append(canonical_hypothesis(
            id=uuid5(NAMESPACE_URL, f"webpent:umdr46d:{chain['chain_id']}"),
            statement=(
                f"{chain['statement']} — verify the COMPOSITION with a "
                f"CausalGuard-guarded differential experiment"
            ),
            vuln_class=_CHAIN_VULN_CLASS.get(kind, "auth_bypass"),
            origin="researcher_brain",
            origin_detail=(
                f"UM-DR-46 Phase D {kind} chain {chain['chain_id']} "
                f"({len(chain['steps'])} evidence-backed steps)"
            ),
            target_url=str(target_url or ""),
            expected_behavior=_CHAIN_EXPECTED.get(
                kind, "the composition resolves under a guarded differential"),
            negative_control=_CHAIN_CONTROL.get(
                kind, "owner replay succeeds; foreign replay denied; sealed"),
            deterministic_match=True,
            evidence_contract={
                "chain_id": chain["chain_id"],
                "kind": kind,
                "step_count": len(chain["steps"]),
                "evidence_refs": chain["evidence_refs"],
            },
        ))
    return hyps


def summarize_chains(model: ApplicationModel) -> dict[str, Any]:
    chains = compose_attack_chains(model)
    kinds: dict[str, int] = {}
    for chain in chains:
        kinds[str(chain["kind"])] = kinds.get(str(chain["kind"]), 0) + 1
    return {
        "advisory_only": True,
        "chain_count": len(chains),
        "chain_kinds": kinds,
    }
