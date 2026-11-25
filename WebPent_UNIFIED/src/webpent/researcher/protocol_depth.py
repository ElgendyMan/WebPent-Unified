"""UM-DR-46 Phase J — multi-protocol depth (SKG-driven targets).

See the test module for the contract. Pure, bounded (32), advisory —
targets, never requests, never authority.
"""
from __future__ import annotations

from typing import Any

from webpent.appmodel.models import ApplicationModel

__all__ = ["protocol_depth_targets"]

_MAX_TARGETS = 32


def protocol_depth_targets(model: ApplicationModel) -> list[dict[str, Any]]:
    """All SKG-driven protocol-depth targets (bounded, sorted)."""
    targets: list[dict[str, Any]] = []

    # 1. workflow sequences: ≥2 observed transitions = sequence-replay work
    workflow_edges: dict[str, list[Any]] = {}
    for relation in model.relations:
        if str(relation.kind) != "transitions":
            continue
        workflow_key = str((relation.metadata or {}).get("workflow_key") or "")
        if workflow_key:
            workflow_edges.setdefault(workflow_key, []).append(relation)
    for workflow_key, relations in sorted(workflow_edges.items()):
        if len(relations) < 2:
            continue
        refs = sorted({ref for r in relations for ref in r.ref_list()})[:8]
        targets.append({
            "kind": "workflow_protocol",
            "workflow_key": workflow_key,
            "transition_count": len(relations),
            "transitions": sorted(
                f"{str((model.entities.get(r.source_id) or r.source_id))}"
                f"→{str((model.entities.get(r.target_id) or r.target_id))}"
                for r in relations
            )[:8],
            "evidence_refs": refs,
            "advisory_only": True,
        })

    # 2. enumerable object-id spaces: numeric observed parameter values
    for entity in sorted(
        (e for e in model.entities.values() if str(e.kind) == "parameter"),
        key=lambda e: e.id,
    ):
        values = sorted(str(v) for v in (
            entity.metadata.get("values_observed") or []))
        numeric = [v for v in values if v.isdigit()]
        if len(numeric) < 2:
            continue
        targets.append({
            "kind": "object_id_space",
            "parameter_id": entity.id,
            "pattern": str(entity.metadata.get("pattern") or ""),
            "numeric_values": numeric[:8],
            "evidence_refs": entity.ref_list(),
            "advisory_only": True,
        })

    # 3. cross-origin workflows: transitions whose trigger endpoints span
    #    >1 trust boundary (CROSSES from endpoints involved in the workflow)
    for workflow_key, relations in sorted(workflow_edges.items()):
        if len(relations) < 2:
            continue
        origins: set[str] = set()
        for relation in relations:
            endpoint_path = str((relation.metadata or {}).get("endpoint") or "")
            for entity in model.entities.values():
                if (str(entity.kind) == "endpoint"
                        and str(entity.metadata.get("path") or "")
                        == endpoint_path):
                    host = str(entity.metadata.get("host") or "")
                    port = str(entity.metadata.get("port") or "")
                    if host:
                        origins.add(f"{host}:{port}")
        if len(origins) > 1:
            targets.append({
                "kind": "cross_origin",
                "workflow_key": workflow_key,
                "origins": sorted(origins)[:4],
                "evidence_refs": sorted(
                    {ref for r in relations for ref in r.ref_list()})[:8],
                "advisory_only": True,
            })
    targets.sort(key=lambda t: (t["kind"], str(t.get("workflow_key")
                                           or t.get("parameter_id") or "")))
    return targets[:_MAX_TARGETS]
