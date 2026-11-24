"""UM-DR-46 Phase G — SKG-aware coverage intelligence.

Coverage cells derived from the Security Knowledge Graph itself:
(resource × principal × operation) triples, each carrying its own
evidence. A cell is ``verified`` ONLY when its evidence intersects the
state's guard-ADJUDICATED observations (guard_verdict
confirmed/falsified); every other cell is honestly
``observed_unverified`` — the model says the access was observed, not
that it was ever security-tested.

Pure, bounded (256), advisory only — a cell is coverage telemetry,
never a verdict, never a test result.
"""
from __future__ import annotations

import json
from hashlib import sha256
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from webpent.appmodel.models import ApplicationModel

__all__ = ["skg_coverage_cells", "skg_coverage_summary"]

_MAX_CELLS = 256

_OPERATION_BY_RELATION = {
    "owns": "own",
    "reads": "read",
    "modifies": "mutate",
    "accesses": "access",
}


def _cell_id(resource_label: str, principal: str, operation: str) -> str:
    blob = json.dumps(
        {"r": resource_label, "p": principal, "o": operation},
        sort_keys=True, separators=(",", ":"))
    digest = sha256(blob.encode("utf-8")).hexdigest()[:40]
    return str(uuid5(NAMESPACE_URL, f"webpent:umdr46g:{digest}"))


def skg_coverage_cells(
    model: ApplicationModel,
    verified_refs: set[str] | frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    """All (resource × principal × operation) cells (≤256, sorted)."""
    cells: dict[str, dict[str, Any]] = {}
    for relation in model.relations:
        kind = str(relation.kind)
        operation = _OPERATION_BY_RELATION.get(kind)
        if operation is None:
            continue
        source = model.entities.get(relation.source_id)
        target = model.entities.get(relation.target_id)
        if source is None or target is None:
            continue
        if str(source.kind) != "identity" or str(target.kind) != "resource":
            continue
        refs = list(relation.ref_list())
        cell_key = f"{target.label}|{source.label}|{operation}"
        entry = cells.setdefault(cell_key, {
            "cell_id": _cell_id(
                str(target.label), str(source.label), operation),
            "cell_key": cell_key,
            "resource_label": str(target.label),
            "principal_label": str(source.label),
            "operation": operation,
            "evidence_refs": [],
            "status": "observed_unverified",
            "advisory_only": True,
        })
        for ref in refs:
            if ref not in entry["evidence_refs"]:
                entry["evidence_refs"].append(ref)
        if any(ref in verified_refs for ref in entry["evidence_refs"]):
            entry["status"] = "verified"
    ordered = sorted(cells.values(), key=lambda c: c["cell_key"])
    return ordered[:_MAX_CELLS]


def skg_coverage_summary(
    model: ApplicationModel,
    verified_refs: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    cells = skg_coverage_cells(model, verified_refs)
    verified = sum(1 for c in cells if c["status"] == "verified")
    return {
        "advisory_only": True,
        "cell_count": len(cells),
        "verified_count": verified,
        "observed_unverified_count": len(cells) - verified,
        "verified_ratio": (
            round(verified / len(cells), 4) if cells else 0.0),
    }
