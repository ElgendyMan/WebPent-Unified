"""L7 lab evaluator: ground truth and scoring.

The labels in this module are the lab corpus's OWN ground truth,
declared from each deployment's implementation profile and applied to
investigation results only AFTER the investigation has finished. No
code under `webpent.egaie` may import this module; the isolation test
in tests/labsuite/ enforces that.

A defect descriptor is (family_key, detail). Engine-facing families
map onto the engine's canonical family labels so per-family TP/FP/FN
can be computed; GRANT_REPLAY has no engine-side generator by design.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from webpent.labsuite.lab_target import LabSpec

# Lab family keys and their engine-facing canonical labels (the exact
# strings the engine emits in HypothesisRecord.family). The grant
# family maps to None: no L6-era hypothesis generator covers it.
ENGINE_FAMILY: dict[str, str | None] = {
    "identity_read": "IDENTITY_BOUNDARY",
    "identity_mutation": "IDENTITY_BOUNDARY",
    "price": "PRICE_INTEGRITY",
    "workflow_identity": "WORKFLOW_IDENTITY",
    "workflow_order": "WORKFLOW_ORDER",
    "spend": "BOUNDARY_LIMIT",
    # L7 Step 6: the engine grew a grant-replay generator after the
    # failure analysis demonstrated the gap; the family is no longer
    # unscorable.
    "grant": "GRANT_REPLAY",
}


def defects_for(spec: LabSpec) -> list[dict[str, str]]:
    """Declare the deployment's defects from its implementation profile."""
    out: list[dict[str, str]] = []
    if not spec.identity_read_enforced:
        out.append({"family": "identity_read", "detail":
                    "cross-owner record reads granted"})
    if not spec.identity_mutation_enforced:
        out.append({"family": "identity_mutation", "detail":
                    "cross-owner record mutations granted"})
    if spec.checkout_impl == "client-total":
        out.append({"family": "price", "detail":
                    "charge follows the client-supplied total"})
    for wf_id in spec.workflows:
        key = wf_id["workflow_id"]
        if not spec.workflow_identity_enforced.get(key, True):
            out.append({"family": "workflow_identity", "detail":
                        f"unauthorized approver accepted on {key}"})
        if not spec.order_enforced.get(key, True):
            out.append({"family": "workflow_order", "detail":
                        f"out-of-chain transition accepted on {key}"})
    if spec.spend_impl in ("no-cap", "per-request"):
        out.append({"family": "spend", "detail":
                    f"spend cap {spec.spend_impl}: cumulative "
                    f"limit not enforced"})
    if spec.grant_impl == "replayable":
        out.append({"family": "grant", "detail":
                    "authorization token replayable after use"})
    return out


def invariant_families(spec: LabSpec) -> list[str]:
    """All invariant families the deployment exercises, defective or
    secured. Secured lookalikes belong to the same invariant family."""
    return sorted(ENGINE_FAMILY)


@dataclass
class FamilyScore:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    # Re-confirmations of an already-counted defect. Under the L8 §4
    # rule one defect is one unique finding regardless of how many
    # probes confirmed it, so a repeat adds here, never to tp.
    duplicate_confirmations: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0


def score_instance(
    spec: LabSpec, confirmed: list[dict[str, Any]],
) -> dict[str, Any]:
    """Score one investigation against one deployment.

    `confirmed` is a list of {"family": <engine family label>,
    "hypothesis_id": ..., "path": <probed path, optional>} entries for
    the investigation's confirmed hypotheses. The probed path (taken
    from the experiment's observation-derived probe plan, the same
    convention the engine's own benchmark uses) disambiguates the two
    lab sub-families the engine reports under one label:
    IDENTITY_BOUNDARY findings probing the mutate segment attribute to
    identity_mutation, everything else to identity_read. Without a
    path, the finding attributes to whichever sub-family is defective
    (identity_read first); with the path present, attribution is
    observation-derived and never label-fed.

    Engine family None (e.g. a grant finding from a future engine)
    scores against the lab's grant family.
    """
    defects = defects_for(spec)
    defective: set[str] = {d["family"] for d in defects}
    scores = {family: FamilyScore() for family in ENGINE_FAMILY}
    matched: dict[str, list[dict[str, Any]]] = {}
    for finding in confirmed:
        engine_family = str(finding.get("family", ""))
        lab_family = _lab_family_for(
            engine_family, path=finding.get("path"), spec=spec)
        if lab_family is None:
            continue
        if lab_family in defective:
            if scores[lab_family].tp == 0:
                scores[lab_family].tp += 1
            else:
                scores[lab_family].duplicate_confirmations += 1
            matched.setdefault(lab_family, []).append(finding)
        else:
            scores[lab_family].fp += 1
            matched.setdefault(lab_family, []).append(finding)
    for lab_family in defective:
        if not matched.get(lab_family):
            scores[lab_family].fn += 1
    return {
        "instance_id": spec.instance_id,
        "families": {
            family: {
                "tp": score.tp, "fp": score.fp, "fn": score.fn,
                "precision": score.precision,
                "recall": score.recall,
            }
            for family, score in scores.items()
        },
        "duplicate_confirmations": {
            family: score.duplicate_confirmations
            for family, score in scores.items()
        },
        "defect_count": len(defects),
        "confirmed_count": len(confirmed),
    }


def _lab_family_for(
    engine_family: str, path: str | None = None,
    spec: LabSpec | None = None,
) -> str | None:
    if engine_family == "IDENTITY_BOUNDARY":
        if spec is not None and path:
            if spec.mutate_segment and spec.mutate_segment in path:
                return "identity_mutation"
            return "identity_read"
        if spec is not None:
            # defects_for returns descriptors, not family strings.
            read_defective = any(
                d["family"] == "identity_read"
                for d in defects_for(spec))
            return "identity_read" if read_defective else (
                "identity_mutation")
    for lab_family, mapped in ENGINE_FAMILY.items():
        if mapped is not None and mapped == engine_family:
            return lab_family
    return None