"""L7 Step 6: failure-driven analysis on the DEV lab corpus.

Runs every strategy configuration (A-D) on every DEV instance, scores
the confirmed findings against the lab's ground truth, and classifies
the cause of every false negative:

- observations: reconnaissance never recorded the surface the
  invariant lives on, so no generator could see it;
- relationship_inference: the surface was observed but the
  relationships the generator needs (owner, identity correlation)
  were never inferred;
- hypothesis_generation: the relationships existed but no generator
  covers the invariant family (a mechanism gap, not a tuning miss);
- selection: a hypothesis existed with an executable plan but the
  scheduler never selected its experiment within budget;
- interpretation: the experiment executed but the oracle returned
  clean/inconclusive on evidence that should have confirmed;
- classification_proof: the oracle confirmed but ground truth did not
  attribute the finding to the defect.

The output is machine-readable (docs/l7_failure_analysis.json) and is
the only justification this step accepts for engine changes. Held-out
corpus is never touched.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from webpent.egaie import discovery_runner as dr
from webpent.egaie.benchmark.strategies import (
    STRATEGY_NAMES,
    build_strategy_orchestrator,
)
from webpent.labsuite import corpus, evaluator
from webpent.labsuite.lab_target import LabTarget

MAX_ROUNDS = 96
OUT_PATH = Path(__file__).resolve().parents[1] / "docs" / (
    "l7_failure_analysis.json")

FAMILY_STAGE = {
    "IDENTITY_BOUNDARY": ("identity_read", "identity_mutation"),
    "PRICE_INTEGRITY": ("price",),
    "WORKFLOW_IDENTITY": ("workflow_identity",),
    "WORKFLOW_ORDER": ("workflow_order",),
    "BOUNDARY_LIMIT": ("spend",),
    "GRANT_REPLAY": ("grant",),
}


def hypothesis_paths(result: Any, port: Any) -> dict[str, set[str]]:
    """hypothesis_id -> set of candidate-step paths of its plans."""
    out: dict[str, set[str]] = {}
    for h in result.hypotheses:
        paths: set[str] = set()
        for e in result.experiments:
            if e.hypothesis_id != h.hypothesis_id:
                continue
            try:
                plan = port.plan_for(e.signature)
            except KeyError:
                continue
            paths.update(
                s.path for s in plan.steps if s.purpose == "candidate")
        out[h.hypothesis_id] = paths
    return out


def confirmed_entries(
    result: Any, port: Any,
) -> list[dict[str, Any]]:
    """Confirmed findings with the observation-derived probed path
    (the candidate step of the registered probe plan), in the exact
    convention the evaluator documents for sub-family attribution."""
    out = []
    for h in result.hypotheses:
        if h.status.value != "confirmed":
            continue
        path = None
        for e in result.experiments:
            if e.hypothesis_id != h.hypothesis_id:
                continue
            try:
                plan = port.plan_for(e.signature)
            except KeyError:
                continue
            for step in plan.steps:
                if step.purpose == "candidate":
                    path = step.path
                    break
            break
        out.append({
            "family": h.family,
            "hypothesis_id": h.hypothesis_id,
            "path": path,
        })
    return out


def classify_cause(
    result: Any, port: Any, lab_family: str, spec: Any,
) -> dict[str, Any]:
    """Why did this lab family miss this defect?

    The two identity sub-families share the engine's IDENTITY_BOUNDARY
    family; a hypothesis belongs to the mutation sub-family when its
    plan's candidate path hits the deployment's mutate segment."""
    engine_families = [
        family for family, lab in FAMILY_STAGE.items()
        if lab_family in lab
    ]
    hyps = [
        h for h in result.hypotheses
        if h.family in engine_families
    ]
    if lab_family == "identity_mutation":
        paths = hypothesis_paths(result, port)
        hyps = [
            h for h in hyps
            if any(spec.mutate_segment in p for p in paths[
                h.hypothesis_id])
        ]
    if not hyps:
        return {
            "cause": "hypothesis_generation",
            "hypotheses": 0, "experiments": 0,
        }
    exps = [
        e for e in result.experiments
        if e.hypothesis_id in {h.hypothesis_id for h in hyps}
    ]
    if not exps:
        return {
            "cause": "selection",
            "hypotheses": len(hyps), "experiments": 0,
        }
    outcomes = [
        result.experiment_outcomes.get(e.experiment_id, "missing")
        for e in exps
    ]
    confirmed = [o for o in outcomes if o == "confirmed"]
    if confirmed:
        return {
            "cause": "classification_proof",
            "hypotheses": len(hyps), "experiments": len(exps),
            "outcomes": outcomes,
        }
    return {
        "cause": "interpretation",
        "hypotheses": len(hyps), "experiments": len(exps),
        "outcomes": outcomes,
    }


def main() -> int:
    runs: list[dict[str, Any]] = []
    for strategy in STRATEGY_NAMES:
        for spec in corpus.dev_block():
            with LabTarget(spec) as target:
                port = dr._build_port(target, spec.seed)
                state = dr._seed_state(target, spec.instance_id)
                orch = build_strategy_orchestrator(port, strategy)
                result = orch.run(state, max_rounds=MAX_ROUNDS)
            confirmed = confirmed_entries(result, port)
            score = evaluator.score_instance(spec, confirmed)
            defects = evaluator.defects_for(spec)
            false_negatives = []
            for defect in defects:
                lab_family = defect["family"]
                family_score = score["families"].get(lab_family)
                if family_score is None or family_score["fn"] != 1:
                    continue
                engine_family = next(
                    (f for f, lab in FAMILY_STAGE.items()
                     if lab_family in lab), None)
                cause = classify_cause(
                    result, port, lab_family, spec)
                false_negatives.append({
                    "lab_family": lab_family,
                    "detail": defect["detail"],
                    "engine_family": engine_family,
                    **cause,
                })
            runs.append({
                "strategy": strategy,
                "instance_id": spec.instance_id,
                "defect_count": score["defect_count"],
                "confirmed_count": len(confirmed),
                "families": score["families"],
                "false_negatives": false_negatives,
            })
            print(
                f"{strategy:22s} {spec.instance_id}: "
                f"TP-confirmed={len(confirmed)} "
                f"defects={score['defect_count']} "
                f"FN={len(false_negatives)}")
    summary: dict[str, dict[str, int]] = {}
    for run in runs:
        for fn in run["false_negatives"]:
            key = (fn["cause"])
            summary.setdefault(fn["lab_family"], {})
            summary[fn["lab_family"]][key] = (
                summary[fn["lab_family"]].get(key, 0) + 1)
    document = {
        "analysis_version": "l7-failure-analysis-1",
        "corpus": "dev_block (101-104) only; held-out untouched",
        "max_rounds": MAX_ROUNDS,
        "runs": runs,
        "fn_causes_by_family": summary,
    }
    OUT_PATH.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    print(f"wrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
