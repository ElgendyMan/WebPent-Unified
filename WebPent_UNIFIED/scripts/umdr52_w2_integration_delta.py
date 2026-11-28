#!/usr/bin/env python3
"""UM-DR-52 W2 closeout — the W1→W2 integration delta (measured).

Question (§4 closeout): does the behavioral layer actually feed the
adaptive selection — i.e., does the ON brain (W3 formula + behavioral
terms) select a DIFFERENT experiment set / order than the declared
info-gain fallback, on the approved lab fixture?

Two surfaces, both measured, both reported:

* pool surface — the approved fixture hypothesis pool (6 hypotheses,
  each carrying a differential-experiment design) ranked OFF (declared
  info_gain) vs ON (brain_priority with behavioral terms). This is the
  same pool whose ORDER delta W1 proved, now measured as the ADAPTIVE
  SELECTION's input.
* planner surface — plan_experiments(model) (the fixture emits 2
  plans; too small to flip top-k membership, reported as-is).

Writes deliverables/umdr52/W2_INTEGRATION_DELTA.json and
deliverables/umdr52/EXPERIMENT_ECONOMICS.json (DECLARED fixture
economics of the ON-selected set — labeled declared, not field).
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def _pool_plans():
    """The approved-lab pool as experiment plans (differential triples)."""
    from tests.test_umdr46_phase_a_skg import BASE, _lab_state
    from webpent.production.hypothesis_adapter import canonical_hypothesis

    def mk(hid: str, vc: str, conf: float, target: str, ig: float | None):
        return canonical_hypothesis(
            id=uuid5(NAMESPACE_URL, f"umdr52w2m:{hid}"),
            statement=f"W2 integration experiment {hid}",
            vuln_class=vc,
            origin="heuristic",
            origin_detail="umdr52 w2 integration",
            target_url=target,
            expected_behavior="sanctioned path enforces its preconditions",
            negative_control="replay through the sanctioned state",
            deterministic_match=False,
            confidence_score=conf,
            info_gain=ig,
        )

    hyps = [
        mk("h-fasttrack", "idor", 0.55, f"{BASE}/api/orders/123/fasttrack", 0.2),
        mk("h-invoice-read", "idor", 0.50, f"{BASE}/api/invoices/900", 0.15),
        mk("h-transfer", "mass_assignment", 0.48, f"{BASE}/api/transfer", 0.3),
        mk("h-profile-write", "auth_bypass", 0.45, f"{BASE}/api/profile", 0.1),
        mk("h-order-skip", "business_logic", 0.52, f"{BASE}/api/orders/123/status", 0.35),
        mk("h-list-read", "idor", 0.42, f"{BASE}/api/orders", 0.05),
    ]
    plans = [{
        "plan_id": str(h.id),
        "experiment_family": str(h.vuln_class),
        "target": {"endpoint_path": str(h.target_url)},
        "info_gain": float(h.info_gain) if h.info_gain is not None else None,
        "confidence": float(h.confidence_score),
        "_hyp": h,
    } for h in hyps]
    return plans, BASE


def main() -> int:
    from tests.test_umdr46_phase_a_skg import _lab_state
    from webpent.researcher.adaptive_engine import (
        ExperimentLedger, ExperimentRecord,
        experiment_economics, select_adaptive,
    )
    from webpent.researcher.experiment_planner import plan_experiments
    from webpent.appmodel.skg import build_security_knowledge_graph
    from webpent.production.brain_engine import (
        build_brain_context, estimate_priority_inputs, priority_formula,
    )

    plans, BASE = _pool_plans()
    planner_plans = plan_experiments(
        build_security_knowledge_graph(_lab_state()))

    ctx = build_brain_context(_lab_state())
    if not ctx.built:
        print("CONTEXT BUILD FAILED:", ctx.error)
        return 1

    def brain_score(plan: dict) -> float:
        inputs = estimate_priority_inputs(plan["_hyp"], ctx)
        return priority_formula(**inputs)

    ledger = ExperimentLedger()  # empty: first-run selection, guard no-op

    off_ranked = [p["plan_id"] for p in sorted(
        plans, key=lambda p: (-(p["info_gain"] or 0.0), p["plan_id"]))]
    on_ranked = [p["plan_id"] for p in sorted(
        plans, key=lambda p: (-brain_score(p), p["plan_id"]))]

    off_sel = [p["plan_id"] for p in select_adaptive(
        plans, ledger, score_fn=lambda p: p["info_gain"] or 0.0, k=3)]
    on_sel = [p["plan_id"] for p in select_adaptive(
        plans, ledger, score_fn=brain_score, k=3)]

    order_changed = off_ranked != on_ranked
    selection_changed = off_sel != on_sel

    paths = {p["plan_id"]: str(p["target"]["endpoint_path"]) for p in plans}
    backing_rows = {
        paths[pid]: [round(v, 4) for v in ctx.behavioral.backing_for(
            paths[pid] if paths[pid].startswith("http")
            else f"{BASE}{paths[pid].rsplit('/', 1)[0]}")]
        for pid in on_ranked[:1]}
    backing_rows.update({
        paths[pid]: [round(v, 4) for v in ctx.behavioral.backing_for(
            paths[pid] if paths[pid].startswith("http") else f"{BASE}{paths[pid]}")]
        for pid in paths})

    verdict = {
        "schema": "umdr52-w2-integration-delta/1.1.0",
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "fixture": "tests.test_umdr46_phase_a_skg._lab_state (approved lab)",
        "pool_plans": len(plans),
        "planner_plans": len(planner_plans),
        "off_full_rank": off_ranked,
        "on_full_rank": on_ranked,
        "off_selection_k3": off_sel,
        "on_selection_k3": on_sel,
        "on_scores": {p["plan_id"]: round(brain_score(p), 6) for p in plans},
        "declared_info_gains": {p["plan_id"]: p["info_gain"] for p in plans},
        "behavioral_backing(target=[density,contradiction,invariant])":
            backing_rows,
        "rank_order_changed": order_changed,
        "selection_changed": selection_changed,
        "planner_surface_note": (
            "plan_experiments on this fixture emits %d plans — the "
            "top-k membership cannot flip with a 2-plan pool; the pool "
            "surface above is the measured integration surface."
            % len(planner_plans)),
        "integration": {
            "question": "does the W1 behavioral evidence, through the W3 "
                        "formula, change WHICH experiments W2 selects "
                        "and in WHAT order?",
            "status": "VERIFIED" if (selection_changed or order_changed)
            else "FAILED — selection and order identical",
        },
    }
    out = REPO / "deliverables/umdr52/W2_INTEGRATION_DELTA.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(verdict, indent=2, default=str) + "\n")
    print(json.dumps(verdict["integration"], indent=1))
    print("OFF rank:", [p[:13] for p in off_ranked])
    print("ON  rank:", [p[:13] for p in on_ranked])
    print("OFF sel k3:", [p[:13] for p in off_sel])
    print("ON  sel k3:", [p[:13] for p in on_sel])

    # DECLARED economics of the ON-selected set (fixture-level, labeled
    # declared — field economics remain open until W3 campaigns).
    led = ExperimentLedger()
    by_id = {p["plan_id"]: p for p in plans}
    for pid in on_ranked:
        p = by_id[pid]
        led.record(ExperimentRecord(
            experiment_sig=pid,
            cell=str(p["target"]["endpoint_path"]),
            family=str(p["experiment_family"]),
            outcome="inconclusive",   # no field run yet — declared, not claimed
            info_gained=float(p["info_gain"] or 0.0),
            requests=3,               # the planner's declared triple cost
        ))
    econ = experiment_economics(led)
    econ["scope_note"] = (
        "DECLARED fixture economics of the ON-ranked set (declared "
        "info_gain + the planner's 3-request differential cost) — "
        "field economics require W3 campaigns and are NOT claimed here.")
    econ_out = REPO / "deliverables/umdr52/EXPERIMENT_ECONOMICS.json"
    econ_out.write_text(json.dumps(econ, indent=2, default=str) + "\n")
    print("wrote", out, "and", econ_out)
    return 0 if (selection_changed or order_changed) else 1


if __name__ == "__main__":
    raise SystemExit(main())
