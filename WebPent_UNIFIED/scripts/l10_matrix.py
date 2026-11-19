"""L10 §Phase 5: budget-matched strategy matrix over the generation-3
surfaces.

Runs five fair configurations from the mission's ablation matrix on
the L10 DEV block (consign, permit) at round budgets 2/4/8/16/32,
and writes docs/l10_matrix_dev.json. All five generate AND execute
candidate experiments through the SAME observation contract,
validation oracle, sealed ProofBundle port, ActionAuthority /
ActionExecutor path, idempotency discipline and request budgets;
only candidate-generation/planning/selection logic differs:

  l8-engine    (A) the L8 adaptive engine unchanged — no planner, no
               remediation hook; the pre-L9 byte-identical loop;
  l10-planner  (B) the L10 stateful planner: declared preconditions,
               dependency-graph setup derivation, remediated re-runs,
               PLUS the phase-4 workflow discovery attached (schema-
               silent surfaces only) and the phase-5 selection
               integrations (prerequisite availability, hypothesis
               confidence, historical outcomes, evidence quality,
               reversibility, remaining budget);
  planner-no-prereq
               (C) the same planner with the prerequisite-reasoning
               ablation flag off and NO discovery attached — candidate
               generation identical to B, blocked outcomes never
               remediated, no schema-silent probing;
  fixed-prereq (D) the independently generated fixed prerequisite
               strategy (webpent.egaie.benchmark.fixed_prerequisites):
               a static per-family recipe list, written without
               reading the planner's derivation logic;
  planner-no-infogain
               (E) B's planner and discovery with information-gain
               SELECTION disabled (ProposalOrderSelector): hypothesis
               generation and state reasoning preserved, selection
               takes the proposal order verbatim.

Metric units match the L9 matrix (requests = engine observations;
tp/fp/fn against the ground truth, applied only after the run
finished), plus the phase-4 discovery accounting (probes attempted /
budget / contradictions) for the strategies that attach discovery.

Sequencing honesty: the DEV block is measured first; the held-out
block is measured afterwards, once, and its outcomes can no longer
influence anything. These are synthetic loopback results over
independently implemented fixture applications: they support no
real-world generalization claim.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from l7_failure_analysis import confirmed_entries
from l8_discovery_matrix import (
    BUDGETS,
    DOCS,
    score_unique,
    seal_summary,
)

from webpent.appsuite import corpus
from webpent.egaie import discovery_runner as dr
from webpent.egaie.benchmark import instrumentation
from webpent.egaie.benchmark.fixed_prerequisites import (
    FixedPrerequisiteRemediator,
)
from webpent.egaie.planner import PlannerConfig, StatefulPlanner
from webpent.egaie.prerequisites import (
    PreconditionStatus,
    UnattainableEffect,
)
from webpent.egaie.selection import ProposalOrderSelector
from webpent.egaie.workflow_discovery import WorkflowDiscovery

L10_STRATEGIES = (
    "l8-engine", "l10-planner", "planner-no-prereq",
    "fixed-prereq", "planner-no-infogain")

BLOCKS = {
    "dev": corpus.l10_dev_block,
}


def _planner_tally(orch: Any) -> dict[str, int]:
    """The §6 prerequisite accounting for the strategy that ran.

    B, C and E read the planner's ledger tally directly (B and E
    also carry the workflow_discovery accounting). D reads its own
    fixed strategy's tally. A declares nothing."""
    planner = getattr(orch, "planner", None)
    if planner is not None:
        return planner.ledger.tally()
    remediator = getattr(orch, "remediator", None)
    if remediator is not None:
        return remediator.tally
    return {}


def _prerequisite_status_tally(orch: Any) -> dict[str, int]:
    """Precondition statuses grouped by ledger status, with the
    verdict-effect discipline attached: every UNATTAINABLE entry
    must carry NEVER_A_VERDICT (§3), so the count also reports how
    many do."""
    planner = getattr(orch, "planner", None)
    if planner is None:
        return {}
    tally: dict[str, int] = {}
    never = 0
    unattainable = 0
    for preconds in planner.ledger.entries.values():
        for precond in preconds:
            key = (
                precond.status.value
                if hasattr(precond.status, "value")
                else str(precond.status))
            tally[key] = tally.get(key, 0) + 1
            if precond.status is PreconditionStatus.UNATTAINABLE:
                unattainable += 1
                if (precond.verdict_effect
                        is UnattainableEffect.NEVER_A_VERDICT):
                    never += 1
    if unattainable:
        tally["unattainable_never_a_verdict"] = never
    return tally


def run_one(strategy: str, entry: corpus.SuiteEntry,
            budget: int) -> dict[str, Any]:
    with corpus.open_instance(entry) as target:
        port = dr._build_port(target, entry.seed)
        state = dr._seed_state(target, entry.instance_id)
        orch = dr._build_orchestrator(port, "adaptive")
        if strategy == "l10-planner":
            orch.planner = StatefulPlanner(
                PlannerConfig(), discovery=WorkflowDiscovery())
        elif strategy == "planner-no-prereq":
            orch.planner = StatefulPlanner(PlannerConfig(
                prerequisite_reasoning=False))
        elif strategy == "fixed-prereq":
            orch.remediator = FixedPrerequisiteRemediator()
        elif strategy == "planner-no-infogain":
            orch.planner = StatefulPlanner(
                PlannerConfig(), discovery=WorkflowDiscovery())
            orch.selector = ProposalOrderSelector()
        started = time.perf_counter()
        result = orch.run(state, max_rounds=budget)
        seconds = time.perf_counter() - started
        http_requests = target.request_count
    requests = len(port.ledger)
    confirmed = confirmed_entries(result, port)
    score = score_unique(entry, confirmed)
    trace = instrumentation.run_trace(result, budget)
    status_tally: dict[str, int] = {}
    for h in result.hypotheses:
        status_tally[h.status.value] = (
            status_tally.get(h.status.value, 0) + 1)
    family_pool: dict[str, int] = {}
    for h in result.hypotheses:
        family_pool[h.family] = family_pool.get(h.family, 0) + 1
    return {
        "strategy": strategy,
        "instance_id": entry.instance_id,
        "app": entry.app,
        "variant": entry.variant,
        "budget": budget,
        "requests": requests,
        "http_requests": http_requests,
        "seconds": round(seconds, 3),
        "tp": score["unique_confirmed"],
        "tp_families": score["tp_families"],
        "fp": score["fp"],
        "fn": score["fn"],
        "raw_confirmed": score["raw_confirmed"],
        "confirmed_families": score["confirmed_families"],
        "confirmed_paths": score["confirmed_paths"],
        "requests_per_tp": (
            round(requests / score["unique_confirmed"], 1)
            if score["unique_confirmed"] else None),
        "hypotheses_generated": len(result.hypotheses),
        "hypotheses_by_family": family_pool,
        "status_tally": status_tally,
        "outcome_tally": trace["outcome_tally"],
        "executed_count": trace["executed_count"],
        "duplicate_experiments": trace["duplicate_experiments"],
        "terminal_reason": trace["terminal_reason"],
        "budget_binding": trace["budget_binding"],
        "rounds_used": trace["rounds_used"],
        "seal": seal_summary(result),
        "prerequisites": _planner_tally(orch),
        "prerequisite_statuses": _prerequisite_status_tally(orch),
        "trace": trace,
    }


def aggregate(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Cross-cuts: discovery curves, first-confirmation budgets,
    budget-matched precision/recall/efficiency at the largest
    budget, prerequisite accounting by strategy, discovery activity
    by strategy, and by app."""
    max_budget = max(BUDGETS)
    curves: dict[str, dict[str, Any]] = {}
    for run in runs:
        key = f"{run['strategy']}/{run['instance_id']}"
        slot = curves.setdefault(key, {
            "strategy": run["strategy"],
            "instance_id": run["instance_id"],
            "app": run["app"], "variant": run["variant"],
            "curve": {}, "first_confirmation_budget": None,
        })
        slot["curve"][str(run["budget"])] = run["tp"]
        if run["tp"] >= 1 and (
                slot["first_confirmation_budget"] is None
                or run["budget"] < (
                    slot["first_confirmation_budget"])):
            slot["first_confirmation_budget"] = run["budget"]

    by_strategy: dict[str, dict[str, Any]] = {}
    for strat in L10_STRATEGIES:
        mrun = [
            r for r in runs
            if r["strategy"] == strat and r["budget"] == max_budget]
        tp_total = sum(r["tp"] for r in mrun)
        fp_total = sum(r["fp"] for r in mrun)
        fn_total = sum(r["fn"] for r in mrun)
        req_total = sum(r["requests"] for r in mrun)
        prereq: dict[str, int] = {}
        for r in mrun:
            for key, value in r["prerequisites"].items():
                if isinstance(value, dict):
                    for sub, count in value.items():
                        flat_key = f"{key}.{sub}"
                        prereq[flat_key] = (
                            prereq.get(flat_key, 0) + count)
                else:
                    prereq[key] = prereq.get(key, 0) + value
        inconclusive = sum(
            r["status_tally"].get("blocked", 0)
            + r["status_tally"].get("inconclusive", 0)
            for r in mrun)
        fcb = [
            s["first_confirmation_budget"]
            for s in curves.values()
            if s["strategy"] == strat
            and s["first_confirmation_budget"] is not None]
        by_strategy[strat] = {
            "instances": len(mrun),
            "tp": tp_total, "fp": fp_total, "fn": fn_total,
            "precision": (
                round(tp_total / (tp_total + fp_total), 3)
                if tp_total + fp_total else None),
            "recall": (
                round(tp_total / (tp_total + fn_total), 3)
                if tp_total + fn_total else None),
            "requests": req_total,
            "requests_per_tp": (
                round(req_total / tp_total, 1) if tp_total else None),
            "mean_first_confirmation_budget": (
                round(sum(fcb) / len(fcb), 2) if fcb else None),
            "prerequisites": prereq,
            "blocked_or_inconclusive_hypotheses": inconclusive,
        }

    by_family: dict[str, dict[str, Any]] = {}
    for run in runs:
        if run["budget"] != max_budget:
            continue
        for fam, count in run["hypotheses_by_family"].items():
            slot = by_family.setdefault(fam, {
                "hypotheses": 0, "confirmed": 0})
            slot["hypotheses"] += count
        for fam in run["tp_families"]:
            slot = by_family.setdefault(fam, {
                "hypotheses": 0, "confirmed": 0})
            slot["confirmed"] += 1

    by_app: dict[str, dict[str, Any]] = {}
    for run in runs:
        if run["budget"] != max_budget:
            continue
        slot = by_app.setdefault(run["app"], {
            "tp": 0, "fp": 0, "fn": 0, "runs": 0})
        slot["tp"] += run["tp"]
        slot["fp"] += run["fp"]
        slot["fn"] += run["fn"]
        slot["runs"] += 1

    return {
        "curves": curves,
        "by_strategy": by_strategy,
        "by_family": by_family,
        "by_app": by_app,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "block", choices=sorted(BLOCKS),
        help="which corpus block to measure, in mission order")
    args = parser.parse_args()
    block = BLOCKS[args.block]()

    runs: list[dict[str, Any]] = []
    for entry in block:
        for strategy in L10_STRATEGIES:
            for budget in BUDGETS:
                run = run_one(strategy, entry, budget)
                runs.append(run)
                print(
                    f"{strategy:22s} {entry.instance_id} "
                    f"b={budget:3d}: tp={run['tp']} fp={run['fp']} "
                    f"fn={run['fn']} raw={run['raw_confirmed']} "
                    f"req={run['requests']} "
                    f"prereq={run['prerequisites']} "
                    f"{run['terminal_reason']}")
                sys.stdout.flush()

    agg = aggregate(runs)
    out = {
        "mission": "L10 section 5 — cross-application strategy matrix",
        "phase": args.block,
        "phase_order": (
            "dev measured first; the held-out block is measured "
            "afterwards, once, after the dev block and its analysis "
            "are frozen; its outcomes can no longer influence "
            "anything"),
        "honesty_note": (
            "synthetic loopback results over independently "
            "implemented fixture applications; they support no "
            "real-world generalization claim"),
        "budgets": list(BUDGETS),
        "strategies": list(L10_STRATEGIES),
        "strategy_definitions": {
            "l8-engine": (
                "A: the L8 adaptive engine unchanged — no planner, "
                "no remediation hook"),
            "l10-planner": (
                "B: the L10 stateful planner — declared "
                "preconditions, dependency-graph setup derivation, "
                "remediated re-runs, phase-4 workflow discovery on "
                "schema-silent surfaces, phase-5 selection "
                "integrations"),
            "planner-no-prereq": (
                "C: the same planner with prerequisite reasoning "
                "ablated (no discovery attached) — candidate "
                "generation identical to B, blocked outcomes never "
                "remediated"),
            "fixed-prereq": (
                "D: an independently generated fixed prerequisite "
                "strategy — a static per-family recipe list built "
                "without reading the planner's derivation logic"),
            "planner-no-infogain": (
                "E: B's planner and discovery with information-gain "
                "selection disabled — hypothesis generation and "
                "state reasoning preserved, selection takes the "
                "proposal order verbatim"),
        },
        "metric_units": {
            "requests": "engine observations recorded in the "
                        "observation ledger (one per HTTP exchange "
                        "the engine issued)",
            "http_requests": "every request the serving stack "
                             "answered, including index fetches",
            "tp": "ground-truth defects confirmed (deduplicated: "
                  "one defect = one finding)",
            "fp": "confirmed findings matching no ground-truth "
                  "defect on the instance",
            "fn": "ground-truth defects never confirmed",
            "raw_confirmed": "hypothesis-level confirmations before "
                             "deduplication",
            "prerequisites": "per-strategy accounting of setup "
                             "attempts: the planner's ledger tally "
                             "for B/C/E, the fixed strategy's own "
                             "tally (identified/verified/failed/"
                             "unknown) for D, empty for A",
            "blocked_or_inconclusive_hypotheses": "hypotheses left "
                "blocked/inconclusive — the non-verdict status a "
                "failed setup must always produce (§3)",
        },
        "runs": runs,
        "aggregate": agg,
    }
    DOCS.mkdir(exist_ok=True)
    out_path = DOCS / f"l10_matrix_{args.block}.json"
    out_path.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
