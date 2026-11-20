"""L8 §3: discovery-efficiency matrix over the generation-2 appsuite.

Runs the four strategy configurations on the appsuite instances at
round budgets 2/4/8/16/32 and writes docs/l8_discovery_<block>.json
with the SAME metric units as the L7 ablation matrix:

- requests = engine observations in the ledger (one HTTP exchange
  recorded as one ObservationRecord); http_requests = every request
  the serving stack answered, index fetches included;
- confirmed = hypothesis-level confirmations (NOT deduplicated);
  unique_confirmed = one per ground-truth defect family (§4 dedup:
  one defect is one finding, however often it re-confirms);
- TP/FN/FP against webpent.appsuite.groundtruth.defects_for, applied
  only AFTER the run finished (the ground truth is read off the app's
  own implementation profile, never put on the wire);
- discovery curve = unique confirmed per budget; first-confirmation
  budget = smallest budget whose run holds >= 1 unique confirmed
  finding; requests-per-unique-confirmed at the largest budget.

Sequencing honesty: the DEV block (docvault, market) is measured
FIRST; failure analysis and any engine change (§5) use only DEV runs.
The HELD-OUT block (ticketflow, slots) is measured afterwards, once,
and its outcomes can no longer influence anything; this order is
recorded in each JSON's "phase" field. These are synthetic loopback
results over independently implemented fixture applications: they
support no real-world generalization claim.
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

from webpent.appsuite import corpus
from webpent.appsuite.groundtruth import (
    ENGINE_FAMILY,
    defects_for,
)
from webpent.egaie import discovery_runner as dr
from webpent.egaie.benchmark import instrumentation
from webpent.egaie.benchmark.provenance import (
    findings_provenance,
)
from webpent.egaie.benchmark.strategies import (
    STRATEGY_NAMES,
    build_strategy_orchestrator,
)

BUDGETS = (2, 4, 8, 16, 32)
DOCS = Path(__file__).resolve().parents[1] / "docs"

BLOCKS = {
    "dev": corpus.dev_block,
    "heldout": corpus.heldout_block,
}


def seal_summary(state: Any) -> dict[str, Any]:
    records = findings_provenance(state)
    return {
        "confirmed_findings": len(records),
        "bundle_count": sum(
            r["seal_summary"]["bundle_count"] for r in records),
        "all_replay_valid": (
            all(r["seal_summary"]["all_replay_valid"]
                for r in records) if records else None),
    }


def ground_truth_families(entry: corpus.SuiteEntry) -> list[str]:
    defects = defects_for(entry.app, entry.spec)
    return [ENGINE_FAMILY[d["family"]] for d in defects]


def score_unique(
    entry: corpus.SuiteEntry,
    confirmed: list[dict[str, Any]],
) -> dict[str, Any]:
    """§4 deduplicated scoring: one defect = one unique finding.

    TP counts a ground-truth defect once when ANY confirmed finding
    carries its engine family; repeated confirmations of the same
    defect do not add TP. FP counts every confirmed finding whose
    family matches no ground-truth defect on this instance (which
    includes every confirmation on a clean variant). FN counts the
    defects no confirmed finding covered.
    """
    defect_families = ground_truth_families(entry)
    confirmed_families = [c["family"] for c in confirmed]
    hit: set[str] = set()
    tp = 0
    tp_families: list[str] = []
    for fam in defect_families:
        if fam in confirmed_families and fam not in hit:
            hit.add(fam)
            tp += 1
            tp_families.append(fam)
    fp = sum(
        1 for fam in confirmed_families
        if fam not in set(defect_families))
    fn = len(defect_families) - tp
    return {
        "defects": len(defect_families),
        "unique_confirmed": tp,
        "tp_families": tp_families,
        "fp": fp,
        "fn": fn,
        "raw_confirmed": len(confirmed_families),
        "confirmed_families": confirmed_families,
        "confirmed_paths": sorted(
            c["path"] or "?" for c in confirmed),
    }


def run_one(
    strategy: str, entry: corpus.SuiteEntry, budget: int,
) -> dict[str, Any]:
    with corpus.open_instance(entry) as target:
        port = dr._build_port(target, entry.seed)
        state = dr._seed_state(target, entry.instance_id)
        orch = build_strategy_orchestrator(port, strategy)
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
        "trace": trace,
    }


def aggregate(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Cross-cuts: curves, first-confirmation budgets, budget-matched
    efficiency at the largest budget, by family and by app."""
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
    for strat in STRATEGY_NAMES:
        mrun = [
            r for r in runs
            if r["strategy"] == strat and r["budget"] == max_budget]
        tp_total = sum(r["tp"] for r in mrun)
        fp_total = sum(r["fp"] for r in mrun)
        fn_total = sum(r["fn"] for r in mrun)
        req_total = sum(r["requests"] for r in mrun)
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
        for strategy in STRATEGY_NAMES:
            for budget in BUDGETS:
                run = run_one(strategy, entry, budget)
                runs.append(run)
                print(
                    f"{strategy:22s} {entry.instance_id} "
                    f"b={budget:3d}: tp={run['tp']} fp={run['fp']} "
                    f"fn={run['fn']} raw={run['raw_confirmed']} "
                    f"req={run['requests']} "
                    f"{run['terminal_reason']}")
                sys.stdout.flush()

    agg = aggregate(runs)
    out = {
        "mission": "L8 section 3 — discovery efficiency",
        "phase": args.block,
        "phase_order": (
            "dev measured first; heldout measured after the dev "
            "failure analysis and any engine change it produced"),
        "honesty_note": (
            "synthetic loopback results over independently "
            "implemented fixture applications; they support no "
            "real-world generalization claim"),
        "budgets": list(BUDGETS),
        "strategies": list(STRATEGY_NAMES),
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
        },
        "runs": runs,
        "aggregate": agg,
    }
    DOCS.mkdir(exist_ok=True)
    out_path = DOCS / f"l8_discovery_{args.block}.json"
    out_path.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
