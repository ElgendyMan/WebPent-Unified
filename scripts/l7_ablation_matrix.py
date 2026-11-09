"""L7 Step 7: full ablation matrix (section 4 metrics, all budgets).

Runs all four strategy configurations on every lab instance (DEV
101-104, HELD-OUT 201-203/211-213, negatives 301-302) at round budgets
16/48/96, and writes docs/l7_ablation_matrix.json with:

- per instance x family x strategy TP/FP/FN, precision/recall,
  confirmed count (ground truth applied only AFTER the investigation
  finished; the probed path comes from the registered probe plan);
- per run: requests executed, wall-clock seconds, requests and seconds
  per confirmed finding, hypotheses generated, outcome tally,
  duplicate experiments, seal/replay validity over confirmed findings,
  terminal reason, budget binding;
- pairwise cross-strategy comparisons (A vs B/C/D): executed-set
  overlap, order divergence, confirmed-set overlap.

Multiple runs of one instance are NOT counted as independent
applications: each line states its strategy, instance and budget.
The JSON carries the standing honesty note: these are synthetic
loopback results and support no real-world generalization claim.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from l7_failure_analysis import confirmed_entries

from webpent.egaie import discovery_runner as dr
from webpent.egaie.benchmark import instrumentation
from webpent.egaie.benchmark.provenance import (
    findings_provenance,
)
from webpent.egaie.benchmark.strategies import (
    STRATEGY_NAMES,
    build_strategy_orchestrator,
)
from webpent.labsuite import corpus, evaluator
from webpent.labsuite.lab_target import LabTarget

BUDGETS = (16, 48, 96)
OUT_PATH = Path(__file__).resolve().parents[1] / "docs" / (
    "l7_ablation_matrix.json")

BLOCKS = (
    ("dev", corpus.dev_block()),
    ("held-out", corpus.heldout_block()),
    ("negative", corpus.negative_block()),
)


def seal_summary(state: Any) -> dict[str, Any]:
    """Seal/replay validity over the run's confirmed findings."""
    records = findings_provenance(state)
    bundle_count = sum(
        r["seal_summary"]["bundle_count"] for r in records)
    return {
        "confirmed_findings": len(records),
        "bundle_count": bundle_count,
        "all_replay_valid": (
            all(r["seal_summary"]["all_replay_valid"]
                for r in records) if records else None),
    }


def run_one(
    strategy: str, spec: Any, budget: int,
) -> dict[str, Any]:
    import time as _time
    with LabTarget(spec) as target:
        port = dr._build_port(target, spec.seed)
        state = dr._seed_state(target, spec.instance_id)
        orch = build_strategy_orchestrator(port, strategy)
        started = _time.perf_counter()
        result = orch.run(state, max_rounds=budget)
        seconds = _time.perf_counter() - started
    requests = len(port.ledger)
    confirmed = confirmed_entries(result, port)
    score = evaluator.score_instance(spec, confirmed)
    # The orchestrator returns a finalized copy of the state; the seed
    # object it was handed never carries executions. Traces MUST be
    # built from the returned state (red-first pinned in
    # tests/egaie/test_ablation_strategies.py).
    trace = instrumentation.run_trace(result, budget)
    seal = seal_summary(result)
    confirmed_count = len(confirmed)
    status_tally: dict[str, int] = {}
    for h in result.hypotheses:
        status_tally[h.status.value] = (
            status_tally.get(h.status.value, 0) + 1)
    return {
        "strategy": strategy,
        "instance_id": spec.instance_id,
        "block": None,  # filled by caller
        "budget": budget,
        "requests": requests,
        "seconds": round(seconds, 3),
        "confirmed_count": confirmed_count,
        "requests_per_confirmed": (
            round(requests / confirmed_count, 1)
            if confirmed_count else None),
        "seconds_per_confirmed": (
            round(seconds / confirmed_count, 3)
            if confirmed_count else None),
        "hypotheses_generated": len(result.hypotheses),
        "status_tally": status_tally,
        "outcome_tally": trace["outcome_tally"],
        "executed_count": trace["executed_count"],
        "duplicate_experiments": trace["duplicate_experiments"],
        "terminal_reason": trace["terminal_reason"],
        "budget_binding": trace["budget_binding"],
        "rounds_used": trace["rounds_used"],
        "seal": seal,
        "families": score["families"],
        "defect_count": score["defect_count"],
        "trace": trace,
    }


def main() -> int:
    runs: list[dict[str, Any]] = []
    traces: dict[tuple[str, str, int], dict[str, Any]] = {}
    for block_name, block in BLOCKS:
        for spec in block:
            for strategy in STRATEGY_NAMES:
                for budget in BUDGETS:
                    run = run_one(strategy, spec, budget)
                    run["block"] = block_name
                    runs.append(run)
                    traces[(strategy, spec.instance_id, budget)] = (
                        run["trace"])
                    print(
                        f"{strategy:22s} {spec.instance_id} "
                        f"b={budget:3d}: confirmed="
                        f"{run['confirmed_count']} "
                        f"requests={run['requests']} "
                        f"({run['seconds']:.1f}s)",
                        flush=True)
                    run.pop("trace")
    comparisons = []
    for block_name, block in BLOCKS:
        for spec in block:
            for budget in BUDGETS:
                anchor = traces[("adaptive", spec.instance_id, budget)]
                for other in STRATEGY_NAMES:
                    if other == "adaptive":
                        continue
                    trace = traces[(other, spec.instance_id, budget)]
                    comparisons.append({
                        "instance_id": spec.instance_id,
                        "block": block_name,
                        "budget": budget,
                        "pair": ("adaptive", other),
                        **instrumentation.compare_traces(
                            anchor, trace),
                    })
    document = {
        "matrix_version": "l7-ablation-matrix-1",
        "budgets": list(BUDGETS),
        "corpus_blocks": [name for name, _ in BLOCKS],
        "note": (
            "Synthetic loopback lab results only. They measure "
            "strategy behaviour on this corpus and support NO claim "
            "of real-world bug-hunting generalization. Ground truth "
            "applied only after each investigation finished; multiple "
            "runs of one instance are not independent applications."),
        "runs": runs,
        "cross_strategy_comparisons": comparisons,
    }
    OUT_PATH.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    print(f"wrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
