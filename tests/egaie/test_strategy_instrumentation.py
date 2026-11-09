"""L7 strategy instrumentation: red-first regression tests.

These pin the facts that make strategy comparisons auditable from raw
logs:

- every proposer invocation is recorded in the state's proposal_log with
  its round and candidate ids;
- the adaptive and fixed strategies share ONE candidate pool and ONE
  executed set (their only measured difference is execution order);
- the proposer-free ablation is diagnostically empty: it generates no
  candidates, executes nothing, and never touches the target — which is
  exactly why it cannot serve as a fair baseline.

Each strategy runs against its own fresh instance: server state is
mutated by experiments, so reusing a target across strategies would
contaminate the comparison.
"""
from __future__ import annotations

import sys
from collections import Counter
from typing import Any

from webpent.egaie import discovery_runner as dr
from webpent.egaie.benchmark.instrumentation import compare_traces, run_trace
from webpent.egaie.eval_instances import InstanceTarget, generate_instance

BUDGET = 64


def _run(mode: str, seed: int = 41) -> tuple[Any, Any, dict[str, Any]]:
    spec = generate_instance(seed, blind=True)
    with InstanceTarget(spec) as target:
        port = dr._build_port(target, seed)
        state = dr._seed_state(target, dr._version_ids(seed)[0])
        state = dr._build_orchestrator(port, mode).run(
            state, max_rounds=BUDGET)
        trace = run_trace(state, BUDGET)
        requests = target._request_count
    return spec, state, {**trace, "requests": requests}


# --------------------------------------------------------- proposal log

def test_proposal_log_records_round_tagged_candidates() -> None:
    _, state, trace = _run("adaptive")
    assert trace["proposal_events"] >= 1, (
        "no proposal events recorded; comparisons cannot be audited")
    pool_ids = {exp.experiment_id for exp in state.experiments}
    logged: set[str] = set()
    for entry in state.proposal_log:
        assert isinstance(entry.get("round"), int)
        assert entry["round"] >= 0
        logged.update(entry.get("experiment_ids", []))
    assert logged == pool_ids, (
        "proposal_log does not account for the full candidate pool")


# ------------------------------------------- adaptive vs fixed parity

def test_adaptive_and_fixed_share_pool_and_executed_set() -> None:
    _, _, trace_a = _run("adaptive")
    _, _, trace_f = _run("fixed")
    comparison = compare_traces(trace_a, trace_f)
    assert comparison["only_a"] == 0
    assert comparison["only_b"] == 0
    assert comparison["executed_overlap_jaccard"] == 1.0
    assert trace_a["candidate_pool_size"] == trace_f["candidate_pool_size"]
    assert trace_a["confirmed"] == trace_f["confirmed"], (
        "identical pools and executed sets must yield identical findings")


def test_fixed_differs_from_adaptive_only_in_order() -> None:
    _, _, trace_a = _run("adaptive")
    _, _, trace_f = _run("fixed")
    comparison = compare_traces(trace_a, trace_f)
    # with a shared proposer the two schedulers may still happen to pick
    # the same order on a small instance; what must NEVER differ is the
    # executed set or the confirmed set
    assert comparison["same_confirmed_set"]
    assert comparison["executed_overlap_jaccard"] == 1.0


# --------------------------------------------- ablation is diagnostic only

def test_ablation_generates_and_executes_nothing() -> None:
    _, state, trace = _run("ablation")
    assert trace["candidate_pool_size"] == 0
    assert trace["executed_count"] == 0
    assert trace["proposal_events"] == 0
    assert trace["terminal_reason"] == "objectives_complete"
    assert state.proposal_log == []
    assert trace["requests"] == 0, (
        "proposer-free ablation still issued target requests")
