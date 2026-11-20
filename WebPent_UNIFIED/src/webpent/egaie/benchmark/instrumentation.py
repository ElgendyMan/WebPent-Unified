"""Benchmark instrumentation: strategy-comparison traces.

Derives a machine-readable, per-run trace from a completed
InvestigationState so that strategy-fairness questions are answerable
from raw logs alone:

- what candidates entered the pool, and at which round (proposal_log);
- which experiments were executed, in what order, and with what
  outcomes (decisions + experiment_outcomes);
- whether the round budget ever bound (budget_binding);
- whether the same experiment signature was executed twice
  (duplicate_experiments);
- the terminal reason (why the run stopped).

`compare_traces` summarizes two strategies over the same instance:
executed-set overlap (Jaccard), order divergence (Kendall-tau style
pairwise disagreement on shared ids), and confirmed-set overlap.

This module is observational only: it reads states and never drives
discovery, never touches targets, and never sees hidden labels.
"""
from __future__ import annotations

from typing import Any

from webpent.egaie.schemas import InvestigationState

EXECUTED_OUTCOMES = ("confirmed", "clean", "inconclusive", "blocked")


def run_trace(state: InvestigationState, budget: int) -> dict[str, Any]:
    executed = [
        exp.experiment_id for exp in state.experiments
        if state.experiment_outcome(exp.experiment_id) in EXECUTED_OUTCOMES
    ]
    outcome_tally: dict[str, int] = {}
    for exp in state.experiments:
        outcome = state.experiment_outcome(exp.experiment_id)
        if outcome:
            outcome_tally[outcome] = outcome_tally.get(outcome, 0) + 1
    # a signature is what the experiment actually does (family + probe
    # + step plan), so two distinct experiment ids doing the same work
    # surface here as duplicates
    signatures: list[str] = []
    for exp in state.experiments:
        if exp.experiment_id in executed:
            signatures.append(_signature(exp))
    duplicates = len(signatures) - len(set(signatures))
    confirmed = sorted(
        exp.experiment_id for exp in state.experiments
        if state.experiment_outcome(exp.experiment_id) == "confirmed"
    )
    return {
        "candidate_pool_size": len(state.experiments),
        "proposals": [
            {"round": entry.get("round"), "count": len(entry.get(
                "experiment_ids", []))}
            for entry in state.proposal_log
        ],
        "proposal_events": len(state.proposal_log),
        "executed_order": executed,
        "executed_count": len(executed),
        "rounds_used": state.round,
        "budget": budget,
        "budget_binding": state.round >= budget,
        "terminal_reason": state.terminal_reason,
        "outcome_tally": outcome_tally,
        "confirmed": confirmed,
        "duplicate_experiments": duplicates,
        "signature_examples": sorted(set(signatures)),
    }


def compare_traces(
    trace_a: dict[str, Any], trace_b: dict[str, Any]
) -> dict[str, Any]:
    set_a = set(trace_a["executed_order"])
    set_b = set(trace_b["executed_order"])
    union = set_a | set_b
    order_a = [e for e in trace_a["executed_order"] if e in set_b]
    order_b = [e for e in trace_b["executed_order"] if e in set_a]
    discordant = 0
    for i, j in zip(order_a, order_b):
        if i != j:
            discordant += 1
    return {
        "executed_overlap_jaccard": (
            len(set_a & set_b) / len(union) if union else 1.0),
        "shared_executed": len(set_a & set_b),
        "only_a": len(set_a - set_b),
        "only_b": len(set_b - set_a),
        "order_divergence": discordant,
        "same_order": order_a == order_b,
        "confirmed_overlap": len(
            set(trace_a["confirmed"]) & set(trace_b["confirmed"])),
        "same_confirmed_set": (
            trace_a["confirmed"] == trace_b["confirmed"]),
    }


def _signature(exp: Any) -> str:
    try:
        payload = json_dumps({
            "family": exp.family,
            "hypothesis": exp.hypothesis_id,
            "context": list(exp.context or ()),
        })
    except (AttributeError, TypeError):
        payload = exp.experiment_id
    return payload


def json_dumps(obj: Any) -> str:
    import json
    return json.dumps(obj, sort_keys=True, default=str)
