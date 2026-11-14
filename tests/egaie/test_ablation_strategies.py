"""L7 Step 4: four fair ablation configurations, red-first.

Mission section 4 requires strategies that can actually generate and
execute candidate experiments. These tests pin the claims that make
the later budget comparison meaningful:

- every configuration generates hypotheses AND executes experiments
  with recorded outcomes (a zero-request ablation is diagnostic
  evidence of an invalid comparison, never a result);
- no strategy state carries the lab's ground truth: family keys from
  the evaluator's defect roster never appear in serialized state;
- the independent fixed strategy (B) and the observation-driven
  baseline (D) mint their own experiment ids in their own namespaces,
  not the adaptive engine's ``differential:recon:`` namespace;
- every configuration stays silent (zero confirmations) on the fully
  secured negative instance.

Each run gets its own live target: lab workflow state advances on
requests, so strategies must never share an application instance.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from webpent.egaie import discovery_runner as dr
from webpent.egaie.benchmark.strategies import (
    BASELINE_ORIGIN,
    INDEPENDENT_ORIGIN,
    STRATEGY_NAMES,
    build_strategy_orchestrator,
)
from webpent.labsuite import corpus
from webpent.labsuite.lab_target import LabTarget

SRC = Path(__file__).resolve().parents[2] / "src" / "webpent"
RECON_ORIGIN = "differential:recon:"
MAX_ROUNDS = 96


def _run(strategy: str, instance_id: int) -> tuple[Any, Any]:
    """Fresh target, fresh port, fresh state per run."""
    spec = corpus.lab_instance(instance_id)
    with LabTarget(spec) as target:
        port = dr._build_port(target, spec.seed)
        state = dr._seed_state(target, spec.instance_id)
        orch = build_strategy_orchestrator(port, strategy)
        result = orch.run(state, max_rounds=MAX_ROUNDS)
    return result, spec


def _confirmed(result: Any) -> list[str]:
    return [h.family for h in result.hypotheses
            if h.status.value == "confirmed"]


# ------------------------------------------------- generate and execute


def test_every_strategy_generates_and_executes_candidates() -> None:
    """Every configuration must both propose and execute candidates:
    an empty proposer or an empty execution log invalidates the
    comparison rather than measuring it."""
    for strategy in STRATEGY_NAMES:
        result, _spec = _run(strategy, 102)
        assert result.hypotheses, strategy
        assert result.experiments, strategy
        executed = {
            e.experiment_id for e in result.experiments}
        assert len(executed) == len(result.experiments), strategy
        assert result.experiment_outcomes, strategy
        for exp in result.experiments:
            assert exp.experiment_id in result.experiment_outcomes, (
                strategy, exp.experiment_id)
        # The proposal log records every round's proposals.
        assert result.proposal_log, strategy


def test_run_trace_reflects_the_returned_state_not_the_seed() -> None:
    """Red-first for the L8 §1 reproduction finding: the orchestrator
    works on a deterministic copy and returns it, so a trace built
    from the pre-run seed state is silently vacuous (executed_count 0,
    empty outcome tally, empty cross-strategy comparisons) even though
    the run executed dozens of requests. The matrix script and any
    future consumer must derive traces from the RETURNED state; this
    test pins the pitfall itself."""
    from webpent.egaie.benchmark.instrumentation import run_trace

    for strategy in STRATEGY_NAMES:
        spec = corpus.lab_instance(102)
        with LabTarget(spec) as target:
            port = dr._build_port(target, spec.seed)
            seed_state = dr._seed_state(target, spec.instance_id)
            orch = build_strategy_orchestrator(port, strategy)
            result = orch.run(seed_state, max_rounds=MAX_ROUNDS)
            requests = len(port.ledger)
        if requests == 0:
            continue
        seed_trace = run_trace(seed_state, MAX_ROUNDS)
        assert seed_trace["executed_count"] == 0, (
            "seed state unexpectedly carries executions; the pitfall "
            "this test pins no longer reproduces")
        trace = run_trace(result, MAX_ROUNDS)
        assert trace["executed_count"] > 0, strategy
        assert trace["outcome_tally"], strategy
        assert trace["rounds_used"] > 0, strategy
        assert trace["executed_count"] <= requests, (strategy, requests)
        confirmed = {
            e.experiment_id for e in result.experiments
            if result.experiment_outcome(e.experiment_id) == "confirmed"
        }
        assert set(trace["confirmed"]) == confirmed, strategy


# ------------------------------------------------------- label leakage


def test_no_strategy_state_carries_labels() -> None:
    """Serialized investigation state must never contain the lab's
    hidden-label vocabulary: the lab's internal family keys and the
    implementation-profile values that determine which defects a
    deployment declares (e.g. which checkout/spend/grant variant is
    installed). Findings emerge from probes, not from reading hidden
    labels. Also: the strategies module itself must never import the
    lab package."""
    source = (SRC / "egaie" / "benchmark" / "strategies.py").read_text(
        encoding="utf-8")
    assert "labsuite" not in source, (
        "strategies.py must not reference the lab package")

    # Lab-internal keys (underscored, never used by the engine) plus
    # every implementation-profile value that is not already ordinary
    # engine vocabulary. "authoritative", "consumed" and "cumulative"
    # are pre-existing engine words (field bindings, cap semantics);
    # the hyphenated profile tokens, the variant names and the lab's
    # underscored family keys are not, and their appearance in state
    # would be leakage.
    hidden = {
        "identity_read", "identity_mutation", "workflow_identity",
        "workflow_order", "client-total", "mirror-total",
        "owner-compare", "approver-acl", "chain-position",
        "history-sequence", "no-cap", "per-request", "replayable",
        "identity_read_enforced", "identity_mutation_enforced",
        "checkout_impl", "spend_impl", "grant_impl",
        "order_enforced", "workflow_identity_enforced",
    }
    for strategy in STRATEGY_NAMES:
        result, _spec = _run(strategy, 102)
        text = []
        for h in result.hypotheses:
            text += [h.hypothesis_id, h.family, h.statement, h.origin]
        for e in result.experiments:
            text += [e.experiment_id, e.family, e.signature]
        blob = "\n".join(t or "" for t in text)
        for key in hidden:
            assert not re.search(rf"\b{re.escape(key)}\b", blob), (
                strategy, key)


# --------------------------------------------------------- own id space


def test_b_and_d_produce_own_experiment_ids() -> None:
    """Config B (independent-fixed) and D (observation-baseline) mint
    experiment ids in their own namespaces, disjoint from each other
    and from the adaptive engine's ``differential:recon:`` namespace,
    so cross-strategy provenance can never be confused."""
    ids: dict[str, set[str]] = {}
    for strategy in ("independent-fixed", "observation-baseline"):
        result, _spec = _run(strategy, 102)
        assert result.experiments, strategy
        ids[strategy] = {e.experiment_id for e in result.experiments}
    b_ids, d_ids = ids["independent-fixed"], ids["observation-baseline"]
    assert all(i.startswith("e-bx") for i in b_ids), b_ids
    assert all(i.startswith("e-bl") for i in d_ids), d_ids
    assert not (b_ids & d_ids), "id namespaces must be disjoint"
    # Origins too: no hypothesis in B or D comes from the shared
    # adaptive recon namespace.
    for strategy, prefix in (("independent-fixed", INDEPENDENT_ORIGIN),
                             ("observation-baseline", BASELINE_ORIGIN)):
        result, _spec = _run(strategy, 102)
        origins = {h.origin for h in result.hypotheses}
        assert origins and all(
            o.startswith(prefix) for o in origins), (strategy, origins)
        assert not any(
            o.startswith(RECON_ORIGIN) for o in origins), strategy


# ------------------------------------------------------ secured silence


def test_all_strategies_silent_on_secured_instance() -> None:
    """A fully secured deployment yields zero confirmations for every
    configuration: a baseline that confirms nothing when nothing is
    wrong, and so do its ablations."""
    for strategy in STRATEGY_NAMES:
        result, _spec = _run(strategy, 301)
        assert _confirmed(result) == [], strategy
