"""Differential Discovery Engine (L5): red-first regression tests.

The discovery benchmark must find previously unspecified scenarios
from observed behavior alone. These tests pin the contracts that make
that claim honest:

- prioritization honors scheduling preconditions (pristine-state band);
- the proposer stages emission so state-advancing probes cannot
  destroy the precondition later probes depend on;
- a finding is a genuine server-enforced differential with a negative
  control, never a bare status-code or model claim;
- missing or contradictory evidence is INCONCLUSIVE/BLOCKED, distinct
  from clean and from confirmed;
- every promoted finding is bound, one-to-one, to a sealed
  replay-valid proof;
- randomized identifiers: the same logical cases are detected across
  deployment seeds and no case label ever reaches the detector;
- the no-proposer baseline confirms nothing on the discovery surface
  and the prioritization ablation never invents a finding.

No live targets: everything runs against the in-process
DiscoveryTarget over loopback.
"""
from __future__ import annotations

from typing import Any

from webpent.egaie import discovery_runner as dr
from webpent.egaie.differential import (
    DifferentialGenerator,
    DifferentialHypothesis,
    DifferentialPrioritizer,
    DifferentialValidationPort,
    ProbePlan,
)
from webpent.egaie.discovery_ground_truth import (
    declared_seeds,
    discovery_ground_truth,
    discovery_ground_truth_version,
)
from webpent.egaie.discovery_target import DiscoveryTarget

# --------------------------------------------------------------- helpers

def _adaptive_state(seed: int = 1, max_rounds: int = 48) -> tuple[Any, Any, Any]:
    with DiscoveryTarget(seed=seed).start() as target:
        state, metrics = dr._run_loop(
            target, mode="adaptive", seed=seed, max_rounds=max_rounds)
    return state, metrics, target


def _recon_hypotheses(state: Any) -> list[Any]:
    return [
        record for record in state.hypotheses
        if record.origin.startswith("differential:recon:")
    ]


def _outcome_counts(state: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for exp in state.experiments:
        outcome = state.experiment_outcome(exp.experiment_id)
        counts[outcome] = counts.get(outcome, 0) + 1
    return counts


# -------------------------------------------- scheduling preconditions

def test_prioritizer_puts_pristine_band_first():
    generator = DifferentialGenerator()
    pristine = generator.PRISTINE_FAMILIES
    plan = ProbePlan(hypothesis_id="plain-01", steps=[])
    plain = DifferentialHypothesis(
        hypothesis_id="plain-01",
        family="IDENTITY_BOUNDARY",
        statement="plain",
        motivating_facts=(),
        invariant="identity",
        confirm_evidence="cross-identity contrast",
        falsify_evidence="identical outcomes",
        gain=1.5,
        cost=0.3,
        preconditions=(),
        plan=plan,
    )
    pristine_h = DifferentialHypothesis(
        hypothesis_id="pristine-01",
        family=next(iter(pristine)),
        statement="pristine",
        motivating_facts=(),
        invariant="order",
        confirm_evidence="out-of-order transition accepted",
        falsify_evidence="409 invalid_transition",
        gain=0.2,
        cost=0.3,
        preconditions=("pristine state",),
        plan=ProbePlan(hypothesis_id="pristine-01", steps=[]),
        pristine_state_required=True,
    )
    ranked = DifferentialPrioritizer().rank([plain, pristine_h])
    # The pristine-band hypothesis is scheduled first even though the
    # plain one has the far higher gain/cost ratio.
    assert ranked[0].hypothesis_id == "pristine-01"


def test_proposer_emits_pristine_band_before_state_advancing_band():
    state, _metrics, _target = _adaptive_state(seed=1)
    pristine = DifferentialGenerator.PRISTINE_FAMILIES
    pristine_ids = [
        exp.experiment_id for exp in state.experiments
        if exp.family in pristine
    ]
    advancing_ids = [
        exp.experiment_id for exp in state.experiments
        if exp.family not in pristine
    ]
    assert pristine_ids, "no pristine-band hypotheses proposed"
    assert advancing_ids, "no state-advancing hypotheses proposed"
    first_advancing = min(
        state.experiments.index(
            next(e for e in state.experiments
                 if e.experiment_id == exp_id))
        for exp_id in advancing_ids
    )
    last_pristine = max(
        state.experiments.index(
            next(e for e in state.experiments
                 if e.experiment_id == exp_id))
        for exp_id in pristine_ids
    )
    assert last_pristine < first_advancing, (
        "state-advancing hypotheses were proposed before every "
        "pristine-state hypothesis was even on the table")


def test_order_probes_execute_before_identity_probes_on_workflows():
    """The behavioral contract behind the staging: no workflow submit
    (state-advancing identity probe step) may hit the target before
    every workflow approve-from-draft step (the out-of-order
    discrimination) has run."""
    with DiscoveryTarget(seed=1).start() as target:
        port = dr._build_port(target, 1)
        state = dr._seed_state(target, dr._version_ids(1)[0])
        dr._build_orchestrator(port, "adaptive").run(
            state, max_rounds=48)
        approve_positions: list[int] = []
        submit_positions: list[int] = []
        for index, record in enumerate(port.ledger.records):
            path = record.path or ""
            if record.method != "POST":
                continue
            action = (record.params or {}).get("action", "")
            if "/wf-" in path and action == "approve":
                approve_positions.append(index)
            elif "/wf-" in path and action == "submit":
                submit_positions.append(index)
    assert approve_positions and submit_positions
    assert max(approve_positions) < min(submit_positions), (
        "an identity probe advanced a workflow before the order "
        "probe tested the pristine state")


# ------------------------------------------- genuine discovery, no labels

def test_adaptive_recovers_full_ground_truth_without_labels():
    _state, metrics, _target = _adaptive_state(seed=1)
    assert metrics["confirmed_count"] == 11
    assert metrics["recall"] == 1.0
    assert metrics["false_positives"] == 0
    assert metrics["replay_valid_confirmed"] == 11
    positives = {
        case.case_id for case in discovery_ground_truth(1)
        if case.positive
    }
    assert set(metrics["true_positive_case_ids"]) == positives


def test_hypotheses_never_carry_case_labels():
    """The detector works from observations: hypothesis identities are
    engine slugs, never the benchmark's case ids."""
    state, _metrics, _target = _adaptive_state(seed=1)
    recon = _recon_hypotheses(state)
    assert len(recon) >= 3
    case_ids = {case.case_id for case in discovery_ground_truth(1)}
    for record in recon:
        assert record.origin.startswith("differential:recon:")
        slug = record.origin[len("differential:recon:"):]
        assert slug not in case_ids
        for case_id in case_ids:
            assert case_id not in record.statement


def test_randomized_identifiers_detected_across_declared_seeds():
    for seed in declared_seeds():
        _state, metrics, _target = _adaptive_state(seed=seed)
        assert metrics["recall"] == 1.0, f"seed {seed}"
        assert metrics["false_positives"] == 0, f"seed {seed}"
        # The external paths genuinely differ per deployment: the
        # detector cannot be scoring memorized names.
        paths = {case.path for case in discovery_ground_truth(seed)}
        other = {
            case.path
            for other_seed in declared_seeds() if other_seed != seed
            for case in discovery_ground_truth(other_seed)
        }
        assert paths.isdisjoint(other), f"seed {seed} paths collide"


def test_business_logic_finding_stays_in_its_own_family():
    """The multi-step cross-owner coupon scenario is a price-integrity
    finding; it must never be promoted as an authorization bypass."""
    _state, metrics, _target = _adaptive_state(seed=1)
    coupon = [
        case for case in discovery_ground_truth(1)
        if case.multi_step and case.positive
    ]
    assert len(coupon) == 1, "exactly one multi-step positive declared"
    assert coupon[0].family == "PRICE_INTEGRITY"
    # The coupon case is recovered by a PRICE_INTEGRITY finding (the
    # per-family attribution comes from the hypothesis that generated
    # the probe, never from path overlap).
    price = metrics["per_family"]["PRICE_INTEGRITY"]
    assert coupon[0].case_id in price["true_positive_case_ids"], price
    # No other family claims the coupon scenario.
    for family in ("IDENTITY_BOUNDARY", "WORKFLOW_ORDER"):
        other = metrics["per_family"][family]
        assert coupon[0].case_id not in other[
            "true_positive_case_ids"], (family, other)
    # The coupon's path is genuinely among the confirmed probed paths,
    # and the price family carries its read-path finding too.
    confirmed_path_set = {
        path for path in metrics["confirmed_paths"] if path
    }
    assert coupon[0].path in confirmed_path_set
    assert price["true_positives"] >= 2


# --------------------------------- evidence standards: confirm vs reject

def test_engine_correctly_rejects_enforced_surface_hypotheses():
    """At least one derived hypothesis must be FALSIFIED by the
    differential evidence (clean), which is the engine rejecting a
    hypothesis it generated rather than confirming everything."""
    state, _metrics, _target = _adaptive_state(seed=1)
    counts = _outcome_counts(state)
    assert counts.get("clean", 0) >= 1, (
        "the engine never rejected any of its own hypotheses")


def test_inconclusive_when_precondition_evidence_is_destroyed():
    """An order probe run against a workflow whose pristine state is
    gone cannot discriminate: the outcome is INCONCLUSIVE, distinct
    from clean and from confirmed, and never a confirmation."""
    with DiscoveryTarget(seed=1).start() as target:
        target.reset()
        deployment = target.deployment
        # Destroy the precondition out of band: advance one enforced
        # workflow to submitted before the engine sees the target.
        owner = next(
            wf.owner for wf in deployment.workflows.values()
            if wf.enforce_identity and wf.enforce_order)
        workflow_id = next(
            wf.workflow_id for wf in deployment.workflows.values()
            if wf.enforce_identity and wf.enforce_order)
        status, _headers, body = target.handle_post(
            f"/{deployment.workflow_segment()}/{workflow_id}",
            {"actor": owner, "action": "submit", "idem": "pre-adv"},
        )
        assert status == 200
        port = dr._build_port(target, 1)
        state = dr._seed_state(target, dr._version_ids(1)[0])
        state = dr._build_orchestrator(port, "adaptive").run(
            state, max_rounds=48)
        outcome = None
        for exp in state.experiments:
            if "order" not in exp.experiment_id:
                continue
            plan = port.plan_for(exp.signature)
            if any(workflow_id in step.path for step in plan.steps):
                outcome = state.experiment_outcome(exp.experiment_id)
    assert outcome == "inconclusive"


def _identity_composite(
    family: str, cand: dict[str, Any], ctrl: dict[str, Any],
) -> dict[str, Any]:
    return {"family": family, "steps": [cand, ctrl]}


def test_legitimate_difference_is_rejected_not_confirmed():
    """False-positive resistance at the judge level: a server-enforced
    ownership control (foreign denied, owner granted) is the
    legitimate difference the engine must NOT promote."""
    judge = DifferentialValidationPort()
    enforced = _identity_composite(
        "IDENTITY_BOUNDARY",
        {"label": "read-cand", "status_code": 403,
         "actor": "acct-0001b", "structured": {"error": "forbidden"},
         "execution": "executed"},
        {"label": "read-ctrl", "status_code": 200,
         "actor": "acct-0001a", "structured": {"owner": "acct-0001a"},
         "execution": "executed"},
    )
    assert judge.validate(enforced, enforced, enforced)["verdict"] == (
        "clean")


def test_missing_identity_evidence_is_inconclusive_not_confirmed():
    """The identity judge requires the candidate/control contrast with
    ownership evidence; without it, no finding is promoted."""
    judge = DifferentialValidationPort()
    # Nothing executed at all: BLOCKED, a distinct disposition.
    blocked = _identity_composite(
        "IDENTITY_BOUNDARY",
        {"label": "read-cand", "status_code": 0, "actor": "",
         "structured": None, "execution": "blocked"},
        {"label": "read-ctrl", "status_code": 0, "actor": "",
         "structured": None, "execution": "blocked"},
    )
    assert judge.validate(blocked, blocked, blocked)["verdict"] == (
        "blocked")
    # One side of the contrast missing: INCONCLUSIVE.
    no_candidate = _identity_composite(
        "IDENTITY_BOUNDARY",
        {"label": "read-cand", "status_code": 0, "actor": "",
         "structured": None, "execution": "missing"},
        {"label": "read-ctrl", "status_code": 200,
         "actor": "acct-0001a", "structured": {"owner": "acct-0001a"},
         "execution": "executed"},
    )
    assert judge.validate(no_candidate, no_candidate, no_candidate)[
        "verdict"] == "inconclusive"
    # Foreign accepted but no ownership evidence in the response: the
    # differential is unverifiable, never a confirmation.
    no_owner = _identity_composite(
        "IDENTITY_BOUNDARY",
        {"label": "read-cand", "status_code": 200,
         "actor": "acct-0001b", "structured": {}, "execution": "executed"},
        {"label": "read-ctrl", "status_code": 403,
         "actor": "acct-0001a", "structured": {"error": "forbidden"},
         "execution": "executed"},
    )
    assert judge.validate(no_owner, no_owner, no_owner)["verdict"] == (
        "inconclusive")


# ------------------------------------------------------- sealed proofs

def test_every_promoted_finding_bound_to_sealed_replay_valid_proof():
    state, metrics, _target = _adaptive_state(seed=1)
    assert metrics["confirmed_count"] > 0
    association = metrics["proof_association"]
    assert association["replay_valid_confirmed"] == (
        association["confirmed_cases"])
    assert association["confirmed_without_proof"] == []
    assert association["unrelated_replay_valid"] == 0
    assert association["duplicate_proof_records"] == 0
    assert association["mismatched_identity_records"] == 0
    # And each verified record is a full sealed bundle.
    for record in state.proof_bundles_verified:
        assert record["replay_valid"] is True
        assert record["seal_valid"] is True
        assert record["verdict_match"] is True
        assert record["digest_match"] is True


# ------------------------------------------------------- interrupted runs

def test_resume_mid_schedule_completes_the_discovery():
    with DiscoveryTarget(seed=1).start() as target:
        target.reset()
        port = dr._build_port(target, 1)
        state = dr._seed_state(target, dr._version_ids(1)[0])
        state = dr._build_orchestrator(port, "adaptive").run(
            state, max_rounds=3)
        confirmed_before = [
            h for h in state.hypotheses
            if h.status.value == "confirmed"]
        state = dr._build_orchestrator(port, "adaptive").run(
            state, max_rounds=48)
        confirmed_after = [
            h for h in state.hypotheses
            if h.status.value == "confirmed"]
        cases = discovery_ground_truth(1)
        positives = {
            case.path for case in cases if case.positive}
        confirmed_paths = {
            origin: dr._finding_path(port, state, origin)
            for origin in dr._confirmed_case_ids(state)
        }
    assert len(confirmed_before) < len(confirmed_after)
    assert len(confirmed_after) == 11
    # Every finding still probes a declared positive path, so the
    # resumed run confirmed the same real findings, not new labels.
    assert set(confirmed_paths.values()) == positives
    # The resumed run still emitted the deferred (state-advancing)
    # band after the interruption.
    pristine = DifferentialGenerator.PRISTINE_FAMILIES
    assert any(exp.family not in pristine for exp in state.experiments)


def test_resume_after_stage_two_does_not_duplicate_hypotheses():
    with DiscoveryTarget(seed=1).start() as target:
        target.reset()
        port = dr._build_port(target, 1)
        state = dr._seed_state(target, dr._version_ids(1)[0])
        state = dr._build_orchestrator(port, "adaptive").run(
            state, max_rounds=20)
        recon_before = len(_recon_hypotheses(state))
        dr._build_orchestrator(port, "adaptive").run(
            state, max_rounds=48)
        recon_after = len(_recon_hypotheses(state))
    assert recon_before > 0
    assert recon_after == recon_before


# ------------------------------------------------ comparison and ablation

def test_baseline_confirms_nothing_and_ablation_never_invents():
    with DiscoveryTarget(seed=1).start() as target:
        report = dr.run_discovery_comparison(target, seed=1)
    baseline = report.baseline
    assert baseline["confirmed_count"] == 0
    assert baseline["false_positives"] == 0
    ablation = report.ablation
    assert ablation["false_positives"] == 0
    adaptive_ids = set(report.adaptive["confirmed_case_ids"])
    ablation_ids = set(ablation["confirmed_case_ids"])
    assert ablation_ids <= adaptive_ids
    assert report.thresholds_pass is True


def test_comparison_reproducible_across_repetitions():
    with DiscoveryTarget(seed=1).start() as target:
        report = dr.run_discovery_comparison(target, seed=1)
    assert report.reproducible is True
    assert report.resume_correct is True


# ------------------------------------------------------ ground truth sanity

def test_ground_truth_shape_and_version():
    cases = discovery_ground_truth(1)
    assert len(cases) == 26
    positives = {case.case_id for case in cases if case.positive}
    assert len(positives) == 11
    assert declared_seeds() == (1, 2, 3)
    assert discovery_ground_truth_version() == "discovery-v2"
    # Every case carries an independent justification; no case is
    # labeled by pointing at a detector outcome.
    assert all(case.justification for case in cases)
