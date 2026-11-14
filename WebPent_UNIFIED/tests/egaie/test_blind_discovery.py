"""Blind Discovery & Cross-Application Generalization (L6): red-first
regression tests.

These tests pin the contracts that make a generalization claim honest:

- the investigation state never carries a hidden defect label, an
  expected verdict, or any oracle-internal token (leakage scan);
- randomized surfaces (routes, ids, field names, workflow shapes) are
  worked entirely through each surface's own schema vocabulary;
- secured lookalikes yield ZERO confirmed findings (no false
  positives on a fully enforced instance);
- missing evidence never confirms;
- the ground-truth evaluator lives outside the discovery package and
  records a causal failure for every false negative;
- proofs for one instance never verify against another (no
  cross-instance evidence reuse);
- the no-proposer baseline, at the SAME round budget, confirms
  nothing on vulnerable instances;
- every confirmed finding's family matches its experiments' family.

No live targets: everything runs against in-process eval instances
over loopback.
"""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from webpent.egaie import discovery_runner as dr
from webpent.egaie.eval_instances import InstanceTarget, generate_instance
from webpent.evalsuite.evaluator import (
    corpus_summary,
    evaluate_instance,
)

SECURED = dict.fromkeys((
    "identity_read", "identity_mutation", "workflow_identity",
    "order", "price", "coupon", "balance"), False)

RECON_ORIGIN = "differential:recon:"


def _investigate(
    seed: int, profile: dict[str, bool] | None = None,
    max_rounds: int = 64,
) -> tuple[Any, Any]:
    spec = generate_instance(seed, blind=True, profile=profile)
    with InstanceTarget(spec) as target:
        port = dr._build_port(target, seed)
        state = dr._seed_state(target, dr._version_ids(seed)[0])
        state = dr._build_orchestrator(port, "adaptive").run(
            state, max_rounds=max_rounds)
    return spec, state


def _confirmed(state: Any) -> list[Any]:
    return [
        record for record in state.hypotheses
        if record.origin.startswith(RECON_ORIGIN)
        and record.status.value == "confirmed"
    ]


def _state_tokens(state: Any) -> str:
    parts = [json.dumps(record.to_dict())
             for record in state.hypotheses]
    parts.extend(json.dumps(exp.to_dict())
                 for exp in state.experiments)
    return " ".join(parts).lower()


# --------------------------------------------------------- label leakage

def test_no_hidden_labels_in_investigation_state() -> None:
    """The defect flags, expected verdicts, and oracle internals must
    never appear anywhere in the investigation state."""
    forbidden = (
        "identity_read_enforced", "identity_mutation_enforced",
        "workflow_identity_enforced", "order_enforced",
        "price_authoritative", "coupon_owner_enforced",
        "balance_enforced", "ground_truth", "expected_verdict",
        "oracle", "profile",
    )
    for seed, profile in ((11, None), (17, SECURED)):
        _, state = _investigate(seed, profile)
        tokens = _state_tokens(state)
        for token in forbidden:
            assert token not in tokens, (
                f"seed {seed}: hidden label {token!r} reached the "
                "investigation state")


# ---------------------------------------------------------- randomization

def test_randomized_surfaces_share_no_vocabulary() -> None:
    """Two instances generated from the same profile must not share
    route segments or field names; the engine still finds defects on
    both."""
    spec_a = generate_instance(21, blind=True)
    spec_b = generate_instance(22, blind=True)
    assert spec_a.read_segment != spec_b.read_segment
    assert spec_a.field_names != spec_b.field_names
    _, a = _investigate(21)
    _, b = _investigate(22)
    assert _confirmed(a), "engine found nothing on instance 21"
    assert _confirmed(b), "engine found nothing on instance 22"


def test_engine_uses_only_the_surfaces_own_vocabulary() -> None:
    """The instance's own randomized group names and parameter names
    must be disjoint from the canonical fixture vocabulary the L5
    engine hardcoded, so a passing run cannot be vocabulary reuse."""
    spec = generate_instance(11, blind=True)
    canonical = {"resources", "operations", "workflows", "resource",
                 "amount", "account", "actor", "idem"}
    assert set(spec.group_names.values()).isdisjoint(canonical)
    assert set(spec.param_names.values()).isdisjoint(canonical)


# ------------------------------------------------------ secured lookalike

def test_secured_lookalike_confirms_nothing() -> None:
    spec, state = _investigate(17, SECURED)
    assert _confirmed(state) == [], (
        "secured lookalike produced false positives")
    result = evaluate_instance(spec, state)
    assert result["false_positives"] == 0
    assert result["false_negatives"] == 0
    assert result["leakage_findings"] == []


# ------------------------------------------- evidence discipline

def test_missing_evidence_is_never_confirmed() -> None:
    """Every experiment outcome on a vulnerable instance must be one
    of the honest labels; an absent observation may never confirm."""
    _, state = _investigate(11)
    for experiment in state.experiments:
        outcome = state.experiment_outcomes.get(
            experiment.experiment_id, "")
        assert outcome in (
            "confirmed", "clean", "inconclusive", "blocked"), (
            f"{experiment.experiment_id}: outcome {outcome!r}")


def test_hypothesis_not_finding_without_experiment() -> None:
    """A hypothesis with no executed experiment must never be in the
    confirmed set (a hypothesis is not a finding)."""
    _, state = _investigate(14)
    experiment_hyps = {
        exp.hypothesis_id for exp in state.experiments
        if state.experiment_outcomes.get(exp.experiment_id)
        in ("confirmed", "clean", "inconclusive", "blocked")
    }
    for record in _confirmed(state):
        assert record.hypothesis_id in experiment_hyps, (
            f"{record.hypothesis_id}: confirmed without an executed "
            "experiment")


# ------------------------------------------------------------- evaluation

def test_evaluator_is_outside_the_discovery_package() -> None:
    """Importing the discovery package must not import the
    ground-truth evaluator: oracle isolation is structural."""
    code = (
        "import sys; import webpent.egaie; "
        "import webpent.egaie.differential; "
        "assert 'webpent.evalsuite.evaluator' not in sys.modules, "
        "'discovery imports the evaluator'"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr


def test_evaluator_records_causal_failure_for_every_miss() -> None:
    """Force misses (tiny round budget on a vulnerable instance) and
    check the evaluator derives a causal failure for each."""
    spec, state = _investigate(14, max_rounds=1)
    result = evaluate_instance(spec, state)
    if result["false_negatives"]:
        for score in result["families"].values():
            for negative in score["false_negatives"]:
                assert negative["causal_failure"] in (
                    "no_hypothesis_generated",
                    "probe_blocked_by_authority",
                    "evidence_gap",
                    "differential_not_discriminating",
                    "partial_evidence_gap",
                    "unclassified",
                )


def test_full_corpus_precision_and_no_leakage() -> None:
    """The 3-instance corpus (2 vulnerable, 1 secured) must score
    precision 1.0 with zero leakage findings."""
    results = []
    for seed, profile in ((11, None), (14, None), (17, SECURED)):
        spec, state = _investigate(seed, profile)
        results.append(evaluate_instance(spec, state))
    summary = corpus_summary(results)
    assert summary["false_positives"] == 0
    assert summary["leakage_findings"] == 0
    assert summary["true_positives"] >= 8
    assert summary["precision"] == 1.0


# --------------------------------------------- proofs never cross targets

def test_proof_bundles_do_not_verify_across_instances() -> None:
    """A sealed evidence bundle built for one target identity must
    FAIL replay verification when the verifying port expects another
    instance's identity."""
    from webpent.egaie.differential import (
        DEFAULT_TARGET_IDENTITY,
        DifferentialProofBundlePort,
    )
    spec = generate_instance(11, blind=True)
    with InstanceTarget(spec) as target:
        port = dr._build_port(target, 11)
        state = dr._seed_state(target, dr._version_ids(11)[0])
        state = dr._build_orchestrator(port, "adaptive").run(
            state, max_rounds=64)
    other = generate_instance(14, blind=True)
    experiment = state.experiments[0]
    builder = DifferentialProofBundlePort()
    bundle = builder.build(
        experiment,
        baseline={"steps": [], "family": experiment.family},
        candidate={"steps": [], "family": experiment.family},
        control={"steps": [], "family": experiment.family},
        causal_result={"verdict": "confirmed"},
    )
    assert bundle.target_identity == DEFAULT_TARGET_IDENTITY
    foreign = DifferentialProofBundlePort(
        expected_target_identity=f"eval:{other.instance_id}")
    report = foreign.verify(bundle)
    assert report["replay_valid"] is False
    assert report["identity_match"] is False


# ------------------------------------------------- baseline fairness

def test_equal_budget_baseline_confirms_nothing() -> None:
    """A proposer-free orchestrator given the SAME round budget must
    not confirm anything on a vulnerable instance: findings require
    the differential machinery, not budget."""
    spec = generate_instance(11, blind=True)
    with InstanceTarget(spec) as target:
        port = dr._build_port(target, 11)
        state = dr._seed_state(target, dr._version_ids(11)[0])
        state = dr._build_orchestrator(port, "ablation").run(
            state, max_rounds=64)
    assert _confirmed(state) == [], (
        "baseline confirmed a finding without differential evidence")


# ------------------------------------------------- per-family discipline

def test_findings_carry_their_own_family() -> None:
    """Every confirmed finding's family must match the family its
    experiments were run under (no family misclassification)."""
    _, state = _investigate(11)
    families_by_hypothesis: dict[str, set[str]] = {}
    for exp in state.experiments:
        families_by_hypothesis.setdefault(
            exp.hypothesis_id, set()).add(exp.family)
    for record in _confirmed(state):
        expected = families_by_hypothesis.get(record.hypothesis_id)
        assert expected and record.family in expected, (
            f"{record.hypothesis_id}: finding family {record.family} "
            f"does not match its experiments' {expected}")


# --------------------------------------- resume and authorization discipline

def test_resume_replay_never_duplicates_mutations() -> None:
    """Re-executing an already-executed state-changing experiment (what
    a resumed investigation does) must not apply a second mutation: the
    idempotency token is derived from the experiment identity, and the
    target applies each (family, key, token) at most once."""
    spec = generate_instance(11, blind=True)
    with InstanceTarget(spec) as target:
        port = dr._build_port(target, 11)
        state = dr._seed_state(target, dr._version_ids(11)[0])
        state = dr._build_orchestrator(port, "adaptive").run(
            state, max_rounds=64)
        executed = [
            exp for exp in state.experiments
            if state.experiment_outcomes.get(exp.experiment_id) == "confirmed"
        ]
        assert executed, "expected at least one confirmed experiment"
        orders_before = len(target._orders)
        mutations_before = len(target._applied_mutations)
        for exp in executed:
            port.execute(exp)
        assert len(target._orders) == orders_before
        assert len(target._applied_mutations) == mutations_before


def test_out_of_scope_authorization_blocks_every_request() -> None:
    """An authorization scoped to another origin must let ZERO requests
    reach the target: scope enforcement sits ahead of every step,
    including reconnaissance."""
    from webpent.autonomous.authorization import EngagementAuthorization
    from webpent.config.settings import ScanMode, Settings
    from webpent.egaie.differential import (
        build_differential_experiment_port,
    )
    spec = generate_instance(11, blind=True)
    with InstanceTarget(spec) as target:
        engagement_id, campaign_id = dr._version_ids(11)
        foreign = EngagementAuthorization(
            target_origin="https://elsewhere.example",
            scope=("https://elsewhere.example",),
            operator="benchmark-operator",
            authorization_reference=engagement_id,
        )
        port = build_differential_experiment_port(
            target=target,
            engagement_id=engagement_id,
            campaign_id=campaign_id,
            authorization=foreign,
            settings=Settings(
                scan_mode=ScanMode.AUTHORIZED_ACTIVE,
                smart_max_actions=dr.DISCOVERY_MAX_ACTIONS,
                smart_action_budget=dr.DISCOVERY_MAX_ACTIONS,
            ),
        )
        state = dr._seed_state(target, engagement_id)
        state = dr._build_orchestrator(port, "adaptive").run(
            state, max_rounds=8)
    assert target._request_count == 0, (
        "out-of-scope authorization still reached the target")
    assert state.experiments == []
    assert _confirmed(state) == []
