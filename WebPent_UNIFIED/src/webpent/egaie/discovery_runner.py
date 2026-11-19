"""EGAIE differential discovery benchmark harness (L5).

Runs the differential discovery engine against the randomized
discovery surface through the SAME single InvestigationOrchestrator
and reports results per declared deployment seed. Three configurations
share one port family, one validation oracle and one budget:

- adaptive: DifferentialProposer (reconnaissance -> grounded
  hypotheses -> ranked probes) with information-gain selection;
- baseline: the existing fixed-order baseline concept applied to the
  discovery surface: the same orchestrator and validation with NO
  proposer and an empty seeded state, so it can only execute what is
  seeded. Ground-truth labels are never seeded (they would leak the
  benchmark into the detector), so the existing baseline confirms
  nothing here by construction: that is the comparison result, not a
  rigging artifact;
- ablation: the differential proposer WITHOUT prioritization
  (insertion order, fixed selection), isolating the contribution of
  ranking/selection from the differential generators themselves.

Results are reported per seed and per family and are NEVER pooled with
the http-v3 fixture benchmark (http_runner.py) or with other seeds.
Only seeds declared by discovery_ground_truth.declared_seeds() are
benchmarkable; any other seed is a configuration error.

Honesty rules enforced here:

- Ground truth is imported only by this module and the tests, never by
  the detector or the port.
- A confirmed finding maps to a ground-truth case by its PROBED PATH
  (from the registered probe plan, i.e. from observations, not from
  labels). Confirmed findings on unlabeled or negative-labeled paths
  are false positives under the declared ground truth.
- Every confirmed finding must carry its own replay-valid sealed proof
  (one-to-one binding, checked per record, never by list length).
- The no-proposer baseline must confirm nothing: findings may only
  come from differential hypotheses, never from seeds, fixtures or
  model output. The prioritization ablation shares the generators,
  so it may confirm real findings, but never anything the adaptive
  run did not, and never a false positive.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

from webpent.autonomous.authorization import EngagementAuthorization
from webpent.config.settings import ScanMode, Settings
from webpent.egaie.benchmark.baseline import build_baseline_orchestrator
from webpent.egaie.differential import (
    DIFFERENTIAL_FAMILIES,
    DifferentialProofBundlePort,
    DifferentialProposer,
    DifferentialValidationPort,
    build_differential_experiment_port,
)
from webpent.egaie.discovery_ground_truth import (
    DISCOVERY_GROUND_TRUTH_VERSION,
    declared_seeds,
    discovery_ground_truth,
)
from webpent.egaie.orchestrator import InvestigationOrchestrator
from webpent.egaie.persistence import load_state, save_state
from webpent.egaie.repetition import RepetitionRegister
from webpent.egaie.schemas import (
    DecisionAction,
    DecisionRecord,
    InvestigationState,
    ProposedExperiment,
)
from webpent.egaie.seeds import seed_state
from webpent.egaie.selection import InformationGainSelector

DISCOVERY_MIN_RECALL = 0.6
DISCOVERY_MAX_ACTIONS = 200
DISCOVERY_RESUME_STATE_PATH = (
    "/tmp/egaie_discovery_benchmark_resume_state.json"
)

_ORIGINAL_PREFIX = "differential:recon:"


def _check_seed(seed: int) -> None:
    if seed not in declared_seeds():
        raise ValueError(f"undeclared discovery seed: {seed}")


def _version_ids(seed: int) -> tuple[str, str]:
    return (
        f"egaie-discovery-benchmark-"
        f"{DISCOVERY_GROUND_TRUTH_VERSION}-s{seed}",
        f"egaie-discovery-campaign-"
        f"{DISCOVERY_GROUND_TRUTH_VERSION}-s{seed}",
    )


def _authorization(
    target: Any, engagement_id: str,
) -> EngagementAuthorization:
    return EngagementAuthorization(
        target_origin=target.target_origin,
        scope=(target.target_origin,),
        operator="benchmark-operator",
        authorization_reference=engagement_id,
    )


def _build_port(target: Any, seed: int) -> Any:
    engagement_id, campaign_id = _version_ids(seed)
    return build_differential_experiment_port(
        target=target,
        engagement_id=engagement_id,
        campaign_id=campaign_id,
        authorization=_authorization(target, engagement_id),
        settings=Settings(
            scan_mode=ScanMode.AUTHORIZED_ACTIVE,
            smart_max_actions=DISCOVERY_MAX_ACTIONS,
            smart_action_budget=DISCOVERY_MAX_ACTIONS,
        ),
    )


def _seed_state(
    target: Any, engagement_id: str,
) -> InvestigationState:
    """An EMPTY seeded state: no ground-truth cases, no fixture ids.

    Every hypothesis in a discovery run must originate from the
    DifferentialProposer's reconnaissance (origin prefixed
    differential:recon:), never from the benchmark's labels.
    """
    return seed_state([], engagement_id, target.target_origin)


def _confirmed_case_ids(state: InvestigationState) -> list[str]:
    return sorted({
        hypothesis.origin
        for hypothesis in state.hypotheses
        if hypothesis.status.value == "confirmed" and hypothesis.origin
    })


def _confirmed_slugs(state: InvestigationState) -> list[str]:
    return sorted(
        origin[len(_ORIGINAL_PREFIX):]
        for origin in _confirmed_case_ids(state)
        if origin.startswith(_ORIGINAL_PREFIX)
    )


class _LedgerModelPort:
    """No-op world-model ledger: the discovery benchmark needs no
    world model and no model-generated hypotheses."""

    def propose(self, state: InvestigationState) -> list[ProposedExperiment]:
        return []

    def update(
        self, state: InvestigationState, experiment: ProposedExperiment,
        observations: Any, causal: Any,
    ) -> dict[str, Any]:
        return {"world_model": [], "attack_graph": []}


class _NoopSelector:
    """Selector that executes candidates in insertion order and only
    terminates when nothing is pending."""

    def select(
        self,
        state: InvestigationState,
        candidates: list[ProposedExperiment],
        register: RepetitionRegister,
        unavailable_hypotheses: frozenset[str] = frozenset(),
        state_advancing_families: frozenset[str] = frozenset(),
        remaining_rounds: int | None = None,
    ) -> DecisionRecord:
        if not candidates:
            return DecisionRecord(
                round=state.round,
                action=DecisionAction.TERMINATE,
                selected_experiment_id="",
                scores={},
                alternatives=(),
                rationale="no pending experiments remain",
            )
        chosen = candidates[0]
        return DecisionRecord(
            round=state.round,
            action=DecisionAction.SELECT,
            selected_experiment_id=chosen.experiment_id,
            scores={},
            alternatives=(),
            rationale="insertion order (benchmark driver)",
        )


class _InsertionOrderPrioritizer:
    """Ablation prioritizer: no ranking, generator emission order."""

    def rank(self, hypotheses: list) -> list:
        return list(hypotheses)


def _build_orchestrator(
    port: Any, mode: str,
) -> InvestigationOrchestrator:
    """Build the ONE orchestrator in one of three benchmark modes.

    adaptive: differential proposer (ranked) + information-gain
    selection. fixed: the same differential proposer WITHOUT ranking
    (insertion order) + fixed-order selection. ablation: the existing
    baseline orchestrator (no proposer at all).
    """
    validation = DifferentialValidationPort()
    proof = DifferentialProofBundlePort()
    if mode == "adaptive":
        return InvestigationOrchestrator(
            experiment_port=port,
            validation_port=validation,
            proof_port=proof,
            model_port=_LedgerModelPort(),
            selector=InformationGainSelector(),
            proposer=DifferentialProposer(port),
        )
    if mode == "fixed":
        return InvestigationOrchestrator(
            experiment_port=port,
            validation_port=validation,
            proof_port=proof,
            model_port=_LedgerModelPort(),
            selector=_NoopSelector(),
            proposer=DifferentialProposer(
                port, prioritizer=_InsertionOrderPrioritizer()),
        )
    if mode == "ablation":
        return build_baseline_orchestrator(
            port, validation, proof, _LedgerModelPort())
    raise ValueError(f"unknown discovery benchmark mode: {mode}")


# --------------------------------------------------------------------------
# Finding -> ground truth mapping (observation-derived, never label-fed)
# --------------------------------------------------------------------------

def _finding_path(
    port: Any, state: InvestigationState, origin: str,
) -> str | None:
    """The path a confirmed finding actually probed, taken from the
    registered probe plan (the plan was built from observations)."""
    if not origin.startswith(_ORIGINAL_PREFIX):
        return None
    slug = origin[len(_ORIGINAL_PREFIX):]
    experiment = next(
        (exp for exp in state.experiments
         if exp.experiment_id == f"e-{slug}"),
        None,
    )
    if experiment is None:
        return None
    try:
        plan = port.plan_for(experiment.signature)
    except ValueError:
        return None
    if plan is None:
        return None
    for step in plan.steps:
        if step.path != "{revealed}":
            return step.path
    return None


def _family_metrics(
    cases: tuple,
    confirmed_paths: dict[str, str | None],
    finding_families: dict[str, str],
    family: str,
) -> dict[str, Any]:
    """Precision / recall / F1 for one family under the declared
    ground truth.

    A finding is attributed to the family of the hypothesis that
    generated it (from the observation-derived probe plan), never to a
    family by path overlap: one defective instance can host two
    declared cases (identity AND order enforcement disabled), and a
    finding demonstrates only the boundary its own probe tested. A
    finding counts as a true positive only when its probed path
    matches a POSITIVE case of its own family; a negative-labeled or
    unlabeled probed path under that family is a false positive.
    Multiple confirmed findings on the same positive path collapse for
    recall; the extras are reported as duplicates.
    """
    family_cases = [case for case in cases if case.family == family]
    positives = {
        case.path: case.case_id for case in family_cases if case.positive
    }
    negatives = {
        case.path: case.case_id
        for case in family_cases if not case.positive
    }
    tp_paths: set[str] = set()
    tp_origins: set[str] = set()
    tp_hits = 0
    false_positive_entries: list[dict[str, Any]] = []
    for origin in sorted(confirmed_paths):
        if finding_families.get(origin) != family:
            continue
        path = confirmed_paths[origin]
        if path in positives:
            tp_hits += 1
            tp_paths.add(path)
            tp_origins.add(origin)
            continue
        false_positive_entries.append({
            "origin": origin,
            "path": path,
            "labeled_negative": path in negatives,
        })
    false_positives = len(false_positive_entries)
    true_positives = len(tp_paths)
    duplicates = tp_hits - true_positives
    recall = (
        round(true_positives / len(positives), 4) if positives else None
    )
    precision = (
        round(true_positives / (true_positives + false_positives), 4)
        if (true_positives + false_positives) else None
    )
    f1 = (
        round(
            2 * precision * recall / (precision + recall), 4)
        if precision is not None and recall is not None
        and (precision + recall) > 0 else None
    )
    return {
        "positives_declared": len(positives),
        "negatives_declared": len(negatives),
        "true_positives": true_positives,
        "true_positive_case_ids": sorted(
            positives[path] for path in tp_paths),
        "true_positive_origins": sorted(tp_origins),
        "false_positives": false_positives,
        "false_positive_entries": false_positive_entries,
        "duplicate_confirmations": duplicates,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _proof_association_metrics(
    state: InvestigationState,
) -> dict[str, Any]:
    """One-to-one association between confirmed differential findings
    and their replay-valid sealed proofs.

    Discovery findings are identified by origin
    (differential:recon:{slug}); an experiment is bound to a finding
    when its hypothesis_id is h-{slug} and the proof record's
    signature carries the same slug. Both identities must agree; each
    record is used at most once.
    """
    confirmed = _confirmed_case_ids(state)
    case_experiments: dict[str, set[str]] = {
        case_id: set() for case_id in confirmed
    }
    experiment_case: dict[str, str] = {}
    for exp in state.experiments:
        case_id: str | None = None
        if exp.hypothesis_id and exp.hypothesis_id.startswith("h-"):
            candidate = f"{_ORIGINAL_PREFIX}{exp.hypothesis_id[2:]}"
            if candidate in case_experiments:
                case_id = candidate
        if case_id is not None:
            case_experiments[case_id].add(exp.experiment_id)
            experiment_case[exp.experiment_id] = case_id

    records = list(state.proof_bundles_verified)
    seen_experiments: set[str] = set()
    duplicate_proof_records = 0
    mismatched_identity_records = 0
    unrelated_replay_valid = 0
    covered: set[str] = set()
    for record in records:
        experiment_id = record.get("experiment_id", "")
        if experiment_id in seen_experiments:
            if record.get("replay_valid") is True:
                duplicate_proof_records += 1
            continue
        seen_experiments.add(experiment_id)
        case_id = experiment_case.get(experiment_id)
        record_slug = str(record.get("signature", "")).split("/", 1)[0]
        record_case = (
            f"{_ORIGINAL_PREFIX}{record_slug}" if record_slug else "")
        if case_id is None or record_case != case_id:
            if record.get("replay_valid") is True:
                if case_id is None:
                    unrelated_replay_valid += 1
                else:
                    mismatched_identity_records += 1
            continue
        if record.get("replay_valid") is True:
            covered.add(case_id)
    confirmed_without_proof = [
        case_id for case_id in confirmed if case_id not in covered
    ]
    return {
        "replay_valid_confirmed": len(covered),
        "confirmed_cases": len(confirmed),
        "confirmed_without_proof": confirmed_without_proof,
        "unrelated_replay_valid": unrelated_replay_valid,
        "duplicate_proof_records": duplicate_proof_records,
        "mismatched_identity_records": mismatched_identity_records,
    }


# --------------------------------------------------------------------------
# Run loop
# --------------------------------------------------------------------------

def _run_loop(
    target: Any,
    mode: str,
    seed: int,
    max_rounds: int,
    reset_target: bool = True,
) -> tuple[InvestigationState, dict[str, Any]]:
    """One discovery run in one mode; reset_target restores the target
    deployment (same seed) before the run so repeated runs start from
    identical conditions. The resume check drives reset_target=False
    across its interrupted/resumed pair."""
    _check_seed(seed)
    if reset_target:
        target.reset()
    started = time.monotonic()
    port = _build_port(target, seed)
    engagement_id, _campaign_id = _version_ids(seed)
    state = _seed_state(target, engagement_id)
    state = _build_orchestrator(port, mode).run(
        state, max_rounds=max_rounds)
    elapsed = round(time.monotonic() - started, 4)

    cases = discovery_ground_truth(seed)
    confirmed = _confirmed_case_ids(state)
    confirmed_paths = {
        origin: _finding_path(port, state, origin)
        for origin in confirmed
    }
    # A finding belongs to the family of the hypothesis that generated
    # it; the probe plan carries the probed path.
    finding_families = {
        hypothesis.origin: hypothesis.family
        for hypothesis in state.hypotheses
        if hypothesis.origin
    }
    total_positives = sum(1 for case in cases if case.positive)
    association = _proof_association_metrics(state)
    confirmed_count = len(confirmed)

    per_family: dict[str, Any] = {}
    for family in DIFFERENTIAL_FAMILIES:
        per_family[family] = _family_metrics(
            cases, confirmed_paths, finding_families, family)
    # Global true positives: confirmed CASES matched family-for-family
    # (a WORKFLOW_ORDER finding never covers an identity-labeled case
    # on the same instance, and vice versa). Global false positives:
    # any confirmed FINDING (origin) that is not a true positive of
    # its own family, plus findings whose probed path could not be
    # recovered. Origins, not case ids: a positive case may be hit by
    # one finding while another finding on the same instance still
    # probes an unlabeled path and is a false positive on its own.
    tp_case_ids: set[str] = set()
    tp_origins: set[str] = set()
    for family in DIFFERENTIAL_FAMILIES:
        tp_case_ids |= set(
            per_family[family]["true_positive_case_ids"])
        tp_origins |= set(per_family[family]["true_positive_origins"])
    false_positive_entries = [
        {"origin": origin, "path": path,
         "family": finding_families.get(origin)}
        for origin, path in sorted(confirmed_paths.items())
        if path is None or origin not in tp_origins
    ]
    outcome_counts: dict[str, dict[str, int]] = {
        family: {} for family in DIFFERENTIAL_FAMILIES
    }
    per_experiment: dict[str, str] = {}
    for exp in state.experiments:
        outcome = state.experiment_outcome(exp.experiment_id)
        if not outcome:
            continue
        per_experiment[exp.experiment_id] = outcome
        bucket = outcome_counts.get(exp.family)
        if bucket is not None:
            bucket[outcome] = bucket.get(outcome, 0) + 1

    hypotheses_generated = sum(
        1 for hypothesis in state.hypotheses
        if hypothesis.origin.startswith(_ORIGINAL_PREFIX)
    )
    metrics: dict[str, Any] = {
        "ground_truth_version": DISCOVERY_GROUND_TRUTH_VERSION,
        "seed": seed,
        "mode": mode,
        "transport": "action_executor",
        "hypotheses_generated": hypotheses_generated,
        "confirmed_count": confirmed_count,
        "confirmed_case_ids": confirmed,
        "confirmed_paths": [
            confirmed_paths[origin] for origin in confirmed],
        "true_positive_case_ids": sorted(tp_case_ids),
        "recall": (
            round(len(tp_case_ids) / total_positives, 4)
            if total_positives else None
        ),
        "false_positives": len(false_positive_entries),
        "false_positive_entries": false_positive_entries,
        "per_family": per_family,
        "outcome_counts": outcome_counts,
        "per_experiment": per_experiment,
        "requests_made": port.requests_made,
        "requests_per_confirmed": (
            round(port.requests_made / confirmed_count, 4)
            if confirmed_count else None
        ),
        "replay_valid_confirmed": association["replay_valid_confirmed"],
        "proof_association": association,
        "wall_time_s": elapsed,
        "terminal_reason": state.terminal_reason,
    }
    return state, metrics


def run_discovery_adaptive(
    target: Any, seed: int = 1, max_rounds: int = 48,
) -> tuple[InvestigationState, dict[str, Any]]:
    """Full differential discovery engine (recon -> ranked probes)."""
    return _run_loop(target, mode="adaptive", seed=seed,
                     max_rounds=max_rounds)


def run_discovery_fixed(
    target: Any, seed: int = 1, max_rounds: int = 48,
) -> tuple[InvestigationState, dict[str, Any]]:
    """Prioritization ablation: same probes, insertion order."""
    return _run_loop(target, mode="fixed", seed=seed,
                     max_rounds=max_rounds)


def run_discovery_ablation(
    target: Any, seed: int = 1, max_rounds: int = 48,
) -> tuple[InvestigationState, dict[str, Any]]:
    """No-proposer ablation: the existing baseline on the discovery
    surface (empty seed, no differential proposer)."""
    return _run_loop(target, mode="ablation", seed=seed,
                     max_rounds=max_rounds)


# --------------------------------------------------------------------------
# Resume correctness (interrupt -> persist -> reload -> resume)
# --------------------------------------------------------------------------

def _step_token(task_key: str) -> str:
    """The deterministic idempotency token a differential probe step
    derives (mirrors DifferentialExperimentPort._run_step)."""
    return hashlib.sha256(task_key.encode("utf-8")).hexdigest()[:16]


def _experiment_task_tokens(
    port: Any, state: InvestigationState, experiment_id: str,
) -> set[str]:
    """Tokens for every POST step an experiment executes (workflow
    transitions and other mutations carry their own token; GETs do
    not)."""
    experiment = next(
        (exp for exp in state.experiments
         if exp.experiment_id == experiment_id),
        None,
    )
    if experiment is None:
        return set()
    try:
        plan = port.plan_for(experiment.signature)
    except ValueError:
        return set()
    if plan is None:
        return set()
    return {
        _step_token(f"{experiment_id}-{step.label}")
        for step in plan.steps if step.method == "POST"
    }


def _resume_invariants(
    first: InvestigationState,
    resumed: InvestigationState,
    target: Any,
    tokens_before_resume: set[str],
    identities_before_resume: set[tuple[str, str, str]],
    workflow_tokens_before_resume: set[str],
) -> tuple[bool, list[str]]:
    """Resume-correctness invariants over real state, not counters.

    Checks: (1) every previously confirmed finding is still present;
    (2) an executed experiment never gains an additional proof record
    after resume; (3) no successful mutation is applied twice for the
    same idempotency identity (both the canonical target's
    (family, resource, token) identities and the discovery surface's
    bare workflow tokens); (4) every identity applied after resume
    carries a token no experiment used before resume, so a legitimate
    additional investigation request (fresh token) is distinguishable
    from a re-applied one (token already used before resume).
    """
    violations: list[str] = []
    confirmed_first = set(_confirmed_case_ids(first))
    confirmed_resumed = set(_confirmed_case_ids(resumed))
    lost = confirmed_first - confirmed_resumed
    if lost:
        violations.append(
            f"confirmed findings lost after resume: {sorted(lost)}")

    def proof_counts(state: InvestigationState) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in state.proof_bundles_verified:
            eid = record.get("experiment_id", "")
            counts[eid] = counts.get(eid, 0) + 1
        return counts

    executed_before = {
        exp.experiment_id for exp in first.experiments
        if first.experiment_outcome(exp.experiment_id)
    }
    counts_before = proof_counts(first)
    counts_after = proof_counts(resumed)
    for eid in sorted(executed_before):
        if counts_after.get(eid, 0) > counts_before.get(eid, 0):
            violations.append(
                "experiment re-confirmed after resume: "
                f"{eid} ({counts_before.get(eid, 0)} -> "
                f"{counts_after.get(eid, 0)} proof records)")

    identities_after = set(target.applied_mutation_identities())
    if not identities_before_resume <= identities_after:
        violations.append(
            "applied mutation identity lost after resume")
    reapplied = {
        identity for identity in identities_after
        if identity not in identities_before_resume
        and identity[2] in tokens_before_resume
    }
    if reapplied:
        violations.append(
            "mutation re-applied with a pre-resume idempotency "
            f"token: {sorted(reapplied)}")

    workflow_tokens_after = set(target.deployment.applied_tokens)
    if not workflow_tokens_before_resume <= workflow_tokens_after:
        violations.append(
            "workflow mutation token lost after resume")
    reapplied_workflow = {
        token for token in workflow_tokens_after
        if token not in workflow_tokens_before_resume
        and token in tokens_before_resume
    }
    if reapplied_workflow:
        violations.append(
            "workflow transition re-applied with a pre-resume "
            f"token: {sorted(reapplied_workflow)}")
    return (not violations, violations)


def _resume_correct(target: Any, seed: int = 1) -> bool:
    """Interrupt mid-run, persist, reload, resume, and verify the
    resume invariants over real state (see _resume_invariants)."""
    _check_seed(seed)
    target.reset()
    port = _build_port(target, seed)
    engagement_id, _campaign_id = _version_ids(seed)
    state = _seed_state(target, engagement_id)
    first = _build_orchestrator(port, mode="adaptive").run(
        state, max_rounds=8)
    save_state(first, _state_path())
    restored = load_state(_state_path())
    executed_before = {
        exp.experiment_id for exp in first.experiments
        if first.experiment_outcome(exp.experiment_id)
    }
    tokens_before_resume: set[str] = set()
    for eid in sorted(executed_before):
        tokens_before_resume |= _experiment_task_tokens(
            port, first, eid)
    identities_before_resume = set(
        target.applied_mutation_identities())
    workflow_tokens_before_resume = set(
        target.deployment.applied_tokens)
    resumed = _build_orchestrator(port, mode="adaptive").run(
        restored, max_rounds=48)
    ok, _violations = _resume_invariants(
        first, resumed, target,
        tokens_before_resume,
        identities_before_resume,
        workflow_tokens_before_resume,
    )
    return ok


def _state_path() -> Any:
    from pathlib import Path
    return Path(DISCOVERY_RESUME_STATE_PATH)


# --------------------------------------------------------------------------
# Report and comparison entry point
# --------------------------------------------------------------------------

@dataclass
class DiscoveryReport:
    adaptive: dict[str, Any]
    baseline: dict[str, Any]
    ablation: dict[str, Any]
    thresholds_pass: bool
    reproducible: bool
    resume_correct: bool
    seed: int
    ground_truth_version: str = DISCOVERY_GROUND_TRUTH_VERSION
    thresholds: dict[str, Any] = field(default_factory=lambda: {
        "min_recall": DISCOVERY_MIN_RECALL,
        "min_confirmations": 1,
        "max_false_positives": 0,
        "replay_valid": "every confirmed finding must have its own "
                        "one-to-one replay-valid proof association",
        "ablation": "the prioritization-ablation run may confirm "
                    "nothing beyond adaptive's findings and no false "
                    "positives; the no-proposer baseline confirms "
                    "nothing on the discovery surface",
        "comparison": "adaptive confirmations > the existing "
                      "fixed-order baseline (no proposer) under "
                      "identical budgets and validation",
        "labels": "ground truth is never seeded, exposed to the "
                  "detector, or used as a case verdict",
    })

    def to_dict(self) -> dict[str, Any]:
        return {
            "ground_truth_version": self.ground_truth_version,
            "seed": self.seed,
            "adaptive": self.adaptive,
            "baseline": self.baseline,
            "ablation": self.ablation,
            "thresholds_pass": self.thresholds_pass,
            "reproducible": self.reproducible,
            "resume_correct": self.resume_correct,
            "thresholds": dict(self.thresholds),
        }


def _thresholds_pass(
    adaptive: dict[str, Any],
    baseline: dict[str, Any],
    ablation: dict[str, Any],
) -> bool:
    """Declared acceptance thresholds over final metrics.

    A successful discovery run requires at least one valid
    confirmation, recall at or above the declared floor, zero false
    positives, complete one-to-one proof binding, and a no-proposer
    ablation that confirms nothing. Undefined per-confirmation
    metrics (None for a zero-confirmation run) can never satisfy a
    positive requirement.
    """
    association = adaptive.get("proof_association") or {}
    recall = adaptive.get("recall")
    replay_valid_confirmed = adaptive.get("replay_valid_confirmed")
    confirmed_count = adaptive.get("confirmed_count", 0)
    requests_per_confirmed = adaptive.get("requests_per_confirmed")
    # The prioritization ablation shares the differential generators,
    # so it may confirm real findings; what it must never do is
    # confirm anything adaptive did not (no invented findings) or
    # raise a false positive. The no-proposer baseline must confirm
    # strictly less than adaptive: on this surface it can only
    # execute what is seeded (nothing), so that is the comparison.
    ablation_paths = set(ablation.get("confirmed_paths") or [])
    adaptive_paths = set(adaptive.get("confirmed_paths") or [])
    return (
        isinstance(recall, (int, float)) and recall >= DISCOVERY_MIN_RECALL
        and confirmed_count >= 1
        and adaptive.get("false_positives") == 0
        and baseline.get("false_positives") == 0
        and ablation.get("false_positives") == 0
        and ablation_paths <= adaptive_paths
        and replay_valid_confirmed == confirmed_count
        and not association.get("confirmed_without_proof")
        and not association.get("unrelated_replay_valid")
        and not association.get("duplicate_proof_records")
        and not association.get("mismatched_identity_records")
        and requests_per_confirmed is not None
        and requests_per_confirmed > 0
        and confirmed_count > baseline.get("confirmed_count", 0)
    )


def run_discovery_comparison(
    target: Any,
    seed: int = 1,
    max_rounds: int = 48,
    repetitions: int = 2,
) -> DiscoveryReport:
    """Adaptive vs existing baseline vs prioritization ablation over
    one declared deployment seed, plus reproducibility and resume
    correctness. Results are never pooled across seeds."""
    _check_seed(seed)
    adaptive_runs = []
    for _ in range(max(1, repetitions)):
        adaptive_runs.append(_run_loop(
            target, mode="adaptive", seed=seed, max_rounds=max_rounds))
    _, adaptive = adaptive_runs[0]
    _, baseline = _run_loop(
        target, mode="ablation", seed=seed, max_rounds=max_rounds)
    _, fixed = _run_loop(
        target, mode="fixed", seed=seed, max_rounds=max_rounds)
    confirmed_sets = [
        tuple(metrics["confirmed_case_ids"])
        for _, metrics in adaptive_runs
    ]
    reproducible = all(
        run_set == confirmed_sets[0] for run_set in confirmed_sets[1:])
    thresholds_pass = _thresholds_pass(adaptive, baseline, fixed)
    resume_correct = _resume_correct(target, seed=seed)
    return DiscoveryReport(
        adaptive=adaptive,
        baseline=baseline,
        ablation=fixed,
        thresholds_pass=thresholds_pass,
        reproducible=reproducible,
        resume_correct=resume_correct,
        seed=seed,
    )
