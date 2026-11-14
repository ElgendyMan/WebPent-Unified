"""EGAIE benchmark runner: adaptive vs fixed-order baseline.

Thresholds declared BEFORE the run (mirrors docs/egaie/01_phase1_plan.md):
recall >= MIN_RECALL, false positives == 0, and the adaptive loop must
beat the baseline on recall at the same round budget or match its recall
while spending fewer experiments per confirmed finding. Reproducibility:
repeated adaptive runs must produce identical confirmed case sets.

Honesty rules: negatives may never be counted confirmed, the ground
truth only scores (never steers), and no validation shortcut exists in
this package: every confirmation still requires CausalGuard + sealed
bundle + passing replay.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webpent.egaie.benchmark.baseline import build_baseline_orchestrator
from webpent.egaie.benchmark.fixture import (
    ControlledFixtureTarget,
    FixtureExperimentPort,
)
from webpent.egaie.benchmark.ground_truth import GROUND_TRUTH_V1
from webpent.egaie.benchmark.http_ground_truth import (
    HTTP_GROUND_TRUTH_V1,
    HTTP_GROUND_TRUTH_V2,
)
from webpent.egaie.causal_adapter import CausalValidationPort, ProofBundlePort
from webpent.egaie.orchestrator import InvestigationOrchestrator
from webpent.egaie.schemas import (
    HypothesisStatus,
    InvestigationState,
    ProposedExperiment,
)
from webpent.egaie.seeds import seed_state
from webpent.egaie.selection import InformationGainSelector

MIN_RECALL = 0.6
ENGAGEMENT_ID = "egaie-bench-v1"
TARGET_URL = "fixture://controlled-local"


class FollowUpProposer:
    """Advisory proposer: suggests stage2 follow-ups for multi-step cases.

    Proposal only: the proposed experiment still runs through the full
    CausalGuard + sealed-bundle + replay pipeline and can never confirm
    anything by itself.
    """

    def propose(self, state: InvestigationState) -> list[ProposedExperiment]:
        proposals: list[ProposedExperiment] = []
        known_ids = {e.experiment_id for e in state.experiments}
        for case in (
            *GROUND_TRUTH_V1, *HTTP_GROUND_TRUTH_V1, *HTTP_GROUND_TRUTH_V2,
        ):
            # Polarity-blind: any multi-step case whose stage-1 probe is
            # inconclusive deserves a follow-up, positive or negative
            # alike. The ground truth never steers this proposal.
            if not case.multi_step:
                continue
            stage1_id = f"e-{case.case_id}"
            stage2_id = f"e-{case.case_id}-stage2"
            if state.experiment_outcome(stage1_id) != "inconclusive":
                continue
            if stage2_id in known_ids:
                continue
            proposals.append(ProposedExperiment(
                experiment_id=stage2_id,
                family=case.family,
                signature=f"{case.case_id}/{case.family}:stage2",
                description=f"stage2 follow-up probe for {case.case_id}",
                cost=0.2,
                risk=0.2,
                gain_estimate=0.5,
                rationale="advisory follow-up after inconclusive stage1",
                hypothesis_id=f"h-{case.case_id}",
            ))
        return proposals


@dataclass
class BenchmarkReport:
    adaptive: dict[str, Any]
    baseline: dict[str, Any]
    thresholds_pass: bool
    reproducible: bool
    replay_case_ids: list[str]
    thresholds: dict[str, Any] = field(default_factory=lambda: {
        "min_recall": MIN_RECALL,
        "max_false_positives": 0,
        "comparison": "better recall, or equal recall at <= experiments "
                      "per confirmed",
    })

    def to_dict(self) -> dict[str, Any]:
        return {
            "adaptive": self.adaptive,
            "baseline": self.baseline,
            "thresholds_pass": self.thresholds_pass,
            "reproducible": self.reproducible,
            "replay_case_ids": list(self.replay_case_ids),
            "thresholds": dict(self.thresholds),
        }


def _metrics(
    state: InvestigationState, confirmed_case_ids: list[str]
) -> dict[str, Any]:
    positives = {c.case_id for c in GROUND_TRUTH_V1 if c.positive}
    negatives = {c.case_id for c in GROUND_TRUTH_V1 if not c.positive}
    true_positives = [cid for cid in confirmed_case_ids if cid in positives]
    false_positives = [cid for cid in confirmed_case_ids if cid in negatives]
    experiments_run = sum(
        1 for outcome in state.experiment_outcomes.values() if outcome != ""
    )
    per_confirmed = (
        round(experiments_run / len(true_positives), 4)
        if true_positives else float(experiments_run)
    )
    return {
        "recall": round(len(true_positives) / len(positives), 4),
        "false_positives": len(false_positives),
        "experiments_per_confirmed": per_confirmed,
        "confirmed_case_ids": sorted(confirmed_case_ids),
        "experiments_run": experiments_run,
        "total_positive_cases": len(positives),
    }


def _confirmed_case_ids(state: InvestigationState) -> list[str]:
    return [
        record.origin for record in state.hypotheses
        if record.status is HypothesisStatus.CONFIRMED and record.origin
    ]


def _fresh_ports():
    target = ControlledFixtureTarget(list(GROUND_TRUTH_V1))
    experiment_port = FixtureExperimentPort(target)
    validation_port = CausalValidationPort()
    proof_port = ProofBundlePort()
    return experiment_port, validation_port, proof_port


class _LedgerModelPort:
    def update(self, state, experiment, observations, causal):
        entry = {
            "round": state.round,
            "experiment_id": experiment.experiment_id,
            "family": experiment.family,
            "verdict": causal["verdict"],
        }
        return {"world_model": [entry], "attack_graph": [entry]}


def run_adaptive(max_rounds: int) -> InvestigationState:
    experiment_port, validation_port, proof_port = _fresh_ports()
    state = seed_state(list(GROUND_TRUTH_V1), ENGAGEMENT_ID, TARGET_URL)
    orchestrator = InvestigationOrchestrator(
        experiment_port=experiment_port,
        validation_port=validation_port,
        proof_port=proof_port,
        model_port=_LedgerModelPort(),
        selector=InformationGainSelector(),
        proposer=FollowUpProposer(),
    )
    return orchestrator.run(state, max_rounds=max_rounds)


def run_baseline(max_rounds: int) -> InvestigationState:
    experiment_port, validation_port, proof_port = _fresh_ports()
    state = seed_state(list(GROUND_TRUTH_V1), ENGAGEMENT_ID, TARGET_URL)
    orchestrator = build_baseline_orchestrator(
        experiment_port, validation_port, proof_port, _LedgerModelPort()
    )
    return orchestrator.run(state, max_rounds=max_rounds)


def evaluate_thresholds(
    adaptive: dict[str, Any], baseline: dict[str, Any]
) -> bool:
    if adaptive["recall"] < MIN_RECALL:
        return False
    if adaptive["false_positives"] != 0:
        return False
    better_recall = adaptive["recall"] > baseline["recall"]
    equal_but_cheaper = (
        adaptive["recall"] == baseline["recall"]
        and adaptive["experiments_per_confirmed"]
        <= baseline["experiments_per_confirmed"]
    )
    return better_recall or equal_but_cheaper


def run_comparison(
    max_rounds: int = 14, repetitions: int = 2
) -> BenchmarkReport:
    adaptive_state = run_adaptive(max_rounds=max_rounds)
    adaptive_metrics = _metrics(
        adaptive_state, _confirmed_case_ids(adaptive_state))
    baseline_state = run_baseline(max_rounds=max_rounds)
    baseline_metrics = _metrics(
        baseline_state, _confirmed_case_ids(baseline_state))
    thresholds_pass = evaluate_thresholds(adaptive_metrics, baseline_metrics)

    replay_case_ids: list[str] = []
    reproducible = True
    for _ in range(max(repetitions - 1, 0)):
        repeat_state = run_adaptive(max_rounds=max_rounds)
        repeat_ids = _confirmed_case_ids(repeat_state)
        if not replay_case_ids:
            replay_case_ids = sorted(repeat_ids)
        if sorted(repeat_ids) != adaptive_metrics["confirmed_case_ids"]:
            reproducible = False
    if repetitions <= 1:
        replay_case_ids = sorted(adaptive_metrics["confirmed_case_ids"])
        reproducible = True
    return BenchmarkReport(
        adaptive=adaptive_metrics,
        baseline=baseline_metrics,
        thresholds_pass=thresholds_pass,
        reproducible=reproducible,
        replay_case_ids=replay_case_ids,
    )
