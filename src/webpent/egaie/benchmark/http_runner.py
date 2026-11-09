"""EGAIE real-HTTP benchmark harness (adaptive vs fixed baseline).

Same target version, same request budgets, same validation rules for
both loops: every run drives the production ActionExecutor path
against a live controlled HTTP target. Results are reported separately
from the six-case in-process fixture benchmark and are never pooled.

Acceptance thresholds were declared before the evaluation
(docs/egaie/10_phase0_http_audit.md) and are enforced by
HTTPReport.thresholds_pass.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from webpent.autonomous.authorization import EngagementAuthorization
from webpent.config.settings import ScanMode, Settings
from webpent.egaie.benchmark.baseline import build_baseline_orchestrator
from webpent.egaie.benchmark.http_ground_truth import (
    HTTP_GROUND_TRUTH_V1,
    HTTP_GROUND_TRUTH_V2,
    HTTP_GROUND_TRUTH_V3,
    HTTP_GROUND_TRUTH_VERSION,
    HTTP_GROUND_TRUTH_VERSION_V2,
    HTTP_GROUND_TRUTH_VERSION_V3,
    HTTPCase,
)
from webpent.egaie.benchmark.runner import FollowUpProposer
from webpent.egaie.causal_adapter import CausalValidationPort
from webpent.egaie.http_port import (
    HTTPProofBundlePort,
    build_http_experiment_port,
)
from webpent.egaie.logic_port import (
    InvariantValidationPort,
    LogicFollowUpProposer,
    LogicProofBundlePort,
    build_logic_experiment_port,
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

HTTP_MIN_RECALL = 0.6
HTTP_ENGAGEMENT_ID = "egaie-http-benchmark-v1"
HTTP_CAMPAIGN_ID = "egaie-http-campaign-v1"
HTTP_MAX_ACTIONS = 200
RESUME_STATE_PATH = "/tmp/egaie_http_benchmark_resume_state.json"

# Declared ground-truth sets only: results are reported per version and
# never pooled across versions. Any case list that is not a declared
# version is rejected rather than silently benchmarked.
_DECLARED_VERSIONS: dict[tuple[HTTPCase, ...], str] = {
    HTTP_GROUND_TRUTH_V1: HTTP_GROUND_TRUTH_VERSION,
    HTTP_GROUND_TRUTH_V2: HTTP_GROUND_TRUTH_VERSION_V2,
    HTTP_GROUND_TRUTH_V3: HTTP_GROUND_TRUTH_VERSION_V3,
}


def _ground_truth_version(cases: tuple[HTTPCase, ...]) -> str:
    try:
        return _DECLARED_VERSIONS[tuple(cases)]
    except KeyError as exc:
        raise ValueError(
            "cases must be a declared HTTP ground-truth version"
        ) from exc


def _task_token(task_key: str) -> str:
    """The deterministic idempotency token a task derives (mirrors
    LogicExperimentPort._params / HTTPExperimentPort._params)."""
    return hashlib.sha256(task_key.encode("utf-8")).hexdigest()[:16]


def _experiment_task_tokens(experiment_id: str) -> set[str]:
    """Tokens for every task an experiment executes (one probe request
    per role), used to tell a legitimate new mutation (fresh token) from
    a re-applied one (token already used before resume)."""
    return {
        _task_token(f"{experiment_id}-{role}")
        for role in ("baseline", "candidate", "control")
    }


class _LedgerModelPort:
    """No-op world-model ledger: HTTP benchmark needs no world model."""

    def propose(self, state: InvestigationState) -> list[ProposedExperiment]:
        return []

    def update(
        self, state: InvestigationState, experiment: ProposedExperiment,
        observations: Any, causal: Any,
    ) -> dict[str, Any]:
        return {"world_model": [], "attack_graph": []}


class _NoopSelector:
    """Selector that only terminates when nothing is pending."""

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


def _authorization(
    target: Any, engagement_id: str = HTTP_ENGAGEMENT_ID,
) -> EngagementAuthorization:
    return EngagementAuthorization(
        target_origin=target.target_origin,
        scope=(target.target_origin,),
        operator="benchmark-operator",
        authorization_reference=engagement_id,
    )


def _logic_version(cases: tuple[HTTPCase, ...]) -> bool:
    """http-v3 is the Logic Breaker version: it is validated by the
    independent invariant oracle and sealed by the logic proof bundle
    port, never by the read-only CausalGuard contract."""
    return _ground_truth_version(cases) == HTTP_GROUND_TRUTH_VERSION_V3


def _build_orchestrator(
    port: Any, adaptive: bool,
    cases: tuple[HTTPCase, ...] = HTTP_GROUND_TRUTH_V1,
) -> Any:
    if _logic_version(cases):
        if adaptive:
            return InvestigationOrchestrator(
                experiment_port=port,
                validation_port=InvariantValidationPort(),
                proof_port=LogicProofBundlePort(),
                model_port=_LedgerModelPort(),
                selector=InformationGainSelector(),
                proposer=LogicFollowUpProposer(),
            )
        return build_baseline_orchestrator(
            port,
            InvariantValidationPort(),
            LogicProofBundlePort(),
            _LedgerModelPort(),
        )
    if adaptive:
        return InvestigationOrchestrator(
            experiment_port=port,
            validation_port=CausalValidationPort(),
            proof_port=HTTPProofBundlePort(),
            model_port=_LedgerModelPort(),
            selector=InformationGainSelector(),
            proposer=FollowUpProposer(),
        )
    return build_baseline_orchestrator(
        port,
        CausalValidationPort(),
        HTTPProofBundlePort(),
        _LedgerModelPort(),
    )


def _version_ids(cases: tuple[HTTPCase, ...]) -> tuple[str, str]:
    version = _ground_truth_version(cases)
    return (
        f"egaie-http-benchmark-{version}",
        f"egaie-http-campaign-{version}",
    )


def _mutates(cases: tuple[HTTPCase, ...]) -> bool:
    return any(case.method != "GET" for case in cases)


def _build_port(target: Any, cases: tuple[HTTPCase, ...] = HTTP_GROUND_TRUTH_V1) -> Any:
    engagement_id, campaign_id = _version_ids(cases)
    scan_mode = (
        ScanMode.AUTHORIZED_ACTIVE if _mutates(cases)
        else ScanMode.SAFE_SMART
    )
    build_port = (
        build_logic_experiment_port if _logic_version(cases)
        else build_http_experiment_port
    )
    return build_port(
        target=target,
        engagement_id=engagement_id,
        campaign_id=campaign_id,
        authorization=_authorization(target, engagement_id),
        settings=Settings(
            scan_mode=scan_mode,
            smart_max_actions=HTTP_MAX_ACTIONS,
        ),
    )


def _seed(
    target: Any,
    cases: tuple[HTTPCase, ...] = HTTP_GROUND_TRUTH_V1,
    engagement_id: str = HTTP_ENGAGEMENT_ID,
) -> InvestigationState:
    return seed_state(
        list(cases), engagement_id,
        target.target_origin,
    )


def _confirmed_case_ids(state: InvestigationState) -> list[str]:
    return sorted({
        hypothesis.origin
        for hypothesis in state.hypotheses
        if hypothesis.status.value == "confirmed" and hypothesis.origin
    })


def _proof_association_metrics(
    state: InvestigationState,
) -> dict[str, Any]:
    """Deterministic one-to-one association between confirmed cases and
    their verified proofs.

    A replay-valid proof record counts toward a confirmed case only
    when BOTH trusted identities agree: the record's experiment_id must
    belong to an experiment bound to that case (via hypothesis_id
    h-{case_id} or the case prefix of the signature) AND the record's
    signature must carry the same case id. Each record is used at most
    once; records beyond the first for the same experiment are
    duplicates; replay-valid records bound to no confirmed case are
    unrelated; a record whose two identities disagree is mismatched.
    The association is never inferred from list lengths alone.
    """
    confirmed = _confirmed_case_ids(state)
    case_experiments: dict[str, set[str]] = {
        case_id: set() for case_id in confirmed
    }
    experiment_case: dict[str, str] = {}
    for exp in state.experiments:
        case_id: str | None = None
        if exp.hypothesis_id and exp.hypothesis_id.startswith("h-"):
            candidate = exp.hypothesis_id[len("h-"):]
            if candidate in case_experiments:
                case_id = candidate
        if case_id is None:
            sig_case = exp.signature.split("/", 1)[0]
            if sig_case in case_experiments:
                case_id = sig_case
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
        sig_case = str(record.get("signature", "")).split("/", 1)[0]
        if case_id is None or sig_case != case_id:
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


def _run_loop(
    target: Any, adaptive: bool, max_rounds: int,
    cases: tuple[HTTPCase, ...] = HTTP_GROUND_TRUTH_V1,
) -> tuple[InvestigationState, dict[str, Any]]:
    started = time.monotonic()
    port = _build_port(target, cases)
    engagement_id, _campaign_id = _version_ids(cases)
    state = _seed(target, cases, engagement_id)
    state = _build_orchestrator(port, adaptive, cases).run(
        state, max_rounds=max_rounds)
    elapsed = round(time.monotonic() - started, 4)
    confirmed = _confirmed_case_ids(state)
    positives = {
        case.case_id for case in cases if case.positive
    }
    negatives = {
        case.case_id for case in cases if not case.positive
    }
    true_positives = [cid for cid in confirmed if cid in positives]
    false_positives = [cid for cid in confirmed if cid in negatives]
    replay_association = _proof_association_metrics(state)
    confirmed_count = len(confirmed)
    metrics: dict[str, Any] = {
        "ground_truth_version": _ground_truth_version(cases),
        "transport": "action_executor",
        "confirmed_count": confirmed_count,
        "confirmed_case_ids": confirmed,
        # Undefined (None) when there are no positives / no
        # confirmations: a ratio over zero is never reported as a
        # success metric.
        "recall": (
            round(len(true_positives) / len(positives), 4)
            if positives else None
        ),
        "false_positives": len(false_positives),
        "false_positive_case_ids": false_positives,
        "requests_made": port.requests_made,
        "requests_per_confirmed": (
            round(port.requests_made / confirmed_count, 4)
            if confirmed_count else None
        ),
        "replay_valid_confirmed": replay_association[
            "replay_valid_confirmed"
        ],
        "proof_association": replay_association,
        "wall_time_s": elapsed,
        "terminal_reason": state.terminal_reason,
        "per_case": {
            case.case_id: state.experiment_outcome(
                f"e-{case.case_id}")
            for case in cases
        },
    }
    return state, metrics


def run_http_adaptive(
    target: Any, max_rounds: int = 14,
    cases: tuple[HTTPCase, ...] = HTTP_GROUND_TRUTH_V1,
) -> tuple[InvestigationState, dict[str, Any]]:
    """Adaptive loop (information-gain selection + follow-ups)."""
    return _run_loop(target, adaptive=True, max_rounds=max_rounds,
                     cases=cases)


def run_http_baseline(
    target: Any, max_rounds: int = 14,
    cases: tuple[HTTPCase, ...] = HTTP_GROUND_TRUTH_V1,
) -> tuple[InvestigationState, dict[str, Any]]:
    """Fixed-order baseline (same port, validation and budgets)."""
    return _run_loop(target, adaptive=False, max_rounds=max_rounds,
                     cases=cases)


def _run_repeated_adaptive(
    target: Any, max_rounds: int, repetitions: int,
    cases: tuple[HTTPCase, ...] = HTTP_GROUND_TRUTH_V1,
):
    runs: list[tuple[InvestigationState, dict[str, Any]]] = []
    for _ in range(max(1, repetitions)):
        runs.append(_run_loop(target, adaptive=True,
                              max_rounds=max_rounds, cases=cases))
    return runs


def _resume_invariants(
    first: InvestigationState,
    resumed: InvestigationState,
    target: Any,
    tokens_before_resume: set[str],
    identities_before_resume: set[tuple[str, str, str]],
) -> tuple[bool, list[str]]:
    """Resume-correctness invariants over real state, not counters.

    Checks: (1) every previously confirmed finding is still present;
    (2) no logical case is confirmed a second time (an executed
    experiment never gains an additional proof record after resume);
    (3) no successful mutation is applied twice for the same
    idempotency identity, and every identity applied after resume
    carries a token no experiment used before resume, so a legitimate
    additional investigation request (fresh token) is distinguishable
    from a duplicate mutation (reused token). Request-count equality is
    never used as a substitute for any of these.
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
    if len(identities_after) != len(set(identities_after)):
        violations.append(
            "duplicate application recorded for one idempotency "
            "identity")
    reapplied = {
        identity for identity in identities_after
        if identity not in identities_before_resume
        and identity[2] in tokens_before_resume
    }
    if reapplied:
        violations.append(
            "mutation re-applied with a pre-resume idempotency "
            f"token: {sorted(reapplied)}")
    return (not violations, violations)


def _resume_correct(
    target: Any, cases: tuple[HTTPCase, ...] = HTTP_GROUND_TRUTH_V1,
) -> bool:
    """Interrupt mid-run, persist, reload, resume, and verify the
    resume invariants over real state (see _resume_invariants)."""
    port = _build_port(target, cases)
    engagement_id, _campaign_id = _version_ids(cases)
    state = _seed(target, cases, engagement_id)
    first = _build_orchestrator(port, adaptive=True, cases=cases).run(
        state, max_rounds=4)
    save_state(first, Path(RESUME_STATE_PATH))
    restored = load_state(Path(RESUME_STATE_PATH))
    executed_before = {
        exp.experiment_id for exp in first.experiments
        if first.experiment_outcome(exp.experiment_id)
    }
    tokens_before_resume: set[str] = set()
    for eid in executed_before:
        tokens_before_resume |= _experiment_task_tokens(eid)
    identities_before_resume = set(
        target.applied_mutation_identities())
    resumed = _build_orchestrator(port, adaptive=True, cases=cases).run(
        restored, max_rounds=14)
    ok, _violations = _resume_invariants(
        first, resumed, target,
        tokens_before_resume, identities_before_resume)
    return ok


@dataclass
class HTTPReport:
    adaptive: dict[str, Any]
    baseline: dict[str, Any]
    thresholds_pass: bool
    reproducible: bool
    resume_correct: bool
    ground_truth_version: str = HTTP_GROUND_TRUTH_VERSION
    thresholds: dict[str, Any] = field(default_factory=lambda: {
        "min_recall": HTTP_MIN_RECALL,
        "min_confirmations": 1,
        "max_false_positives": 0,
        "replay_valid": "every confirmed finding must have its own "
                        "one-to-one replay-valid proof association",
        "comparison": "adaptive confirmations > fixed-order baseline "
                      "under identical budgets and validation",
    })

    def to_dict(self) -> dict[str, Any]:
        return {
            "ground_truth_version": self.ground_truth_version,
            "adaptive": self.adaptive,
            "baseline": self.baseline,
            "thresholds_pass": self.thresholds_pass,
            "reproducible": self.reproducible,
            "resume_correct": self.resume_correct,
            "thresholds": dict(self.thresholds),
        }


def _thresholds_pass(adaptive: dict[str, Any], baseline: dict[str, Any]
                     ) -> bool:
    """Declared acceptance thresholds over final metrics.

    A successful detection run requires at least one valid
    confirmation; undefined per-confirmation metrics (None for a
    zero-confirmation run) can never satisfy a positive requirement,
    while a baseline with zero confirmations remains a legitimate
    comparison outcome.
    """
    association = adaptive.get("proof_association") or {}
    recall = adaptive.get("recall")
    replay_valid_confirmed = adaptive.get("replay_valid_confirmed")
    confirmed_count = adaptive.get("confirmed_count", 0)
    requests_per_confirmed = adaptive.get("requests_per_confirmed")
    return (
        isinstance(recall, (int, float)) and recall >= HTTP_MIN_RECALL
        and confirmed_count >= 1
        and adaptive.get("false_positives") == 0
        and baseline.get("false_positives") == 0
        and replay_valid_confirmed == confirmed_count
        and not association.get("confirmed_without_proof")
        and not association.get("unrelated_replay_valid")
        and not association.get("duplicate_proof_records")
        and not association.get("mismatched_identity_records")
        and requests_per_confirmed is not None
        and requests_per_confirmed > 0
        and confirmed_count > baseline.get("confirmed_count", 0)
    )


def run_http_comparison(
    target: Any,
    max_rounds: int = 14,
    repetitions: int = 2,
    cases: tuple[HTTPCase, ...] = HTTP_GROUND_TRUTH_V1,
) -> HTTPReport:
    """Adaptive vs fixed-order baseline over the same live HTTP target."""
    adaptive_runs = _run_repeated_adaptive(
        target, max_rounds, repetitions, cases=cases)
    _, adaptive = adaptive_runs[0]
    _, baseline = run_http_baseline(
        target, max_rounds=max_rounds, cases=cases)
    confirmed_sets = [
        tuple(metrics["confirmed_case_ids"])
        for _, metrics in adaptive_runs
    ]
    reproducible = all(
        run_set == confirmed_sets[0] for run_set in confirmed_sets[1:])
    thresholds_pass = _thresholds_pass(adaptive, baseline)
    resume_correct = _resume_correct(target, cases=cases)
    return HTTPReport(
        adaptive=adaptive,
        baseline=baseline,
        thresholds_pass=thresholds_pass,
        reproducible=reproducible,
        resume_correct=resume_correct,
        ground_truth_version=_ground_truth_version(cases),
    )
