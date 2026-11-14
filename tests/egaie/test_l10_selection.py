"""L10 Phase 5 — researcher-quality selection (red-first).

The selector integrates the observation record it already has with
the planner's prerequisite accounting: experiments whose
prerequisites are known-unavailable are never retried; resolved
hypotheses are never re-probed; historical blocked outcomes,
evidence quality, reversibility of the mutation and the remaining
budget all move the score. Nothing here invents evidence or
overrides the oracle: selection only chooses WHAT to run next, and
every chosen experiment still goes through the full pipeline.
"""
from __future__ import annotations

from typing import Any

from webpent.egaie.prerequisites import (
    Precondition,
    PreconditionKind,
    PreconditionStatus,
    UnattainableEffect,
)
from webpent.egaie.repetition import RepetitionRegister
from webpent.egaie.schemas import (
    DecisionAction,
    EvidenceItem,
    EvidenceKind,
    HypothesisRecord,
    HypothesisStatus,
    InvestigationState,
    ProposedExperiment,
)
from webpent.egaie.selection import (
    EXHAUSTED_SCORE,
    InformationGainSelector,
    ProposalOrderSelector,
)


def _state(*hypotheses: HypothesisRecord) -> InvestigationState:
    state = InvestigationState(engagement_id="e", target_url="t")
    for record in hypotheses:
        state.add_hypothesis(record)
    return state


def _hyp(hypothesis_id: str, status: HypothesisStatus = (
        HypothesisStatus.PROPOSED)) -> HypothesisRecord:
    return HypothesisRecord(
        hypothesis_id=hypothesis_id, family="IDOR",
        statement="s").with_status(status)


def _exp(experiment_id: str, family: str = "IDOR",
         signature: str = "sig", hypothesis_id: str = "",
         cost: float = 0.2, risk: float = 0.2,
         gain: float = 0.5) -> ProposedExperiment:
    return ProposedExperiment(
        experiment_id=experiment_id, family=family, signature=signature,
        description="d", cost=cost, risk=risk, gain_estimate=gain,
        rationale="r", hypothesis_id=hypothesis_id)


# -- prerequisite availability ----------------------------------------

def test_known_unavailable_prerequisite_is_never_selected() -> None:
    state = _state(_hyp("h-blocked"))
    available = _exp("e-cheap", hypothesis_id="h-other", gain=0.1)
    unavailable = _exp("e-rich", hypothesis_id="h-blocked", gain=9.0)
    decision = InformationGainSelector().select(
        state, [unavailable, available], RepetitionRegister(),
        unavailable_hypotheses=frozenset({"h-blocked"}))
    assert decision.selected_experiment_id == "e-cheap", (
        "an experiment whose prerequisites are known-unavailable is "
        "not retried, however attractive its gain estimate")
    assert decision.scores["e-rich"] == EXHAUSTED_SCORE


def test_all_candidates_unavailable_switches_strategy() -> None:
    state = _state(_hyp("h-blocked"))
    decision = InformationGainSelector().select(
        state, [_exp("e-1", hypothesis_id="h-blocked")],
        RepetitionRegister(),
        unavailable_hypotheses=frozenset({"h-blocked"}))
    assert decision.action is DecisionAction.STRATEGY_SWITCH


def test_unavailable_exclusion_is_opt_in() -> None:
    # Legacy call shape: no availability information supplied, the
    # selector behaves exactly as before (the same score formula).
    state = _state(_hyp("h-1"))
    exp = _exp("e-1", hypothesis_id="h-1", cost=0.2, risk=0.2,
               gain=0.5)
    decision = InformationGainSelector().select(
        state, [exp], RepetitionRegister())
    # legacy formula incl. the unresolved-family bonus
    assert decision.scores["e-1"] == round(0.5 + 0.5 - 0.2 - 0.2, 6)


# -- hypothesis confidence and resolution ------------------------------

def test_resolved_hypothesis_is_not_reprobed() -> None:
    state = _state(_hyp("h-done", HypothesisStatus.CONFIRMED))
    decision = InformationGainSelector().select(
        state, [_exp("e-1", hypothesis_id="h-done")],
        RepetitionRegister())
    assert decision.scores["e-1"] == EXHAUSTED_SCORE, (
        "a hypothesis the evidence has already resolved is not "
        "probed again")


def test_supported_hypothesis_outranks_bare_proposal() -> None:
    supported = _state(_hyp("h-s", HypothesisStatus.SUPPORTED))
    proposed = _state(_hyp("h-p"))
    selector = InformationGainSelector()
    exp_s = _exp("e-s", hypothesis_id="h-s")
    exp_p = _exp("e-p", hypothesis_id="h-p")
    d_s = selector.select(supported, [exp_s], RepetitionRegister())
    d_p = selector.select(proposed, [exp_p], RepetitionRegister())
    assert d_s.scores["e-s"] > d_p.scores["e-p"], (
        "evidence-backed confidence ranks above a bare proposal at "
        "equal cost and gain")


# -- historical outcomes and evidence quality --------------------------

def test_blocked_history_penalizes_the_hypothesis() -> None:
    state = _state(_hyp("h-1"), _hyp("h-2"))
    prior = _exp("e-prior", hypothesis_id="h-1")
    state.add_experiment(prior)
    state.mark_experiment_outcome("e-prior", "blocked")
    fresh = _exp("e-fresh", hypothesis_id="h-2")
    penalized = _exp("e-penalized", hypothesis_id="h-1")
    decision = InformationGainSelector().select(
        state, [penalized, fresh], RepetitionRegister())
    assert decision.scores["e-fresh"] > decision.scores["e-penalized"], (
        "a hypothesis whose earlier experiment came back blocked "
        "carries that history into the next selection")


def test_evidence_quality_moves_the_score() -> None:
    state = _state(_hyp("h-sup"), _hyp("h-con"))
    supporting = _exp("e-sup", hypothesis_id="h-sup")
    contradicting = _exp("e-con", hypothesis_id="h-con")
    state.add_experiment(supporting)
    state.add_experiment(contradicting)
    state.add_evidence(EvidenceItem(
        evidence_id="ev-1", kind=EvidenceKind.SUPPORTING,
        source="causal_guard", ref="e-sup", summary="s", round=1))
    state.add_evidence(EvidenceItem(
        evidence_id="ev-2", kind=EvidenceKind.CONTRADICTING,
        source="causal_guard", ref="e-con", summary="s", round=1))
    decision = InformationGainSelector().select(
        state, [contradicting, supporting], RepetitionRegister())
    assert decision.scores["e-sup"] > decision.scores["e-con"], (
        "supporting evidence lifts a candidate; contradicting "
        "evidence lowers it — selection reads the evidence record")


# -- reversibility and remaining budget --------------------------------

def test_state_advancing_mutation_is_penalized() -> None:
    state = _state(_hyp("h-1"), _hyp("h-2"))
    read_only = _exp("e-read", family="READONLY")
    mutating = _exp("e-mut", family="STATEFUL")
    decision = InformationGainSelector().select(
        state, [mutating, read_only], RepetitionRegister(),
        state_advancing_families=frozenset({"STATEFUL"}))
    assert decision.scores["e-read"] > decision.scores["e-mut"], (
        "at equal cost and gain, a reversible read outranks a "
        "state-advancing mutation")


def test_tight_budget_scales_cost_and_risk() -> None:
    state = _state(_hyp("h-1"), _hyp("h-2"), _hyp("h-3"))
    cheap = _exp("e-cheap", hypothesis_id="h-1", cost=0.1, risk=0.1,
                 gain=0.05)
    rich = _exp("e-rich", hypothesis_id="h-2", cost=0.8, risk=0.8,
                gain=1.5)
    register = RepetitionRegister()
    relaxed = InformationGainSelector().select(
        state, [rich, cheap], register, remaining_rounds=8)
    assert relaxed.selected_experiment_id == "e-rich", (
        "with budget to spare the richer experiment wins")
    tight = InformationGainSelector().select(
        state, [rich, cheap], register, remaining_rounds=1)
    assert tight.selected_experiment_id == "e-cheap", (
        "when the remaining rounds cannot cover the pending pool, "
        "cost and risk weigh more: a cheaper experiment that can "
        "still discriminate beats an expensive one that may never "
        "run")


# -- ablation E: information-gain selection disabled -------------------

def test_proposal_order_selector_ignores_gain() -> None:
    state = _state(_hyp("h-1"), _hyp("h-2"))
    first = _exp("e-first", hypothesis_id="h-1", gain=0.1)
    rich = _exp("e-rich", hypothesis_id="h-2", gain=9.0)
    decision = ProposalOrderSelector().select(
        state, [first, rich], RepetitionRegister())
    assert decision.action is DecisionAction.SELECT
    assert decision.selected_experiment_id == "e-first", (
        "the ablation takes the proposal order verbatim: no gain "
        "scoring, no family bonus, no reversibility term")


def test_proposal_order_selector_skips_exhausted() -> None:
    state = _state(_hyp("h-1"))
    register = RepetitionRegister()
    register.record("sig-x/IDOR", "inconclusive")
    register.record("sig-x/IDOR", "inconclusive")
    exhausted = _exp("e-x", signature="sig-x/IDOR")
    decision = ProposalOrderSelector().select(
        state, [exhausted], register)
    assert decision.action is DecisionAction.STRATEGY_SWITCH, (
        "the repetition register still holds: an exhausted "
        "signature is never re-run even under the ablation")


def test_proposal_order_selector_terminates_when_empty() -> None:
    state = _state()
    decision = ProposalOrderSelector().select(
        state, [], RepetitionRegister())
    assert decision.action is DecisionAction.TERMINATE


# -- orchestrator wiring ------------------------------------------------

def _planner_with_unattainable() -> Any:
    from webpent.egaie.planner import PlannerConfig, StatefulPlanner
    planner = StatefulPlanner(PlannerConfig())
    planner.ledger.declare("h-blocked", (
        Precondition(
            kind=PreconditionKind.APP_STATE,
            target="transition:/wf/items/1:source-state",
            status=PreconditionStatus.UNATTAINABLE),))
    planner.ledger.declare("h-open", (
        Precondition(
            kind=PreconditionKind.APP_STATE,
            target="transition:/wf/items/2:source-state",
            status=PreconditionStatus.ESTABLISHABLE),))
    return planner


def test_orchestrator_feeds_unavailable_hypotheses_to_selector() -> None:
    from types import SimpleNamespace

    from webpent.egaie import orchestrator as orch_module
    planner = _planner_with_unattainable()
    orch = orch_module.InvestigationOrchestrator(
        experiment_port=SimpleNamespace(scope_allowed=True),
        validation_port=None, proof_port=None, model_port=None,
        planner=planner)
    unavailable = orch._unavailable_hypotheses()
    assert "h-blocked" in unavailable, (
        "a hypothesis with an unattainable precondition is flagged "
        "unavailable from the planner's own ledger")
    assert "h-open" not in unavailable, (
        "an establishable precondition is not unavailable: the "
        "engine still derives and executes its setup")
    # every flagged id carries the never-a-verdict effect: an
    # unattainable precondition can never become a verdict.
    for hyp_id in unavailable:
        for precond in planner.ledger.get(hyp_id):
            if precond.blocks_execution:
                assert precond.verdict_effect is (
                    UnattainableEffect.NEVER_A_VERDICT)


def test_orchestrator_without_planner_flags_nothing() -> None:
    from types import SimpleNamespace

    from webpent.egaie import orchestrator as orch_module
    orch = orch_module.InvestigationOrchestrator(
        experiment_port=SimpleNamespace(scope_allowed=True),
        validation_port=None, proof_port=None, model_port=None)
    assert orch._unavailable_hypotheses() == frozenset(), (
        "the pre-L9 loop (strategy A) gets no availability input: "
        "its behavior is unchanged")
