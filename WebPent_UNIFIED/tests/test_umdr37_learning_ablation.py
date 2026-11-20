"""UM-DR-37 Part 10.2 — causal learning-between-decisions proof (G37-14).

Run A (feedback enabled) vs Run B (feedback ablated) over the SAME
seeded investigation state, using the REAL InformationGainSelector and
the REAL InvestigationState schema. The only difference between arms is
the evidence channel into selection: Run B's selector sees the same
state minus the recorded evidence items.

The causal chain proven here, deterministically:

    Observation (evidence item for experiment E_a1)
      -> Model update (evidence tally: H_a +1)
      -> Ranking change (E_a2 score +0.25)
      -> Experiment selection change (E_a2 selected instead of E_b1)
"""

from __future__ import annotations

from dataclasses import replace

from webpent.egaie.repetition import RepetitionRegister
from webpent.egaie.schemas import (
    EvidenceItem,
    EvidenceKind,
    HypothesisRecord,
    HypothesisStatus,
    InvestigationState,
    ProposedExperiment,
)
from webpent.egaie.selection import InformationGainSelector


class AblatedFeedbackSelector(InformationGainSelector):
    """Run-B arm: cut the evidence channel into SELECTION only.

    The selector sees the same state minus the recorded evidence items
    (no evidence tally, no evidence-derived lifts). Everything else —
    the repetition register, termination, candidate set, static scores
    — is untouched, so any decision difference between arms is
    attributable to the recorded evidence alone.
    """

    def select(self, state, candidates, register, *args, **kwargs):
        ablated = replace(state, evidence=[])
        return super().select(ablated, candidates, register, *args,
                              **kwargs)


def _seed_state() -> InvestigationState:
    return InvestigationState(
        engagement_id="umdr37-learning-ablation",
        target_url="https://authorized-lab.invalid",
        round=1,
        hypotheses=[
            HypothesisRecord(hypothesis_id="H_a", family="fam_a",
                             statement="hypothesis A"),
            HypothesisRecord(hypothesis_id="H_b", family="fam_b",
                             statement="hypothesis B"),
        ],
        experiments=[
            # E_a1 was EXECUTED in round 1 (not a candidate any more)
            ProposedExperiment(
                experiment_id="E_a1", family="fam_a",
                signature="sig-a1", description="executed probe",
                cost=0.0, risk=0.0, gain_estimate=0.6,
                rationale="round-1 probe", hypothesis_id="H_a"),
        ],
        evidence=[],
        decisions=[],
        observations=[],
    )


def _candidates() -> list[ProposedExperiment]:
    return [
        ProposedExperiment(
            experiment_id="E_a2", family="fam_a", signature="sig-a2",
            description="follow-up on H_a", cost=0.0, risk=0.0,
            gain_estimate=0.6, rationale="follow-up", hypothesis_id="H_a"),
        ProposedExperiment(
            experiment_id="E_b1", family="fam_b", signature="sig-b1",
            description="first probe of H_b", cost=0.0, risk=0.0,
            gain_estimate=0.7, rationale="statically best",
            hypothesis_id="H_b"),
    ]
    # static scores (no evidence): E_b1 = 0.7+0.5 = 1.2 > E_a2 = 1.1


def _observed_state() -> InvestigationState:
    """The seeded state AFTER round 1's observation landed: E_a1's
    outcome was recorded as SUPPORTING evidence for H_a."""
    state = _seed_state()
    state.evidence.append(EvidenceItem(
        evidence_id="ev-1", kind=EvidenceKind.SUPPORTING,
        source="round-1 execution", ref="E_a1",
        summary="E_a1 discriminated H_a", round=1))
    return state


def test_same_seed_no_evidence_decisions_are_identical() -> None:
    """Sanity: with no recorded evidence the arms must decide
    identically (the ablation is invisible without feedback)."""
    selector = InformationGainSelector()
    ablated = AblatedFeedbackSelector()
    state = _seed_state()
    run_a = selector.select(state, _candidates(), RepetitionRegister())
    run_b = ablated.select(state, _candidates(), RepetitionRegister())
    assert run_a.selected_experiment_id == run_b.selected_experiment_id
    assert run_a.scores == run_b.scores


def test_evidence_changes_the_second_decision_causally() -> None:
    """THE causal proof: the SAME observed state, selection with vs
    without the evidence channel, yields a DIFFERENT next experiment —
    and the difference is exactly the evidence lift on H_a's candidate."""
    selector = InformationGainSelector()
    ablated = AblatedFeedbackSelector()
    state = _observed_state()

    run_a = selector.select(state, _candidates(), RepetitionRegister())
    run_b = ablated.select(state, _candidates(), RepetitionRegister())

    # Run B (no feedback): the statically-best experiment is chosen.
    assert run_b.selected_experiment_id == "E_b1"
    assert run_b.scores["E_a2"] == 1.1  # 0.6 gain + 0.5 family bonus
    assert run_b.scores["E_b1"] == 1.2

    # Run A (feedback): H_a's evidence tally (+1) lifts E_a2 by exactly
    # EVIDENCE_LIFT and flips the selection.
    assert run_a.selected_experiment_id == "E_a2"
    assert run_a.scores["E_a2"] == 1.1 + InformationGainSelector.EVIDENCE_LIFT
    assert run_a.scores["E_b1"] == 1.2  # untouched by H_a's evidence

    # The decision difference is caused by the evidence item alone: the
    # arms saw identical candidates, register, and static state.
    assert run_a.selected_experiment_id != run_b.selected_experiment_id
    delta = run_a.scores["E_a2"] - run_b.scores["E_a2"]
    assert delta == InformationGainSelector.EVIDENCE_LIFT


def test_contradicting_evidence_reorders_downward() -> None:
    """The same causal channel runs in reverse: contradicting evidence
    must LOWER the affected hypothesis's candidate."""
    selector = InformationGainSelector()
    ablated = AblatedFeedbackSelector()
    state = _observed_state()
    state.evidence.append(EvidenceItem(
        evidence_id="ev-2", kind=EvidenceKind.CONTRADICTING,
        source="round-1 execution", ref="E_a1",
        summary="second observation contradicts", round=1))
    # net tally for H_a is now 0 -> no lift
    run_a = selector.select(state, _candidates(), RepetitionRegister())
    run_b = ablated.select(state, _candidates(), RepetitionRegister())
    assert run_a.selected_experiment_id == "E_b1"
    assert run_a.scores["E_a2"] == 1.1
    assert run_a.scores == run_b.scores


def test_supported_status_lifts_confidence_independently() -> None:
    """The model-update channel is layered: a SUPPORTED hypothesis
    adds the confidence lift on top of the evidence tally (both are
    recorded-state updates, both flow into the next decision)."""
    selector = InformationGainSelector()
    state = _observed_state()
    state.hypotheses[0] = state.hypotheses[0].with_status(
        HypothesisStatus.SUPPORTED)
    run_a = selector.select(state, _candidates(), RepetitionRegister())
    expected = (1.1
                + InformationGainSelector.EVIDENCE_LIFT
                + InformationGainSelector.SUPPORTED_CONFIDENCE_LIFT)
    assert run_a.scores["E_a2"] == expected
    assert run_a.selected_experiment_id == "E_a2"
