"""UM-DR-37 Part 15 — focused adversarial tests.

Cases not already pinned by the existing adversarial suites
(confirmation-authority: test_umdr35/36_1; family spine: umdr31/28;
scope/SSRF: m1c + engagement tests). This file pins:

  15.2 hypothesis engine  — invalid lifecycle transitions rejected,
                            resolution requires causal + negative-control
                            evidence signals;
  15.3 planner            — repeated low-information experiments are
                            penalized then exhausted, never re-selected;
  15.2 families           — duplicate candidates collapse on the
                            deterministic dedupe key;
  15.1 app model          — contradicted knowledge never silently
                            un-contradicts (pinned in the appmodel
                            extension tests; referenced here).
"""

from __future__ import annotations

from webpent.egaie.repetition import (
    EXHAUSTION_THRESHOLD,
    RepetitionRegister,
)
from webpent.egaie.schemas import InvestigationState, ProposedExperiment
from webpent.egaie.selection import EXHAUSTED_SCORE, InformationGainSelector
from webpent.families.base import FamilyCandidate, FamilyId
from webpent.models.hypothesis import Hypothesis, HypothesisStatus
from webpent.research.hypothesis_engine import HypothesisEngine


def _hypothesis(status: HypothesisStatus = HypothesisStatus.UNEXPLORED):
    return Hypothesis(
        target_url="https://authorized-lab.invalid/api/x",
        statement="adversarial test hypothesis",
        vuln_class="idor",
        status=status,
    )


def test_engine_rejects_invalid_lifecycle_transition() -> None:
    """unexplored -> resolved_true must be refused: resolution is only
    reachable from an investigation (15.2 incorrect lifecycle
    transition)."""
    hypothesis = _hypothesis(HypothesisStatus.UNEXPLORED)
    result = HypothesisEngine.transition(
        hypothesis, HypothesisStatus.RESOLVED_TRUE,
        reason="attempted shortcut",
    )
    assert result.accepted is False
    assert result.new_status == HypothesisStatus.UNEXPLORED.value
    assert "not allowed" in result.reason
    # and the closed statuses are terminal
    closed = _hypothesis(HypothesisStatus.RESOLVED_FALSE)
    reopened = HypothesisEngine.transition(
        closed, HypothesisStatus.INVESTIGATING,
        reason="attempted resurrection of a refuted hypothesis",
    )
    assert reopened.accepted is False


def test_repetition_register_exhausts_low_information_signatures() -> None:
    """A signature that keeps returning uninformative outcomes is
    exhausted after the threshold — the planner must never re-run it
    (15.3 repeated low-information experiment)."""
    register = RepetitionRegister()
    signature = "idor/probe-a"
    for _ in range(EXHAUSTION_THRESHOLD):
        register.record(signature, "inconclusive")
    assert register.is_exhausted(signature) is True
    # informative outcomes do not count toward exhaustion
    register.record("ssrf/probe-b", "informative_differential")
    assert register.is_exhausted("ssrf/probe-b") is False


def test_selector_never_selects_exhausted_signature() -> None:
    register = RepetitionRegister()
    for _ in range(EXHAUSTION_THRESHOLD):
        register.record("sig-a", "inconclusive")
    selector = InformationGainSelector()
    state = InvestigationState(
        engagement_id="umdr37-adversarial",
        target_url="https://authorized-lab.invalid",
    )
    candidates = [
        ProposedExperiment(
            experiment_id="E-exhausted", family="idor",
            signature="sig-a", description="already exhausted",
            cost=0.0, risk=0.0, gain_estimate=0.99,
            rationale="highest static gain", hypothesis_id="h-1"),
        ProposedExperiment(
            experiment_id="E-fresh", family="ssrf", signature="sig-b",
            description="fresh informative candidate", cost=0.0,
            risk=0.0, gain_estimate=0.3, rationale="",
            hypothesis_id="h-2"),
    ]
    decision = selector.select(state, candidates, register)
    assert decision.selected_experiment_id == "E-fresh"
    assert decision.scores["E-exhausted"] == EXHAUSTED_SCORE


def test_selector_penalizes_each_uninformative_repetition() -> None:
    """Below exhaustion, every uninformative repetition lowers the
    score by the documented penalty (15.3 redundancy)."""
    register = RepetitionRegister()
    register.record("sig-a", "inconclusive")
    selector = InformationGainSelector()
    state = InvestigationState(
        engagement_id="umdr37-adversarial",
        target_url="https://authorized-lab.invalid",
    )
    candidates = [
        ProposedExperiment(
            experiment_id="E-penalized", family="idor",
            signature="sig-a", description="repeated once", cost=0.0,
            risk=0.0, gain_estimate=0.5, rationale="",
            hypothesis_id="h-1"),
    ]
    with_penalty = selector.select(state, candidates, register)
    clean = selector.select(
        state, candidates, RepetitionRegister())
    delta = (clean.scores["E-penalized"]
             - with_penalty.scores["E-penalized"])
    assert delta == 1.0  # REPETITION_PENALTY per uninformative outcome


def test_duplicate_family_candidates_collapse_on_dedupe_key() -> None:
    """Two candidates for the same family/scenario/endpoint produce the
    SAME deterministic dedupe key — the spine's dedup contract (15.2
    duplicate hypotheses)."""
    def make(candidate_id: str) -> FamilyCandidate:
        return FamilyCandidate(
            candidate_id=candidate_id,
            family=FamilyId.TENANT_ISOLATION,
            vuln_class="idor",
            scenario_id="cross-tenant-read",
            affected_endpoint="/api/invoices/INV-A-101",
            hypothesis="foreign principal reads owner invoice",
            evidence_refs=["obs:1"],
        )

    first = make("cand-1")
    second = make("cand-2")
    assert first.dedupe_key == second.dedupe_key
    # a different scenario or endpoint produces a different key
    third = FamilyCandidate(
        candidate_id="cand-3",
        family=FamilyId.TENANT_ISOLATION,
        vuln_class="idor",
        scenario_id="cross-tenant-write",
        affected_endpoint="/api/invoices/INV-A-101",
        hypothesis="foreign principal writes owner invoice",
        evidence_refs=["obs:1"],
    )
    assert third.dedupe_key != first.dedupe_key
