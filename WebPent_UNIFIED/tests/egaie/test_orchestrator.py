"""EGAIE orchestrator: end-to-end on the controlled fixture, promotion
discipline, termination, repetition switch, resume, advisory proposer."""
from __future__ import annotations

import pathlib

from webpent.egaie.benchmark.fixture import (
    ControlledFixtureTarget,
    FixtureCase,
    FixtureExperimentPort,
)
from webpent.egaie.causal_adapter import (
    CausalValidationPort,
    ProofBundlePort,
)
from webpent.egaie.orchestrator import InvestigationOrchestrator
from webpent.egaie.persistence import load_state, save_state
from webpent.egaie.schemas import (
    DecisionAction,
    HypothesisRecord,
    HypothesisStatus,
    InvestigationState,
    ProposedExperiment,
)
from webpent.egaie.selection import InformationGainSelector


class RecordingModelPort:
    """Advisory ledger: records world-model / attack-graph deltas."""

    def __init__(self) -> None:
        self.updates: list[dict] = []

    def update(self, state, experiment, observations, causal):
        entry = {
            "round": state.round,
            "experiment_id": experiment.experiment_id,
            "family": experiment.family,
            "verdict": causal["verdict"],
        }
        self.updates.append(entry)
        return {"world_model": [entry], "attack_graph": [entry]}


def _fixture() -> ControlledFixtureTarget:
    return ControlledFixtureTarget([
        FixtureCase(case_id="pos-idor-1", family="IDOR", positive=True),
        FixtureCase(case_id="neg-idor-1", family="IDOR", positive=False),
    ])


def _ports(target: ControlledFixtureTarget):
    port = FixtureExperimentPort(target)
    validation = CausalValidationPort()
    proof = ProofBundlePort()
    model = RecordingModelPort()
    return port, validation, proof, model


def _state_with_case(case_id: str, family: str) -> InvestigationState:
    state = InvestigationState(
        engagement_id="eng-egaie", target_url="fixture://demo")
    state.add_hypothesis(HypothesisRecord(
        hypothesis_id=f"h-{case_id}", family=family,
        statement=f"case {case_id}", source="advisory", origin=case_id))
    state.add_experiment(ProposedExperiment(
        experiment_id=f"e-{case_id}", family=family,
        signature=f"{case_id}/{family}",
        description="probe", cost=0.2, risk=0.3, gain_estimate=0.5,
        rationale="seed"))
    return state


def test_end_to_end_confirms_positive_case():
    port, validation, proof, model = _ports(_fixture())
    state = _state_with_case("pos-idor-1", "IDOR")
    orchestrator = InvestigationOrchestrator(
        experiment_port=port, validation_port=validation,
        proof_port=proof, model_port=model,
        selector=InformationGainSelector())
    result = orchestrator.run(state, max_rounds=3)
    confirmed = [h for h in result.hypotheses
                 if h.status is HypothesisStatus.CONFIRMED]
    assert len(confirmed) == 1
    assert confirmed[0].hypothesis_id == "h-pos-idor-1"
    supporting = [e for e in result.evidence
                  if e.source == "causal_guard"]
    assert supporting, "confirmation must cite causal_guard evidence"
    assert result.terminal_reason != ""
    assert any(d.action is DecisionAction.SELECT
               for d in result.decision_records())
    assert model.updates, "world model must receive updates"
    assert result.world_model_updates and result.attack_graph_updates


def test_clean_verdict_never_confirms():
    port, validation, proof, model = _ports(_fixture())
    state = _state_with_case("neg-idor-1", "IDOR")
    orchestrator = InvestigationOrchestrator(
        experiment_port=port, validation_port=validation,
        proof_port=proof, model_port=model,
        selector=InformationGainSelector())
    result = orchestrator.run(state, max_rounds=3)
    statuses = {h.hypothesis_id: h.status for h in result.hypotheses}
    assert statuses["h-neg-idor-1"] is not HypothesisStatus.CONFIRMED
    assert statuses["h-neg-idor-1"] is HypothesisStatus.CONTRADICTED


def test_replay_failure_blocks_confirmation():
    port, validation, proof, model = _ports(_fixture())
    state = _state_with_case("pos-idor-1", "IDOR")
    # Tamper with the bundle between build and replay: replay must fail.
    class TamperingProofPort(ProofBundlePort):
        def build(self, experiment, baseline, candidate, control,
                  causal_result):
            bundle = super().build(experiment, baseline, candidate,
                                   control, causal_result)
            return bundle  # intact build; tamper happens in verify
        def verify(self, bundle):
            result = super().verify(bundle)
            return dict(result, replay_valid=False)
    orchestrator = InvestigationOrchestrator(
        experiment_port=port, validation_port=validation,
        proof_port=TamperingProofPort(), model_port=model,
        selector=InformationGainSelector())
    result = orchestrator.run(state, max_rounds=3)
    statuses = {h.hypothesis_id: h.status for h in result.hypotheses}
    assert statuses["h-pos-idor-1"] is not HypothesisStatus.CONFIRMED
    outcomes = [result.experiment_outcome("e-pos-idor-1")]
    assert outcomes == ["unverified"]


def test_scope_denied_is_fail_closed():
    port, validation, proof, model = _ports(_fixture())
    port.scope_allowed = False
    state = _state_with_case("pos-idor-1", "IDOR")
    orchestrator = InvestigationOrchestrator(
        experiment_port=port, validation_port=validation,
        proof_port=proof, model_port=model,
        selector=InformationGainSelector())
    result = orchestrator.run(state, max_rounds=2)
    assert result.terminal_reason == "scope_denied"
    statuses = {h.hypothesis_id: h.status for h in result.hypotheses}
    assert statuses["h-pos-idor-1"] is HypothesisStatus.PROPOSED
    assert not result.observations


def test_round_budget_exhausts_with_open_hypotheses():
    port, validation, proof, model = _ports(_fixture())
    state = InvestigationState(
        engagement_id="e", target_url="t")
    state.add_hypothesis(HypothesisRecord(
        hypothesis_id="h-open", family="BOLA", statement="open"))
    orchestrator = InvestigationOrchestrator(
        experiment_port=port, validation_port=validation,
        proof_port=proof, model_port=model,
        selector=InformationGainSelector())
    result = orchestrator.run(state, max_rounds=2)
    assert result.terminal_reason == "round_budget_exhausted"
    assert result.round == 2


def test_repeated_inconclusive_switches_strategy():
    port, validation, proof, model = _ports(_fixture())
    state = _state_with_case("pos-idor-1", "IDOR")
    # InconclusivePort: never yields a decidable verdict.
    class InconclusivePort(FixtureExperimentPort):
        def execute(self, experiment):
            base, cand, control = super().execute(experiment)
            incomplete = dict(cand)
            incomplete.pop("headers", None)
            return base, incomplete, control
    orchestrator = InvestigationOrchestrator(
        experiment_port=InconclusivePort(_fixture()),
        validation_port=validation, proof_port=proof, model_port=model,
        selector=InformationGainSelector())
    state.add_experiment(ProposedExperiment(
        experiment_id="e-pos-idor-1-b", family="IDOR",
        signature="pos-idor-1/IDOR",
        description="retry", cost=0.2, risk=0.3, gain_estimate=0.5,
        rationale="seed"))
    result = orchestrator.run(state, max_rounds=6)
    actions = [d.action for d in result.decision_records()]
    assert DecisionAction.STRATEGY_SWITCH in actions
    assert result.terminal_reason != ""


def test_resume_after_interruption(tmp_path: pathlib.Path):
    port, validation, proof, model = _ports(_fixture())
    state = _state_with_case("pos-idor-1", "IDOR")
    orchestrator = InvestigationOrchestrator(
        experiment_port=port, validation_port=validation,
        proof_port=proof, model_port=model,
        selector=InformationGainSelector())
    first = orchestrator.run(state, max_rounds=1)
    assert first.round == 1
    path = tmp_path / "state.json"
    save_state(first, path)
    restored = load_state(path)
    assert restored.round == 1
    resumed = orchestrator.run(restored, max_rounds=3)
    confirmed = [h for h in resumed.hypotheses
                 if h.status is HypothesisStatus.CONFIRMED]
    assert len(confirmed) == 1
    assert resumed.round > restored.round


def test_advisory_proposer_extends_but_never_confirms():
    port, validation, proof, model = _ports(_fixture())
    state = _state_with_case("neg-idor-1", "IDOR")

    class AdvisoryProposer:
        def propose(self, state):
            if state.round == 0:
                return [ProposedExperiment(
                    experiment_id="e-advisory", family="IDOR",
                    signature="neg-idor-1/IDOR",
                    description="advisory probe", cost=0.2, risk=0.2,
                    gain_estimate=0.5, rationale="advisory proposal only")]
            return []

    orchestrator = InvestigationOrchestrator(
        experiment_port=port, validation_port=validation,
        proof_port=proof, model_port=model,
        selector=InformationGainSelector(),
        proposer=AdvisoryProposer())
    result = orchestrator.run(state, max_rounds=4)
    statuses = {h.hypothesis_id: h.status for h in result.hypotheses}
    assert statuses["h-neg-idor-1"] is not HypothesisStatus.CONFIRMED
    assert any(e.experiment_id == "e-advisory"
               for e in result.experiments)


def test_package_has_no_dynamic_resolution():
    package_dir = pathlib.Path(
        __import__("webpent.egaie", fromlist=["egaie"]).__file__).parent
    for path in package_dir.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "getattr(" not in source, f"getattr in {path.name}"
        assert "hasattr(" not in source, f"hasattr in {path.name}"
        assert "except Exception" not in source, path.name
