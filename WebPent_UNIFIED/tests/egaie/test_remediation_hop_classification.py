"""L10 Phase 3: the failed-hop outcome vocabulary is pinned at the
orchestrator's remediation loop.

The corpus itself never produces a refused setup hop (its surfaces
accept the owner's own published transitions), so this module pins
the classification with a minimal port whose hop records are
controlled:

- a REFUSED hop (non-2xx, or not executed) is "transition
  unavailable": the surface said no. A refusal is never an
  executed-without-effect report;
- an ACCEPTED hop whose re-read did not confirm its result state is
  "executed but state not reached" (TRANSITION_WITHOUT_EFFECT).

Both are BLOCK reasons: the hypothesis is parked, never scored as a
negative security result, and no re-run is spent on a failed
sequence. The contrast case shows a confirmed hop re-runs the
experiment and verifies its precondition in the ledger. Everything
downstream (planner derivation, assertion ledger, re-evaluation
ordering) is the production code: only the port's records are
synthetic.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from webpent.egaie import orchestrator as orch_module
from webpent.egaie.differential import ProbePlan, ProbeStep
from webpent.egaie.orchestrator import InvestigationOrchestrator
from webpent.egaie.planner import (
    BlockReason,
    PlannerConfig,
    StatefulPlanner,
)
from webpent.egaie.prerequisites import (
    PreconditionKind,
    PreconditionStatus,
    UnattainableEffect,
)
from webpent.egaie.schemas import ProposedExperiment

PATH = "/wf/items/1"
CHAIN = ("draft", "review", "final")
TARGETS = {"advance": "review", "finalize": "final"}
EXPERIMENT_ID = "hop-classification"


class FakePort:
    """Minimal experiment port: the only behavior under test is
    what ``_remediate`` reads off the hop records."""

    def __init__(self, setup_status: int,
                 observed_state: str) -> None:
        self.bindings = SimpleNamespace(
            idem_param="Idempotency-Key", state_field="state",
            action_param="action")
        self.ledger = object()
        self.setup_status = setup_status
        self.observed_state = observed_state
        self.remediated: list[str] = []
        self.executed: list[str] = []

    def plan_for(self, signature: str) -> ProbePlan:
        return ProbePlan(
            hypothesis_id="h-hop",
            steps=(ProbeStep(
                purpose="candidate", label="c", method="POST",
                path=PATH, actor="agent-a",
                params=(("action", "finalize"),),
            ),),
        )

    def run_setup_steps(self, steps: Any,
                        experiment_id: str) -> dict[str, Any]:
        records: dict[str, Any] = {}
        for step in steps:
            if step.label.endswith("-setup"):
                records[step.label] = SimpleNamespace(
                    execution="executed",
                    status_code=self.setup_status,
                    structured={}, record_id="rec-setup")
            else:
                records[step.label] = SimpleNamespace(
                    execution="executed", status_code=200,
                    structured={"state": self.observed_state},
                    record_id="rec-verify")
        return records

    def mark_remediated(self, experiment_id: str) -> None:
        self.remediated.append(experiment_id)

    def execute(self, experiment: Any) -> Any:
        self.executed.append(experiment.experiment_id)
        return ("base", "cand", "ctrl")


def _view() -> SimpleNamespace:
    return SimpleNamespace(
        workflow_paths={PATH},
        workflow_chains={PATH: CHAIN},
        workflow_owner={PATH: "agent-a"},
        workflow_state={PATH: "draft"},
        workflow_action_targets={PATH: TARGETS},
        workflow_requirements={},
        action_param="action",
    )


def _experiment() -> ProposedExperiment:
    return ProposedExperiment(
        experiment_id=EXPERIMENT_ID,
        family="WORKFLOW_IDENTITY",
        signature="h-hop/finalize",
        description="deep source-state probe",
        cost=2.0, risk=0.0, gain_estimate=1.0,
        rationale="hop classification pin",
        hypothesis_id="h-hop",
    )


def _run(monkeypatch: pytest.MonkeyPatch,
         port: FakePort) -> tuple[Any, InvestigationOrchestrator]:
    """Run the production remediation cycle against the fake port,
    with only the view's source (RelationshipTracker) stubbed.
    Returns (result, orchestrator)."""
    monkeypatch.setattr(
        orch_module, "RelationshipTracker",
        lambda ledger, bindings: SimpleNamespace(
            view=lambda: _view()))
    orch = InvestigationOrchestrator(
        experiment_port=port, validation_port=None,
        proof_port=None, model_port=None)
    orch.planner = StatefulPlanner(PlannerConfig())
    return orch._remediate(_experiment()), orch


def test_refused_hop_is_unavailable_not_without_effect(
        monkeypatch: pytest.MonkeyPatch) -> None:
    port = FakePort(setup_status=409, observed_state="draft")
    result, orch = _run(monkeypatch, port)
    assert result is None, "a failed hop must not spend a re-run"
    assert port.remediated == [], (
        "a refused hop must never reach the re-execution path")
    tally = orch.planner.tally()["setup_failures_by_reason"]
    assert tally[BlockReason.UNAVAILABLE.value] == 1
    assert tally[BlockReason.TRANSITION_WITHOUT_EFFECT.value] == 0, (
        "a refusal (the surface said no) is never reported as an "
        "executed-but-ineffective transition")
    preconds = orch.planner.ledger.get("h-hop")
    assert preconds and preconds[0].kind is (
        PreconditionKind.WORKFLOW_TRANSITION)
    precond = preconds[0]
    assert precond.status is PreconditionStatus.UNATTAINABLE
    assert (precond.verdict_effect
            is UnattainableEffect.NEVER_A_VERDICT), (
        "a failed setup blocks the hypothesis and is never a "
        "negative security verdict")


def test_accepted_stuck_hop_is_without_effect(
        monkeypatch: pytest.MonkeyPatch) -> None:
    # 200 + executed, but the re-read shows the state did not move:
    # executed, not refused.
    port = FakePort(setup_status=200, observed_state="draft")
    result, orch = _run(monkeypatch, port)
    assert result is None
    assert port.remediated == []
    tally = orch.planner.tally()["setup_failures_by_reason"]
    assert tally[BlockReason.TRANSITION_WITHOUT_EFFECT.value] == 1
    assert tally[BlockReason.UNAVAILABLE.value] == 0, (
        "an accepted hop whose re-read did not confirm its result "
        "state is executed-but-state-not-reached, not unavailable")


def test_confirmed_hop_establishes_and_reruns(
        monkeypatch: pytest.MonkeyPatch) -> None:
    port = FakePort(setup_status=200, observed_state="review")
    result, orch = _run(monkeypatch, port)
    assert result == ("base", "cand", "ctrl"), (
        "a fully confirmed hop sequence re-runs the experiment")
    assert port.remediated == [EXPERIMENT_ID]
    assert port.executed == [EXPERIMENT_ID]
    tally = orch.planner.tally()["setup_failures_by_reason"]
    assert tally[BlockReason.UNAVAILABLE.value] == 0
    assert tally[BlockReason.TRANSITION_WITHOUT_EFFECT.value] == 0
    precond = orch.planner.ledger.get("h-hop")[0]
    assert precond.status is PreconditionStatus.OBSERVED
    assert precond.basis == "rec-verify", (
        "an OBSERVED precondition carries the re-read observation "
        "that backs it")
