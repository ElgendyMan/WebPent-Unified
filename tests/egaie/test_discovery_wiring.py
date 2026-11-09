"""L10 Phase 4 — the discovery component is wired into remediation.

The published schema (chain + action table) stays the planner's
primary source: discovery is consulted ONLY where the table is
silent, so a complete schema yields byte-identical behavior. Where
the table is silent, remediation spends the discovery budget on
candidates the LEDGER ITSELF observed running — never invented
actions, never the blocked experiment's own action (the experiment's
re-run is that action's only legitimate retry) — and every probe is
a production request (authority, scope, idempotency, re-read). A
probe that was ACCEPTED (state movement or a gate-advancing stall)
justifies one re-run so the differential judgment — never the probe
— decides; a refused probe records the gate and parks the
hypothesis, never a negative verdict.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from webpent.egaie import orchestrator as orch_module
from webpent.egaie.differential import (
    ObservationLedger,
    ProbePlan,
    ProbeStep,
)
from webpent.egaie.orchestrator import InvestigationOrchestrator
from webpent.egaie.planner import (
    BlockReason,
    PlannerConfig,
    StatefulPlanner,
)
from webpent.egaie.prerequisites import PreconditionKind, PreconditionStatus
from webpent.egaie.schemas import ProposedExperiment
from webpent.egaie.workflow_discovery import WorkflowDiscovery

PATH = "/wf/items/1"
OWNER = "owner-a"
EXPERIMENT_ID = "wf-discovery"
COMPOSITES = ("base", "cand", "ctrl")


class SilentSurfacePort:
    """A surface whose workflow schema publishes NOTHING: no chain,
    no action table — the view can only say who owns the path and
    what state a re-read last showed. The state machine is real, and
    EVERY request (probe hops included) is recorded in the real
    ledger, so discovery mines what actually happened. The port is
    the only synthetic piece; orchestrator, planner, discovery,
    ledger and derivation are production code."""

    def __init__(self, initial: str,
                 machine: dict[tuple[str, str], str],
                 refusals: set[tuple[str, str]] = ()) -> None:
        self.bindings = SimpleNamespace(
            idem_param="Idempotency-Key", state_field="state",
            action_param="action")
        self.ledger = ObservationLedger()
        self.state = initial
        self.machine = dict(machine)
        self.refusals = set(refusals)
        self.remediated: list[str] = []
        self.executed: list[str] = []
        self._ord = 0

    def seed(self, actor: str, method: str, action: str | None = None,
             path: str = PATH) -> None:
        """A reconnaissance-era record: the surface's own activity."""
        self._ord += 1
        record_id = f"rec-{self._ord:03d}"
        if method == "GET":
            self.ledger.append(actor, "GET", path, {}, {
                "status_code": 200, "execution": "executed",
                "headers": {},
                "structured": {"state": self.state}})
            return
        assert action is not None
        key = (self.state, action)
        if key in self.refusals or key not in self.machine:
            self.ledger.append(actor, "POST", path,
                               {self.bindings.action_param: action}, {
                                   "status_code": 409,
                                   "execution": "executed",
                                   "headers": {}, "structured": {}})
            return
        self.state = self.machine[key]
        self.ledger.append(actor, "POST", path,
                           {self.bindings.action_param: action}, {
                               "status_code": 200, "execution": "executed",
                               "headers": {}, "structured": {}})

    def plan_for(self, signature: str) -> ProbePlan:
        return ProbePlan(
            hypothesis_id="h-wf",
            steps=(ProbeStep(
                purpose="candidate", label="c", method="POST",
                path=PATH, actor=OWNER,
                params=(("action", "approve"),),
            ),),
        )

    def _post(self, step: ProbeStep) -> tuple[int, dict]:
        action = next(
            value for key, value in step.params
            if key == self.bindings.action_param)
        key = (self.state, action)
        if key in self.refusals or key not in self.machine:
            return 409, {}
        self.state = self.machine[key]
        return 200, {}

    def run_setup_steps(self, steps: Any,
                        experiment_id: str) -> dict[str, Any]:
        records: dict[str, Any] = {}
        for step in steps:
            self._ord += 1
            record_id = f"rec-{self._ord:03d}"
            if step.method == "POST":
                status, structured = self._post(step)
                self.ledger.append(
                    step.actor, "POST", step.path, dict(step.params), {
                        "status_code": status, "execution": "executed",
                        "headers": {}, "structured": structured})
            else:
                status, structured = 200, {"state": self.state}
                self.ledger.append(step.actor, "GET", step.path, {}, {
                    "status_code": status, "execution": "executed",
                    "headers": {}, "structured": structured})
            records[step.label] = SimpleNamespace(
                execution="executed", status_code=status,
                structured=structured, record_id=record_id)
        return records

    def mark_remediated(self, experiment_id: str) -> None:
        self.remediated.append(experiment_id)

    def execute(self, experiment: Any) -> Any:
        for step in self.plan_for(experiment.signature).steps:
            self.run_setup_steps([step], experiment.experiment_id)
        self.executed.append(experiment.experiment_id)
        return COMPOSITES


def _view(state: str) -> SimpleNamespace:
    """The schema-silent view: the published workflow description is
    empty — discovery can only work from observations."""
    return SimpleNamespace(
        workflow_paths={PATH},
        workflow_chains={},
        workflow_owner={PATH: OWNER},
        workflow_state={PATH: state},
        workflow_action_targets={},
        workflow_requirements={},
        action_param="action",
        identity_of={},
        accounts=(),
    )


def _experiment() -> ProposedExperiment:
    return ProposedExperiment(
        experiment_id=EXPERIMENT_ID,
        family="WORKFLOW_IDENTITY",
        signature="h-wf/approve",
        description="schema-silent source-state probe",
        cost=2.0, risk=0.0, gain_estimate=1.0,
        rationale="discovery wiring pin",
        hypothesis_id="h-wf",
    )


def _run(monkeypatch: pytest.MonkeyPatch,
         port: SilentSurfacePort,
         view_state: str,
         discovery: WorkflowDiscovery | None) -> tuple[Any,
                                                       InvestigationOrchestrator]:
    monkeypatch.setattr(
        orch_module, "RelationshipTracker",
        lambda ledger, bindings: SimpleNamespace(
            view=lambda: _view(view_state)))
    orch = InvestigationOrchestrator(
        experiment_port=port, validation_port=None,
        proof_port=None, model_port=None)
    orch.planner = StatefulPlanner(PlannerConfig(), discovery=discovery)
    return orch._remediate(_experiment()), orch


def _seeded_port(**kwargs: Any) -> SilentSurfacePort:
    port = SilentSurfacePort(**kwargs)
    port.seed(OWNER, "GET")
    return port


# -- the payoff: probes learn the machine, the judgment decides -------

def test_accepted_probe_learns_the_machine_and_the_rerun_is_judged(
        monkeypatch: pytest.MonkeyPatch) -> None:
    port = _seeded_port(
        initial="s1",
        machine={
            ("s1", "prep"): "s2", ("s2", "prep"): "s3",
            ("s3", "approve"): "s4"},
    )
    port.seed(OWNER, "POST", action="prep")
    port.seed(OWNER, "GET")
    discovery = WorkflowDiscovery(max_discovery_actions=4)
    result, orch = _run(monkeypatch, port, "s2", discovery)
    assert result == COMPOSITES, (
        "an accepted discovery probe is new information about the "
        "surface: the blocked experiment is re-run ONCE so the "
        "differential judgment — never the probe — decides")
    assert port.remediated == [EXPERIMENT_ID]
    assert discovery.actions_spent == 1
    assert discovery.transitions(PATH) == {
        ("s1", "prep"): "s2", ("s2", "prep"): "s3"}, (
        "the probe learned the unseen transition from its own "
        "re-read, an observation like any other")
    tally = orch.planner.tally()["setup_failures_by_reason"]
    assert not any(tally.values()), (
        "a discovery probe is never a setup failure of the "
        "hypothesis: no block reason, no negative verdict")
    precond = orch.planner.ledger.get("h-wf")[0]
    assert precond.status is PreconditionStatus.INFERRED, (
        "an unverified discovery path leaves the precondition "
        "INFERRED — never UNATTAINABLE, never a verdict")


def test_refused_probes_park_without_a_rerun(
        monkeypatch: pytest.MonkeyPatch) -> None:
    port = _seeded_port(
        initial="s1", machine={("s1", "prep"): "s2"})
    port.seed(OWNER, "POST", action="prep")
    port.seed(OWNER, "GET")
    discovery = WorkflowDiscovery(max_discovery_actions=4)
    result, orch = _run(monkeypatch, port, "s2", discovery)
    assert result is None, (
        "no probe was accepted: nothing about the surface changed, "
        "so a re-run would spend budget on the same refusal")
    assert port.remediated == []
    assert discovery.actions_spent == 1
    assert ("s2", "prep") in discovery.refusals(PATH), (
        "the probe's refusal is recorded as an observation of the "
        "gate")
    assert not any(
        orch.planner.tally()["setup_failures_by_reason"].values()), (
        "the probe's refusal is not a setup failure of the "
        "hypothesis and never a negative verdict")
    precond = orch.planner.ledger.get("h-wf")[0]
    assert precond.status is PreconditionStatus.INFERRED


def test_the_experiments_own_action_is_never_probed(
        monkeypatch: pytest.MonkeyPatch) -> None:
    port = _seeded_port(
        initial="s1",
        machine={
            ("s1", "prep"): "s2", ("s2", "prep"): "s3",
            ("s3", "approve"): "s4"},
        refusals={("s1", "approve")},
    )
    port.seed(OWNER, "POST", action="approve")   # refused at s1
    port.seed(OWNER, "GET")
    port.seed(OWNER, "POST", action="prep")      # s1 -> s2
    port.seed(OWNER, "GET")
    discovery = WorkflowDiscovery(max_discovery_actions=4)
    result, _ = _run(monkeypatch, port, "s2", discovery)
    assert result == COMPOSITES
    assert discovery.attempted == {(PATH, "s2", "prep")}, (
        "the blocked experiment's own action is never probed: its "
        "only legitimate retry is the experiment's own re-run")
    assert discovery.actions_spent == 1


# -- explicit budget, dedup, suppression across cycles ----------------

def test_the_budget_bounds_probes_across_cycles(
        monkeypatch: pytest.MonkeyPatch) -> None:
    port = _seeded_port(
        initial="s1", machine={("s1", "prep"): "s2"})
    port.seed(OWNER, "POST", action="prep")
    port.seed(OWNER, "GET")
    discovery = WorkflowDiscovery(max_discovery_actions=1)
    result, orch = _run(monkeypatch, port, "s2", discovery)
    assert result is None
    assert discovery.actions_spent == 1
    # a later blocked experiment on the same planner: the budget is
    # spent, so remediation probes nothing further
    later = ProposedExperiment(
        experiment_id="wf-discovery-2", family="WORKFLOW_IDENTITY",
        signature="h-wf-2/approve", description="later probe",
        cost=2.0, risk=0.0, gain_estimate=1.0,
        rationale="budget pin", hypothesis_id="h-wf-2")
    monkeypatch.setattr(
        orch_module, "RelationshipTracker",
        lambda ledger, bindings: SimpleNamespace(
            view=lambda: _view("s2")))
    result = orch._remediate(later)
    assert result is None
    assert discovery.actions_spent == 1, "the explicit budget holds"


def test_a_learned_refusal_suppresses_repeat_probes(
        monkeypatch: pytest.MonkeyPatch) -> None:
    port = _seeded_port(
        initial="s1", machine={("s1", "prep"): "s2"})
    port.seed(OWNER, "POST", action="prep")
    port.seed(OWNER, "GET")
    discovery = WorkflowDiscovery(max_discovery_actions=4)
    result, orch = _run(monkeypatch, port, "s2", discovery)
    assert result is None
    assert discovery.actions_spent == 1
    later = ProposedExperiment(
        experiment_id="wf-discovery-2", family="WORKFLOW_IDENTITY",
        signature="h-wf-2/approve", description="later probe",
        cost=2.0, risk=0.0, gain_estimate=1.0,
        rationale="dedup pin", hypothesis_id="h-wf-2")
    monkeypatch.setattr(
        orch_module, "RelationshipTracker",
        lambda ledger, bindings: SimpleNamespace(
            view=lambda: _view("s2")))
    orch._remediate(later)
    assert discovery.actions_spent == 1, (
        "the same (path, from-state, action) is probed at most "
        "once, across cycles: the learned refusal carries no "
        "information gain, so it is not a candidate again")


# -- state beliefs follow the probes' own re-reads --------------------

def test_probe_state_changes_update_the_state_belief(
        monkeypatch: pytest.MonkeyPatch) -> None:
    port = _seeded_port(
        initial="s1",
        machine={
            ("s1", "prep"): "s2", ("s2", "prep"): "s3",
            ("s3", "approve"): "s4"},
    )
    port.seed(OWNER, "POST", action="prep")
    port.seed(OWNER, "GET")
    discovery = WorkflowDiscovery(max_discovery_actions=4)
    result, orch = _run(monkeypatch, port, "s2", discovery)
    assert result == COMPOSITES
    view = _view("s2")
    assert orch.planner.current_state(PATH, view) == "s4", (
        "the state belief follows the probes' own re-reads, never "
        "the stale view")


# -- priority: the published schema always wins -----------------------

def test_published_schema_takes_priority_and_discovery_stays_idle(
        monkeypatch: pytest.MonkeyPatch) -> None:
    port = _seeded_port(
        initial="s1",
        machine={("s1", "prep"): "s2", ("s2", "approve"): "s3"})
    # discovery arrives primed with edges mined elsewhere; with a
    # published chain and action table it must stay idle regardless
    discovery = _discovery_from_ledger()
    published = SimpleNamespace(
        workflow_paths={PATH},
        workflow_chains={PATH: ("s1", "s2", "s3")},
        workflow_owner={PATH: OWNER},
        workflow_state={PATH: "s1"},
        workflow_action_targets={PATH: {"prep": "s2",
                                        "approve": "s3"}},
        workflow_requirements={},
        action_param="action",
        identity_of={},
        accounts=(),
    )
    monkeypatch.setattr(
        orch_module, "RelationshipTracker",
        lambda ledger, bindings: SimpleNamespace(
            view=lambda: published))
    orch = InvestigationOrchestrator(
        experiment_port=port, validation_port=None,
        proof_port=None, model_port=None)
    orch.planner = StatefulPlanner(PlannerConfig(), discovery=discovery)
    result = orch._remediate(_experiment())
    assert result == COMPOSITES, (
        "the published table derives the whole setup: prep hops the "
        "surface to s2, the source state the table implies for "
        "approve")
    assert discovery.actions_spent == 0, (
        "the published schema answers everything: the attached "
        "discovery component stays idle — no mining, no probes, "
        "byte-identical L9 behavior")
    assert discovery.contradictions == []
    precond = orch.planner.ledger.get("h-wf")[0]
    assert precond.status is PreconditionStatus.OBSERVED, (
        "the published path verifies through its own re-reads, "
        "exactly as in L9")


# -- planner-level derivation from discovery edges --------------------

def _discovery_from_ledger() -> WorkflowDiscovery:
    discovery = WorkflowDiscovery()
    ledger = ObservationLedger()
    for actor, method, params, structured in (
            (OWNER, "GET", {}, {"state": "s1"}),
            (OWNER, "POST", {"action": "prep"}, {}),
            (OWNER, "GET", {}, {"state": "s2"}),
            (OWNER, "GET", {}, {"state": "s2"}),
            (OWNER, "POST", {"action": "approve"}, {}),
            (OWNER, "GET", {}, {"state": "s3"})):
        ledger.append(actor, method, PATH, params, {
            "status_code": 200, "execution": "executed",
            "headers": {}, "structured": structured})
    discovery.mine(ledger, _view("s2"), SimpleNamespace(
        state_field="state", action_param="action"))
    return discovery


def _silent_view(state: str) -> SimpleNamespace:
    return _view(state)


def test_discovery_edges_derive_need_and_hops() -> None:
    planner = StatefulPlanner(
        PlannerConfig(), discovery=_discovery_from_ledger())
    planner.seed_state(PATH, "s1")
    view = _silent_view("s1")
    hypothesis = SimpleNamespace(
        hypothesis_id="h-wf",
        plan=SimpleNamespace(steps=(
            ProbeStep(purpose="candidate", label="c", method="POST",
                      path=PATH, actor=OWNER,
                      params=(("action", "approve"),)),)))
    precond = planner.ensure_declared(hypothesis, view)[0]
    assert precond.kind is PreconditionKind.WORKFLOW_TRANSITION
    need = planner.transition_need(precond, hypothesis, view)
    assert need == ("s2", "s1", ("s1", "s2", "s3")), (
        "where the table is silent, the need is derived from the "
        "edges the ledger itself observed: the source state the "
        "action was OBSERVED to run from, reachable forward from "
        "the current state")
    plan = planner.setup_plan(precond, hypothesis, view)
    assert plan is not None and len(plan.hops) == 1
    hop = plan.hops[0]
    assert (hop.params == (("action", "prep"),)
            and hop.result_state == "s2"
            and hop.actor == OWNER), (
        "the hop uses the surface's own OBSERVED transition, as "
        "the recorded owner, verified by its own re-read")


def test_quarantined_edges_never_derive_a_plan() -> None:
    discovery = _discovery_from_ledger()
    # the approve transition contradicts itself: quarantined
    ledger = ObservationLedger()
    for actor, method, params, structured in (
            (OWNER, "GET", {}, {"state": "s2"}),
            (OWNER, "POST", {"action": "approve"}, {}),
            (OWNER, "GET", {}, {"state": "sx"})):
        ledger.append(actor, method, PATH, params, {
            "status_code": 200, "execution": "executed",
            "headers": {}, "structured": structured})
    discovery.mine(ledger, _view("s2"), SimpleNamespace(
        state_field="state", action_param="action"))
    planner = StatefulPlanner(PlannerConfig(), discovery=discovery)
    planner.seed_state(PATH, "s1")
    view = _silent_view("s1")
    hypothesis = SimpleNamespace(
        hypothesis_id="h-wf",
        plan=SimpleNamespace(steps=(
            ProbeStep(purpose="candidate", label="c", method="POST",
                      path=PATH, actor=OWNER,
                      params=(("action", "approve"),)),)))
    (precond,) = planner.ensure_declared(hypothesis, view)
    assert discovery.contradictions, "the contradiction is recorded"
    assert planner.transition_need(precond, hypothesis, view) is None, (
        "a quarantined transition is never planned through")
    assert planner.setup_plan(precond, hypothesis, view) is None


def test_tally_reports_discovery_only_when_attached(
        monkeypatch: pytest.MonkeyPatch) -> None:
    port = _seeded_port(
        initial="s1",
        machine={
            ("s1", "prep"): "s2", ("s2", "prep"): "s3",
            ("s3", "approve"): "s4"},
    )
    port.seed(OWNER, "POST", action="prep")
    port.seed(OWNER, "GET")
    discovery = WorkflowDiscovery(max_discovery_actions=4)
    result, orch = _run(monkeypatch, port, "s2", discovery)
    assert result == COMPOSITES
    report = orch.planner.tally()["workflow_discovery"]
    assert report["probes_attempted"] == 1
    assert report["probe_budget"] == 4
    assert report["contradictions"] == 0
    # and when no discovery is attached, the key is absent: the
    # L9 accounting stays byte-identical
    published_port = _seeded_port(
        initial="s1", machine={("s1", "prep"): "s2"})
    _, bare = _run(monkeypatch, published_port, "s2", None)
    assert "workflow_discovery" not in bare.planner.tally()
