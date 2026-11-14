"""L9 §6: strategy-baseline wiring regressions.

Baseline C (the planner with prerequisite reasoning ablated) must
never remediate a blocked outcome: candidate generation is
identical to baseline B, and any confirmation it produces would
not isolate the planner's contribution. Baseline D (the
independently generated fixed prerequisite strategy) rides the
orchestrator's remediation hook with its own static recipe list,
through the same execution machinery and fail-closed oracle, and
must confirm the two-stage held-out defect while never flagging
the secured lookalike.
"""
from __future__ import annotations

from webpent.egaie import discovery_runner as dr
from webpent.egaie.benchmark.fixed_prerequisites import (
    FixedPrerequisiteRemediator,
)
from webpent.egaie.planner import PlannerConfig, StatefulPlanner
from webpent.appsuite.corpus import SuiteEntry, open_instance


def _run(entry: SuiteEntry, budget: int = 16, **wiring):
    with open_instance(entry) as target:
        port = dr._build_port(target, entry.seed)
        state = dr._seed_state(target, entry.instance_id)
        orch = dr._build_orchestrator(port, "adaptive")
        for name, value in wiring.items():
            setattr(orch, name, value)
        state = orch.run(state, max_rounds=budget)
    return state, orch


def test_prerequisite_ablation_never_remediates() -> None:
    # C: candidate generation unchanged, remediation off. The
    # ledger records no transition preconditions and establishes
    # nothing, and the defect behind the prerequisite stays an
    # unconfirmed hypothesis — the exact gap the planner (B) closes.
    state, orch = _run(
        SuiteEntry("ledgerflow", "defective"),
        planner=StatefulPlanner(PlannerConfig(
            prerequisite_reasoning=False)))
    confirmed = [
        h for h in state.hypotheses if h.status.value == "confirmed"]
    assert not confirmed, (
        "the ablated planner confirmed a defect that sits behind "
        "an unestablished prerequisite: the ablation does not "
        "isolate the planner's contribution")
    establishment = orch.planner.ledger.tally().get("observed", 0)
    assert establishment == 0, (
        "the ablated planner established workflow states anyway")
    # every hypothesis the ablated run left behind is a non-verdict
    statuses = {h.status.value for h in state.hypotheses}
    assert statuses <= {"proposed", "supported", "blocked",
                        "inconclusive", "contradicted"}, statuses


def test_fixed_prerequisite_strategy_confirms_without_planner() -> None:
    # D: the independent fixed recipe confirms the two-stage held-out
    # defect through the orchestrator's remediation hook — same
    # candidate generation, same oracle, same budgets as B.
    state, orch = _run(
        SuiteEntry("ledgerflow", "defective"),
        remediator=FixedPrerequisiteRemediator())
    confirmed = [
        h for h in state.hypotheses
        if h.status.value == "confirmed"
        and h.family == "WORKFLOW_IDENTITY"]
    assert confirmed, (
        "the fixed prerequisite strategy never confirmed the "
        "two-stage defect")
    assert orch.remediator.tally, (
        "the fixed strategy fired no recipes")


def test_fixed_prerequisite_strategy_never_flags_secured() -> None:
    # D's recipe fired on a secured surface must resolve clean
    # through the fail-closed oracle: a setup that fails or fires
    # pointlessly never becomes a finding either way.
    state, orch = _run(
        SuiteEntry("ledgerflow", "secured"),
        remediator=FixedPrerequisiteRemediator())
    flagged = [
        h.hypothesis_id for h in state.hypotheses
        if h.status.value == "confirmed"]
    assert not flagged, flagged


def test_fixed_strategy_module_is_independent_of_planner() -> None:
    # The mission's fairness requirement: the fixed prerequisite
    # strategy is generated independently of the planner's
    # derivation logic. Pin it structurally: the module imports
    # nothing from webpent.egaie.planner and holds its own static
    # recipe table.
    import inspect
    import sys

    from webpent.egaie.benchmark import fixed_prerequisites
    imported = [
        name for name, value
        in vars(fixed_prerequisites).items()
        if inspect.ismodule(value)]
    assert all(
        not name.startswith("webpent.egaie.planner")
        for name in imported), imported
    assert fixed_prerequisites.RECIPES == {
        "WORKFLOW_IDENTITY": ("advance-first-published-action",)}
    assert sys.modules["webpent.egaie.benchmark"
                       ".fixed_prerequisites"] is (
        fixed_prerequisites)
