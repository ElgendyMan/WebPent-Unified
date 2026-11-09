"""L9 §3 Phase 2 — red-first tests for the bounded stateful planner.

Rules under test: read-only preference, authorized setup through the
surface's own vocabulary, re-evaluation after each result, and the
two invariants — an inferred precondition is never a verified fact,
and a failed/unreachable precondition blocks execution and NEVER
becomes a negative security verdict.
"""

from dataclasses import dataclass, field

from webpent.egaie.differential import ProbeStep, RelationshipView
from webpent.egaie.planner import (
    BlockReason,
    PlannerConfig,
    PlannerDecision,
    StatefulPlanner,
)
from webpent.egaie.prerequisites import (
    Precondition,
    PreconditionKind,
    PreconditionStatus,
    PrerequisiteLedger,
)


@dataclass
class _Plan:
    steps: tuple = ()


@dataclass
class _Hyp:
    hypothesis_id: str
    family: str = "WORKFLOW_IDENTITY"
    plan: _Plan = field(default_factory=_Plan)
    prerequisites: tuple = ()


CHAIN = ("open", "queued", "approved", "settled")


def _view() -> RelationshipView:
    return RelationshipView(
        accounts=("owner-1", "ext-1"),
        workflow_paths=("workflows/wf-1",),
        workflow_owner={"workflows/wf-1": "owner-1"},
        workflow_state={"workflows/wf-1": "open"},
        workflow_chains={"workflows/wf-1": CHAIN},
        workflow_action_targets={"workflows/wf-1": {
            "queue": "queued", "approve": "approved",
            "settle": "settled"}},
        identity_of={"cred-1": "ext-1"},
    )


def _transition_hyp(target: str = "transition:workflows/wf-1:source-state",
                    action: str = "approve") -> _Hyp:
    """The discriminating probe POSTs an action whose required
    source state the surface does not hand out for free."""
    return _Hyp(
        hypothesis_id="h-9",
        plan=_Plan(steps=(
            ProbeStep(purpose="baseline", label="b", method="GET",
                      path="workflows/wf-1", actor="ext-1"),
            ProbeStep(purpose="candidate", label="c", method="POST",
                      path="workflows/wf-1", actor="ext-1",
                      params=(("action", action),)),
        )),
        prerequisites=(
            Precondition(kind=PreconditionKind.IDENTITY,
                         target="identity:ext-1",
                         establish_via="credential correlation"),
            Precondition(kind=PreconditionKind.WORKFLOW_TRANSITION,
                         target=target),
        ))


def test_setup_prefers_read_only_first_and_uses_surface_vocabulary(
) -> None:
    view = _view()
    hyp = _transition_hyp()
    planner = StatefulPlanner()
    planner.attach([hyp])
    # identity is read-only verifiable: it comes before any setup
    assert planner.decide(hyp, view) is (
        PlannerDecision.VERIFY_READ_ONLY)
    planner.record_observation(
        "h-9", "identity:ext-1", "obs-1")
    # approve's source state is 'queued'; the surface sits in 'open'
    # (its first observed state): the owner's own 'queue' transition
    # is the minimal authorized setup.
    decision = planner.decide(hyp, view)
    assert decision is PlannerDecision.SETUP
    plan = planner.setup_plan(
        next(p for p in hyp.prerequisites
             if p.kind is PreconditionKind.WORKFLOW_TRANSITION),
        hyp, view)
    assert plan is not None and len(plan.hops) == 1
    action = plan.hops[0]
    # everything derived from the surface's own description:
    assert action.actor == "owner-1"
    assert action.method == "POST"
    assert action.path == "workflows/wf-1"
    assert action.params == (("action", "queue"),)
    assert action.idempotency_key
    assert action.result_state == "queued"
    # setup is an explicit POST + read-only re-read pair: HTTP
    # success alone never proves a transition
    steps = plan.to_steps(idem_param="idem",
                          verify_path="workflows/wf-1")
    assert [s.method for s in steps] == ["POST", "GET"]
    assert ("idem", action.idempotency_key) in steps[0].params


def test_satisfied_state_verifies_read_only_then_runs() -> None:
    view = _view()
    planner = StatefulPlanner()
    # the surface reports the workflow already sits in 'queued'
    planner.seed_state("workflows/wf-1", "queued")
    hyp = _transition_hyp()
    planner.attach([hyp])
    planner.record_observation("h-9", "identity:ext-1", "obs-1")
    assert planner.decide(hyp, view) is (
        PlannerDecision.VERIFY_READ_ONLY)
    # the re-read verifies the transition precondition...
    planner.record_observation(
        "h-9", "transition:workflows/wf-1:source-state", "obs-2")
    # ...and only then is the discriminating experiment runnable
    assert planner.decide(hyp, view) is PlannerDecision.RUN


def test_unrewindable_state_blocks_never_negative() -> None:
    view = _view()
    planner = StatefulPlanner()
    # the workflow is already past the required source state and a
    # forward-only machine cannot go back
    planner.seed_state("workflows/wf-1", "approved")
    hyp = _transition_hyp()
    planner.attach([hyp])
    planner.record_observation("h-9", "identity:ext-1", "obs-1")
    assert planner.decide(hyp, view) is PlannerDecision.BLOCKED
    # the block reason is recorded and the verdict effect is
    # NEVER a negative security verdict
    assert planner.tally()["setup_failures_by_reason"][
        BlockReason.UNAVAILABLE.value] == 1
    blockers = planner.ledger.execution_blockers("h-9")
    assert blockers, "unattainable precondition must block"
    from webpent.egaie.prerequisites import UnattainableEffect
    assert blockers[0].verdict_effect is (
        UnattainableEffect.NEVER_A_VERDICT)
    assert planner.ledger.verdict_gate("h-9") == "blocked"


def test_transition_without_effect_is_a_recorded_block_reason(
) -> None:
    """§4 outcome: the setup POST succeeded but the re-read shows
    the state did not move — blocked, never a verdict."""
    planner = StatefulPlanner()
    planner.attach([_transition_hyp()])
    planner.record_setup_failure(
        "h-9", "transition:workflows/wf-1:source-state",
        BlockReason.TRANSITION_WITHOUT_EFFECT)
    assert planner.ledger.verdict_gate("h-9") == "blocked"
    assert planner.tally()["setup_failures_by_reason"][
        BlockReason.TRANSITION_WITHOUT_EFFECT.value] == 1


def test_ablation_without_prerequisite_reasoning_parks_never_flags(
) -> None:
    view = _view()
    hyp = _transition_hyp()
    planner = StatefulPlanner(
        config=PlannerConfig(prerequisite_reasoning=False))
    planner.attach([hyp])
    planner.record_observation("h-9", "identity:ext-1", "obs-1")
    assert planner.decide(hyp, view) is PlannerDecision.INCONCLUSIVE
    assert planner.tally()["setup_actions_attempted"] == 0
    # parked is NOT blocked and NOT a finding: nothing was proposed
    assert planner.ledger.verdict_gate("h-9") == "unverified"


def test_re_evaluate_after_each_result() -> None:
    view = _view()
    hyp = _transition_hyp()
    planner = StatefulPlanner()
    planner.attach([hyp])
    planner.record_observation("h-9", "identity:ext-1", "obs-1")
    assert planner.decide(hyp, view) is PlannerDecision.SETUP
    plan = planner.setup_plan(
        next(p for p in hyp.prerequisites
             if p.kind is PreconditionKind.WORKFLOW_TRANSITION),
        hyp, view)
    assert plan is not None and len(plan.hops) == 1
    # the re-read after the setup shows the state moved
    assert planner.observe_state("workflows/wf-1", "queued")
    planner.record_observation(
        "h-9", "transition:workflows/wf-1:source-state", "obs-2")
    assert planner.decide(hyp, view) is PlannerDecision.RUN
    tally = planner.tally()
    assert tally["prerequisites_verified"] == 2
    assert tally["setup_actions_attempted"] == 1


def test_setup_budget_exhaustion_parks_not_blocks() -> None:
    view = _view()
    hyp = _transition_hyp()
    planner = StatefulPlanner(
        config=PlannerConfig(max_setup_actions=0))
    planner.attach([hyp])
    planner.record_observation("h-9", "identity:ext-1", "obs-1")
    assert planner.decide(hyp, view) is PlannerDecision.INCONCLUSIVE
    # parked, with the precondition still merely unverified: the
    # budget said no, the surface never said insecure
    assert planner.ledger.verdict_gate("h-9") == "unverified"


def test_stop_conditions_leave_the_schedule() -> None:
    planner = StatefulPlanner()
    hyp = _transition_hyp()
    planner.attach([hyp])
    planner.record_stopped("h-9", "falsified")
    view = _view()
    assert planner.decide(hyp, view) is PlannerDecision.BLOCKED
    assert planner.tally()["hypotheses_stopped"] == 1


def test_setup_cap_derived_counts_in_request_budget_terms() -> None:
    """Setup actions are budgeted like probes: request_cost covers
    the POST and its verification re-read."""
    view = _view()
    hyp = _transition_hyp()
    planner = StatefulPlanner()
    planner.attach([hyp])
    precond = next(p for p in hyp.prerequisites
                   if p.kind is PreconditionKind.WORKFLOW_TRANSITION)
    plan = planner.setup_plan(precond, hyp, view)
    assert plan is not None and len(plan.hops) == 1
    assert plan.hops[0].request_cost == 2
    assert plan.hops[0].result_state == "queued"


def test_ungated_hypotheses_run_unchanged() -> None:
    """A hypothesis with no preconditions is ungated: pre-planner
    behavior preserved (strategy A's contract)."""
    planner = StatefulPlanner()
    hyp = _Hyp(hypothesis_id="h-plain", plan=_Plan())
    planner.attach([hyp])
    assert planner.decide(hyp, _view()) is PlannerDecision.RUN


def test_precondition_with_establishable_status_still_gated() -> None:
    """ESTABLISHABLE is a plan, not a fact: the ledger still reports
    it unverified until a recorded observation backs it."""
    ledger = PrerequisiteLedger()
    ledger.declare("h-1", (
        Precondition(kind=PreconditionKind.APP_STATE,
                     target="ticket:queued",
                     status=PreconditionStatus.ESTABLISHABLE,
                     establish_via="owner submits"),))
    assert ledger.verdict_gate("h-1") == "unverified"
    ledger.verify("h-1", "ticket:queued", "obs-5")
    assert ledger.verdict_gate("h-1") == "clear"


# -- L10 Phase 3: multi-hop minimal-sequence derivation ---------------

CHAIN4 = ("intake", "review", "ready", "approved")


def _deep_view() -> RelationshipView:
    return RelationshipView(
        accounts=("owner-1", "ext-1"),
        workflow_paths=("workflows/wf-4",),
        workflow_owner={"workflows/wf-4": "owner-1"},
        workflow_state={"workflows/wf-4": "intake"},
        workflow_chains={"workflows/wf-4": CHAIN4},
        workflow_action_targets={"workflows/wf-4": {
            "satisfy": "review", "approve": "approved"}},
        identity_of={"cred-1": "ext-1"},
    )


def _deep_hyp() -> _Hyp:
    """The discriminating probe POSTs 'approve', whose required
    source state 'ready' sits TWO chain steps above the observed
    state 'intake', and the surface's table publishes no action
    targeting 'ready' at all."""
    return _Hyp(
        hypothesis_id="h-deep",
        plan=_Plan(steps=(
            ProbeStep(purpose="baseline", label="b", method="GET",
                      path="workflows/wf-4", actor="ext-1"),
            ProbeStep(purpose="candidate", label="c", method="POST",
                      path="workflows/wf-4", actor="ext-1",
                      params=(("action", "approve"),)),
        )),
        prerequisites=(
            Precondition(kind=PreconditionKind.IDENTITY,
                         target="identity:ext-1",
                         establish_via="credential correlation"),
            Precondition(kind=PreconditionKind.WORKFLOW_TRANSITION,
                         target="transition:workflows/wf-4:source-state"),
        ))


def _deep_precond(hyp: _Hyp) -> Precondition:
    return next(p for p in hyp.prerequisites
                if p.kind is PreconditionKind.WORKFLOW_TRANSITION)


def test_multi_hop_setup_derives_minimal_owner_sequence() -> None:
    view = _deep_view()
    hyp = _deep_hyp()
    planner = StatefulPlanner()
    planner.attach([hyp])
    planner.record_observation("h-deep", "identity:ext-1", "obs-1")
    assert planner.decide(hyp, view) is PlannerDecision.SETUP
    plan = planner.setup_plan(_deep_precond(hyp), hyp, view)
    assert plan is not None
    assert len(plan.hops) == 2
    first, second = plan.hops
    # both hops are the surface's own advancing transition, applied
    # by the workflow's recorded owner
    assert first.actor == second.actor == "owner-1"
    assert first.params == (("action", "satisfy"),)
    assert first.result_state == "review"
    # the second hop REAPPLIES the advancing transition: the table
    # publishes no action targeting 'ready'; the forward-only linear
    # chain is the surface's own description, and only the per-hop
    # re-read can verify the reapplication (an inferred plan, never
    # a fact)
    assert second.params == (("action", "satisfy"),)
    assert second.result_state == "ready"
    assert second.idempotency_key != first.idempotency_key
    # each hop is a POST + read-only re-read pair
    steps = plan.to_steps(idem_param="idem",
                          verify_path="workflows/wf-4")
    assert [s.method for s in steps] == ["POST", "GET", "POST", "GET"]
    # the hops count against the setup budget in request terms
    assert planner.tally()["setup_actions_attempted"] == 2


def test_multi_hop_re_evaluate_needs_one_fewer_hop() -> None:
    """After hop 1's re-read is recorded, the derivation needs ONE
    hop, not two: re-evaluation after every recorded result."""
    view = _deep_view()
    hyp = _deep_hyp()
    planner = StatefulPlanner()
    planner.attach([hyp])
    planner.record_observation("h-deep", "identity:ext-1", "obs-1")
    plan = planner.setup_plan(_deep_precond(hyp), hyp, view)
    assert plan is not None and len(plan.hops) == 2
    assert planner.observe_state("workflows/wf-4", "review")
    replan = planner.setup_plan(_deep_precond(hyp), hyp, view)
    assert replan is not None and len(replan.hops) == 1
    assert replan.hops[0].result_state == "ready"


def test_multi_hop_no_advancing_transition_parks() -> None:
    """Nothing in the surface's own table advances the chain: the
    hypothesis is parked inconclusive, never flagged, never blocked
    and never a negative verdict."""
    from dataclasses import replace
    view = replace(_deep_view(), workflow_action_targets={
        "workflows/wf-4": {"approve": "approved"}})
    hyp = _deep_hyp()
    planner = StatefulPlanner()
    planner.attach([hyp])
    planner.record_observation("h-deep", "identity:ext-1", "obs-1")
    assert planner.decide(hyp, view) is PlannerDecision.INCONCLUSIVE
    assert planner.ledger.verdict_gate("h-deep") == "unverified"


def test_multi_hop_budget_shortfall_parks() -> None:
    """A setup budget that cannot carry the full minimal sequence
    parks the hypothesis: partial establishment would leave the
    discriminating experiment unrunnable while spending requests."""
    view = _deep_view()
    hyp = _deep_hyp()
    planner = StatefulPlanner(
        config=PlannerConfig(max_setup_actions=1))
    planner.attach([hyp])
    planner.record_observation("h-deep", "identity:ext-1", "obs-1")
    assert planner.decide(hyp, view) is PlannerDecision.INCONCLUSIVE
    assert planner.ledger.verdict_gate("h-deep") == "unverified"
    assert planner.tally()["setup_actions_attempted"] == 0


def test_requirements_extend_the_minimal_sequence() -> None:
    """The surface's own published checklist is a dependency the
    chain alone cannot express: a final transition gated on N
    requirements needs N advancement applications even when the
    stage chain implies fewer hops. Derivation stays keyed on the
    surface's own published counts (never fixture knowledge), and
    the stall hop's postcondition (accepted action, no stage
    regression) is verified by its re-read."""
    from dataclasses import replace
    view = replace(_deep_view(), workflow_requirements={
        "workflows/wf-4": ("req-1", "req-2", "req-3")})
    hyp = _deep_hyp()
    planner = StatefulPlanner()
    planner.attach([hyp])
    planner.record_observation("h-deep", "identity:ext-1", "obs-1")
    assert planner.decide(hyp, view) is PlannerDecision.SETUP
    plan = planner.setup_plan(_deep_precond(hyp), hyp, view)
    assert plan is not None
    assert len(plan.hops) == 3
    first, second, third = plan.hops
    assert first.result_state == "review"
    assert second.result_state == "ready"
    # the third application satisfies the last published
    # requirement: the stage STALLS at the required state (the
    # surface's own chain says the approve transition's source is
    # 'ready'), so its re-read must show the required state with no
    # regression — and the action must have been accepted
    assert third.params == (("action", "satisfy"),)
    assert third.result_state == "ready"
    assert third.actor == "owner-1"
    assert third.idempotency_key not in {
        first.idempotency_key, second.idempotency_key}
    assert planner.tally()["setup_actions_attempted"] == 3


def test_requirements_within_the_chain_add_no_hops() -> None:
    """A checklist no longer than the chain's own hop count changes
    nothing: the chain hops dominate."""
    from dataclasses import replace
    view = replace(_deep_view(), workflow_requirements={
        "workflows/wf-4": ("req-1",)})
    hyp = _deep_hyp()
    planner = StatefulPlanner()
    planner.attach([hyp])
    planner.record_observation("h-deep", "identity:ext-1", "obs-1")
    plan = planner.setup_plan(_deep_precond(hyp), hyp, view)
    assert plan is not None and len(plan.hops) == 2


# -- assertion-ledger integration (L10 Phase 2/3) ---------------------

def test_link_assertions_seeds_inferred_beliefs_and_edges() -> None:
    """State beliefs start INFERRED from the view's own first
    observation, are never facts, and the transition assertion is
    registered as their dependent for re-evaluation."""
    view = _deep_view()
    hyp = _deep_hyp()
    planner = StatefulPlanner()
    planner.attach([hyp])
    planner.link_assertions("h-deep", view)
    assertion = planner.assertions.get("state:workflows/wf-4")
    assert assertion is not None
    assert assertion.status.value == "inferred"
    assert assertion.is_fact is False
    # a contradiction of the state belief demotes the transition
    # assertion for re-evaluation
    _, reevaluate = planner.assertions.invalidate(
        "state:workflows/wf-4", "obs-x", reason="test")
    assert "transition:workflows/wf-4:source-state" in reevaluate


def test_assert_state_verifies_only_with_observation_id() -> None:
    """A verified hop records an observation-backed VERIFIED
    assertion; the transition dependency is demoted on the advance
    (the old belief is explicitly invalidated, never overwritten)
    and the new state is re-asserted and verified."""
    view = _deep_view()
    hyp = _deep_hyp()
    planner = StatefulPlanner()
    planner.attach([hyp])
    planner.link_assertions("h-deep", view)
    reevaluate = planner.assert_state(
        "workflows/wf-4", "review", "obs-hop-1")
    assertion = planner.assertions.get("state:workflows/wf-4")
    assert assertion.status.value == "verified"
    assert assertion.is_fact is True
    assert assertion.provenance.observation_id == "obs-hop-1"
    # the advance invalidated the seeded 'intake' belief, so the
    # dependent transition assertion was demoted for re-evaluation
    assert "transition:workflows/wf-4:source-state" in reevaluate
    # re-reading the same state reconciles without demotion
    assert planner.assert_state(
        "workflows/wf-4", "review", "obs-hop-2") == set()


def test_refute_state_invalidates_on_disagreement_only() -> None:
    """A refused hop whose re-read agrees with the belief leaves it
    standing; a re-read that disagrees explicitly invalidates the
    belief and demotes its dependents."""
    view = _deep_view()
    hyp = _deep_hyp()
    planner = StatefulPlanner()
    planner.attach([hyp])
    planner.link_assertions("h-deep", view)
    # refused hop, state unchanged: the belief stands
    assert planner.refute_state(
        "workflows/wf-4", "intake", "obs-refused") == set()
    assert planner.assertions.get(
        "state:workflows/wf-4").status.value == "inferred"
    # re-read disagrees with the belief: explicit invalidation (the
    # dependent was already demoted to UNKNOWN by the advance's
    # invalidation, so nothing changes again — it stays in
    # re-evaluation while the belief is terminal)
    planner.assert_state("workflows/wf-4", "review", "obs-hop-1")
    assert planner.refute_state(
        "workflows/wf-4", "intake", "obs-contradict") == set()
    invalidated = planner.assertions.get("state:workflows/wf-4")
    assert invalidated.status.value == "invalidated"
    assert planner.assertions.get(
        "transition:workflows/wf-4:source-state"
    ).status.value == "unknown"


def test_demote_dependents_reverts_observed_precondition() -> None:
    """An invalidated belief demotes the OBSERVED precondition that
    rested on it back to INFERRED: it gates nothing again until a
    new observation re-verifies it."""
    hyp = _deep_hyp()
    planner = StatefulPlanner()
    planner.attach([hyp])
    planner.record_observation("h-deep", "identity:ext-1", "obs-0")
    planner.record_observation(
        "h-deep", "transition:workflows/wf-4:source-state", "obs-1")
    assert planner.ledger.verdict_gate("h-deep") != "unverified"
    demoted = planner.demote_assertion_dependents({
        "transition:workflows/wf-4:source-state"})
    assert demoted == ["h-deep:transition:workflows/"
                       "wf-4:source-state"]
    precond = planner.ledger.get("h-deep")[1]
    assert precond.status is PreconditionStatus.INFERRED
    assert planner.ledger.verdict_gate("h-deep") == "unverified"
