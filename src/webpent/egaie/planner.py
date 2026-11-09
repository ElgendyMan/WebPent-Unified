"""L9 §3 — bounded stateful investigation planner.

A planning layer over the differential engine's hypotheses: each
hypothesis carries structured preconditions (see
``webpent.egaie.prerequisites``); this module decides, per
hypothesis, what must happen before its discriminating experiment
can mean anything, and expresses that as the minimal valid
experiment sequence:

- prefer read-only observations that resolve uncertainty;
- propose a state-changing setup action only when it is authorized,
  in scope, and the cheapest path to a discriminating experiment,
  always with an idempotency key through the existing
  ActionAuthority/ActionExecutor path (the setup is an explicit
  investigation action, never silent);
- re-evaluate after every recorded result (no fixed sequences);
- stop on falsified, evidence sufficient, precondition unattainable
  or budget exhausted.

The rules this module exists to enforce (never violated, never
relaxed):

- an inferred precondition is never treated as a verified fact;
- a failed attempt to reach a precondition BLOCKS the hypothesis
  and never becomes a negative security verdict;
- an HTTP success alone never proves a transition: every setup is
  followed by a read-only re-read and only the re-read's state can
  verify the precondition.

The planner proposes through the same channels the proposer uses; it
does not execute anything itself and cannot bypass authorization,
scope or capability checks, which stay in ActionAuthority. Every
setup action it derives uses the surface's OWN vocabulary (owner,
action names, states all come from the observed view) — nothing
about any specific application is hard-coded.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from webpent.egaie.assertions import AssertionLedger
from webpent.egaie.differential import (
    ProbeStep,
    RelationshipView,
)
from webpent.egaie.prerequisites import (
    Precondition,
    PreconditionKind,
    PreconditionStatus,
    PrerequisiteLedger,
)
from webpent.egaie.workflow_discovery import WorkflowDiscovery


class PlannerDecision(StrEnum):
    """What must happen before (or instead of) the experiment."""

    RUN = "run"                       # gate clear: experiment may run
    VERIFY_READ_ONLY = "verify_read_only"  # read-only resolves it
    SETUP = "setup"                   # authorized setup action first
    BLOCKED = "blocked"               # unattainable; never a verdict
    INCONCLUSIVE = "inconclusive"     # parked; never a verdict


class BlockReason(StrEnum):
    """Why a setup attempt failed to reach its precondition (L9 §4).

    Every reason maps to UNATTAINABLE: the hypothesis is parked,
    never scored as a negative security result."""

    AUTHORIZATION = "authorization"
    UNAVAILABLE = "unavailable"
    TRANSITION_WITHOUT_EFFECT = "transition_without_effect"


@dataclass(frozen=True)
class SetupAction:
    """One authorized, scoped, reversible, budgeted state-changing
    action whose only job is to reach a hypothesis's precondition.

    The idempotency key travels in the step params through the
    existing ActionAuthority/ActionExecutor path, so a replayed
    setup cannot double-apply."""

    action_id: str
    hypothesis_id: str
    target: str          # the precondition target it establishes
    method: str
    path: str
    actor: str
    params: tuple[tuple[str, str], ...]
    idempotency_key: str
    rationale: str
    # The chain state this hop's re-read must show. HTTP success
    # alone never proves the hop: only the re-read can.
    result_state: str = ""
    # Budget accounting: setup actions count in the SAME request
    # budget as probes (one POST + one verification re-read).
    request_cost: int = 2

    def to_steps(self, idem_param: str,
                 verify_path: str) -> tuple[ProbeStep, ...]:
        """The setup as probe steps: the state-changing POST (with
        the idempotency key) followed by a read-only re-read. HTTP
        success alone never proves a transition; the re-read is what
        the planner verifies against."""
        return (
            ProbeStep(
                purpose="baseline",
                label=f"{self.action_id}-setup",
                method=self.method,
                path=self.path,
                actor=self.actor,
                params=self.params + ((idem_param,
                                       self.idempotency_key),)),
            ProbeStep(
                purpose="baseline",
                label=f"{self.action_id}-verify",
                method="GET",
                path=verify_path,
                actor=self.actor),
        )


@dataclass(frozen=True)
class SetupPlan:
    """The MINIMAL ordered sequence of authorized setup hops that
    walks a workflow from its current state to a precondition's
    required source state (L10 Phase 3: multi-step dependency
    graphs over the surface's own state description).

    Every hop carries the chain state its re-read must show; the
    executor verifies each hop in order and stops at the first
    failure (fail-closed: a failed hop BLOCKS the hypothesis and
    never becomes a negative security verdict). Reapplication hops
    (an advancing transition applied again on a forward-only chain)
    are INFERRED plans: only their per-hop re-read can verify them."""

    hypothesis_id: str
    target: str          # the precondition target the plan establishes
    hops: tuple[SetupAction, ...]

    def to_steps(self, idem_param: str,
                 verify_path: str) -> tuple[ProbeStep, ...]:
        """All hops as probe steps: each state-changing POST (with
        its own idempotency key) followed by its read-only re-read."""
        steps: list[ProbeStep] = []
        for hop in self.hops:
            steps.extend(hop.to_steps(idem_param, verify_path))
        return tuple(steps)


@dataclass
class PlannerEvent:
    """One recordable planner event (§6 accounting)."""

    kind: str          # declared | verified | setup_failed |
                       # parked_inconclusive | stopped
    hypothesis_id: str
    target: str = ""
    detail: str = ""


@dataclass
class PlannerConfig:
    prerequisite_reasoning: bool = True
    # Total reserved setup actions across the run. Sized for the
    # L10 pre-establishment path: a survey-style plan legitimately
    # fronts a per-path establishment (one precond per probed
    # workflow, each the minimal hop sequence the surface's own
    # published chain and requirements imply), so the budget must
    # carry several paths' worth of hops, not one hypothesis's. The
    # per-precond derivation stays minimal; the cap bounds only the
    # run's total, and a plan that does not fit is parked (never
    # partially executed).
    max_setup_actions: int = 24
    prefer_read_only: bool = True
    # The surface's own action-parameter name. Empty (the default)
    # means DERIVED FROM THE SURFACE: the planner reads it off the
    # observed view (which carries it from the target's own schema
    # bindings) at derivation time, because reconnaissance happens
    # inside the run, after the planner is wired. An explicit value
    # overrides the derivation (fixture tests). The planner never
    # assumes a fixed name.
    action_param: str = ""


class StatefulPlanner:
    """Dependency graph over hypotheses × preconditions × setup
    actions, with post-result re-evaluation.

    The planner never executes: it decides and proposes. Execution
    always goes through the same port machinery as every probe, so
    authorization, scope, capability, budget and idempotency remain
    the production path, unchanged."""

    def __init__(
            self,
            config: PlannerConfig | None = None,
            ledger: PrerequisiteLedger | None = None,
            discovery: WorkflowDiscovery | None = None,
    ) -> None:
        self.config = config or PlannerConfig()
        self.ledger = ledger or PrerequisiteLedger()
        # L10 Phase 4: the attached workflow discovery component
        # (optional). Where the surface publishes NO chain and NO
        # action table, the planner derives needs and hops from the
        # edges this component OBSERVED (mined from the ledger or
        # learned through bounded probes) — never invented ones.
        # A bare planner (no discovery) behaves exactly as in L9.
        self.discovery = discovery
        self.events: list[PlannerEvent] = []
        # investigation-wide assertion ledger (L10 Phase 2/3): state
        # beliefs with explicit provenance, seeded INFERRED from the
        # view, VERIFIED only by a re-read carrying its observation
        # id, invalidated (never overwritten) on contradiction.
        self.assertions = AssertionLedger()
        self._setup_count = 0
        self._setup_failures: dict[str, BlockReason] = {}
        # hypothesis_id -> falsified | evidence_sufficient
        self._stopped: dict[str, str] = {}
        # current state per workflow path (starts at the first
        # observed state and is updated from every re-read)
        self._state: dict[str, str] = {}
        # path -> transition OBSERVED (verified re-read) to advance
        # that path's chain: the observation-grounded reapplication
        # license for later derivations
        self._observed_advancers: dict[str, str] = {}

    # -- graph construction ------------------------------------------

    def attach(self, hypotheses: Any) -> None:
        """Register hypotheses and their structured preconditions.
        Hypotheses without preconditions are ungated (they run as
        before); nothing else about them changes."""
        for hyp in hypotheses:
            preconds = tuple(hyp.prerequisites)
            self.ledger.declare(hyp.hypothesis_id, preconds)
            if preconds:
                self.events.append(PlannerEvent(
                    kind="declared",
                    hypothesis_id=hyp.hypothesis_id,
                    target=",".join(p.target for p in preconds)))

    def seed_state(self, path: str, state: str) -> None:
        """Record the currently observed state of a workflow path
        (the view's first-observed state, or a later re-read)."""
        self._state.setdefault(path, state)

    def current_state(self, path: str, view: RelationshipView) -> str:
        """The planner's current state belief for a workflow path:
        the last state a re-read verified (its own re-reads and the
        re-reads of hops and probes executed on its behalf), falling
        back to the view's first-observed state. Never a guess."""
        return (
            self._state.get(path)
            or view.workflow_state.get(path)
            or "")

    def observe_state(self, path: str, state: str) -> bool:
        """Update the state of a workflow path from a re-read.
        Returns True when the state changed."""
        if self._state.get(path) == state:
            return False
        self._state[path] = state
        return True

    def note_advancement(self, path: str, action: str) -> None:
        """A verified hop's re-read showed this transition advancing
        the path's chain: recorded as the observation-grounded
        reapplication license for later derivations. An observation,
        never an assumption."""
        self._observed_advancers.setdefault(path, action)

    # -- assertion ledger (L10 Phase 2/3) -------------------------------

    def link_assertions(self, hypothesis_id: str,
                        view: RelationshipView) -> None:
        """Seed and link the investigation-wide assertion ledger for
        one hypothesis's transition preconditions: each ``state:<path>``
        belief starts INFERRED (from the view's own first observation,
        never a fact) and the transition assertion is registered as
        its dependent, so a later contradiction demotes the transition
        for re-evaluation instead of silently keeping it. State
        beliefs are seeded from the view alone — no fixture
        knowledge, and an already-asserted belief is never demoted
        by re-seeding."""
        for precond in self.ledger.get(hypothesis_id):
            if precond.kind is not PreconditionKind.WORKFLOW_TRANSITION:
                continue
            parts = precond.target.split(":", 2)
            if len(parts) < 2:
                continue
            path = parts[1]
            state_key = f"state:{path}"
            if (state_key not in self.assertions.assertions
                    and view.workflow_state.get(path)):
                self.assertions.infer(
                    state_key, view.workflow_state[path],
                    detail="seeded from the relationship view's "
                           "first-observed state")
            self.assertions.depends_on(state_key, precond.target)
            # the transition belief itself is also an assertion
            # (INFERRED): a demotion of it — directly or through its
            # state belief — is a real status change, not a
            # graph-only entry nothing can observe
            if precond.target not in self.assertions.assertions:
                self.assertions.infer(
                    precond.target, "",
                    detail="the hypothesis's source-state belief, "
                           "seeded inferred (never a fact)")

    def assert_state(self, path: str, state: str,
                     observation_id: str) -> set[str]:
        """Record a re-read-backed state belief — the ONLY way a
        state assertion becomes VERIFIED is this call carrying the
        re-read's observation id. When the re-read shows a different
        state than the asserted belief, the old belief is explicitly
        INVALIDATED (never silently overwritten) and its dependents
        are demoted to UNKNOWN for re-evaluation; the new state is
        then re-asserted and verified.

        Returns the demoted dependents (the re-evaluation set)."""
        key = f"state:{path}"
        current = self.assertions.get(key)
        reevaluate: set[str] = set()
        if current is not None and current.value != state:
            _, reevaluate = self.assertions.invalidate(
                key, observation_id,
                reason=f"state advanced: re-read shows {state!r}")
            current = None
        if current is None:
            self.assertions.infer(
                key, state,
                detail="from the workflow's own transition result")
        self.assertions.verify(
            key, state, observation_id,
            detail="setup hop re-read")
        return reevaluate

    def refute_state(self, path: str, observed: str,
                     observation_id: str) -> set[str]:
        """A setup hop failed and its re-read shows a state that
        disagrees with the asserted belief: the belief is explicitly
        INVALIDATED (a disagreement never overwrites) and its
        dependents are demoted to UNKNOWN for re-evaluation. When the
        re-read agrees with the belief (the hop was refused but the
        state is what we thought), the belief stands — the hop
        failure is recorded by the caller, and no demotion is
        warranted. Returns the demoted dependents."""
        key = f"state:{path}"
        current = self.assertions.get(key)
        if current is None or current.value == observed:
            return set()
        _, reevaluate = self.assertions.invalidate(
            key, observation_id,
            reason=f"re-read shows {observed!r}, not the asserted "
                   "state")
        return reevaluate

    def demote_assertion_dependents(self, keys: set[str]) -> list[str]:
        """Re-evaluation: every OBSERVED precondition whose target is
        a demoted assertion key goes back to INFERRED in the
        per-hypothesis ledger — it gates nothing again until a new
        observation re-verifies it. Returns the demoted pairs."""
        return self.ledger.demote_dependents(keys)

    # -- decision -----------------------------------------------------

    def decide(self, hypothesis: Any,
               view: RelationshipView) -> PlannerDecision:
        """The single decision point. Precedence: stopped > blocked
        > read-only verification > setup > parked inconclusive.
        Called again after every recorded result (re-evaluation);
        there are no fixed sequences."""
        hyp_id = hypothesis.hypothesis_id
        if hyp_id in self._stopped:
            return PlannerDecision.BLOCKED
        gate = self.ledger.verdict_gate(hyp_id)
        if gate == "blocked":
            return PlannerDecision.BLOCKED
        if gate == "clear":
            return PlannerDecision.RUN
        unmet = self.ledger.unverified(hyp_id)
        read_only = [p for p in unmet
                     if p.kind is not PreconditionKind.WORKFLOW_TRANSITION]
        if read_only and self.config.prefer_read_only:
            return PlannerDecision.VERIFY_READ_ONLY
        if not self.config.prerequisite_reasoning:
            return self._park(hyp_id, unmet)
        for precond in unmet:
            if precond.kind is not PreconditionKind.WORKFLOW_TRANSITION:
                continue
            needed = self._transition_need(precond, hypothesis, view)
            if needed is None:
                # no derivable requirement from the surface's own
                # state description: nothing authorized to do
                return self._park(hyp_id, unmet)
            required, current, chain = needed
            if current == required:
                # already satisfied on the wire: a read-only re-read
                # verifies it (HTTP history is not proof, the re-read
                # is)
                return PlannerDecision.VERIFY_READ_ONLY
            if chain.index(required) > chain.index(current):
                if self._derive_plan(precond, hypothesis, view,
                                     reserve=False) is not None:
                    return PlannerDecision.SETUP
                return self._park(hyp_id, unmet)
            # required state precedes the current one: transitions
            # never rewind, so the precondition is unavailable.
            self.record_setup_failure(
                hyp_id, precond.target, BlockReason.UNAVAILABLE)
            return PlannerDecision.BLOCKED
        return self._park(hyp_id, unmet)

    def order(self, hypotheses: Any,
              view: RelationshipView) -> list[tuple[Any, PlannerDecision]]:
        """Minimal valid sequence: read-only verification first,
        then ungated experiments, then setup-gated hypotheses, then
        parked/blocked. Re-derived by the caller after every
        result."""
        decisions = [(h, self.decide(h, view)) for h in hypotheses]
        rank = {PlannerDecision.VERIFY_READ_ONLY: 0,
                PlannerDecision.RUN: 1,
                PlannerDecision.SETUP: 2,
                PlannerDecision.INCONCLUSIVE: 3,
                PlannerDecision.BLOCKED: 4}
        if self.config.prefer_read_only:
            decisions.sort(key=lambda pair: rank[pair[1]])
        return decisions

    # -- setup synthesis ----------------------------------------------

    def setup_plan(
            self, precondition: Precondition, hypothesis: Any,
            view: RelationshipView,
    ) -> SetupPlan | None:
        """Derive the MINIMAL authorized setup sequence for one
        transition precondition and reserve its hops against the
        configured cap (the caller commits to executing them in
        order). Returns None when no authorized sequence is
        derivable (the caller must park the hypothesis, never flag
        it)."""
        return self._derive_plan(
            precondition, hypothesis, view, reserve=True)

    def _derive_plan(
            self, precondition: Precondition, hypothesis: Any,
            view: RelationshipView, reserve: bool,
    ) -> SetupPlan | None:
        """Derive the minimal authorized hop sequence that walks the
        workflow from its current state to the required source
        state, using ONLY the surface's own description (the
        published chain and action table) and the workflow's
        recorded owner. Nothing about any specific application is
        hard-coded.

        Each hop moves the chain one step forward. A hop prefers the
        table's own action whose published result is the needed
        state; where the table publishes none, the surface's
        advancing transition (its published result is a later chain
        state on the same forward-only chain) is REAPPLIED to
        advance one more step — an INFERRED plan whose only
        verification is the per-hop re-read. A hop that fails its
        re-read blocks the hypothesis (never a verdict)."""
        if self._setup_count >= self.config.max_setup_actions:
            return None
        needed = self._transition_need(precondition, hypothesis, view)
        if needed is None:
            return None
        required, current, chain = needed
        if current == required:
            return None
        cur_i, req_i = chain.index(current), chain.index(required)
        if req_i <= cur_i:
            return None  # cannot rewind a forward-only machine
        path = precondition.target.split(":", 2)[1]
        owner = view.workflow_owner.get(path)
        if not owner:
            return None
        targets = view.workflow_action_targets.get(path, {})
        # Reapplication licenses, strongest first: (a) the planner's
        # own OBSERVED advancement of this path (a verified hop's
        # re-read showed this transition advancing the chain);
        # (b) the table-grounded inference that the transition whose
        # published result is the state we sit at advances one more
        # step on the surface's own forward-only chain; (c) the
        # previous hop of this same plan (verified by its own
        # re-read at execution time). Every reapplication hop is an
        # INFERRED plan: only its re-read can confirm it.
        observed = self._observed_advancers.get(path)
        prev_action: str | None = None
        hops: list[SetupAction] = []
        # The surface's own published checklist is a dependency the
        # stage chain alone cannot express: a final transition gated
        # on N requirements needs N advancement applications even
        # when the chain implies fewer hops. The published counts
        # decide which model dominates; every application is
        # verified by its own re-read (an extra application's
        # postcondition is the required state with NO regression,
        # and the action actually accepted).
        #
        # L10 Phase 10: the requirement count credits the progress
        # the workflow has ALREADY made. On the same model the chain
        # model already assumes — each advancement application moves
        # the chain one step AND satisfies one requirement — a
        # workflow already at chain index cur_i has consumed
        # min(cur_i, N) requirements, so the applications still owed
        # are max(0, N - cur_i), and the plan owes the larger of
        # that and the remaining chain hops. Counting from the start
        # of the chain instead would oversatisfy: an application
        # past the last unmet requirement is not a stall, it is an
        # unmet-requirement lookup on a complete checklist — an
        # error the surface never guards, and a hop whose re-read
        # can never verify it. The model stays the surface's own
        # published description (chain, N) plus the position its
        # re-reads reported; no application vocabulary is assumed.
        requirements = view.workflow_requirements.get(path) or ()
        applications_owed = max(
            req_i - cur_i, max(0, len(requirements) - cur_i))
        extra = applications_owed - (req_i - cur_i)
        for step_i in range(cur_i, req_i):
            needed_state = chain[step_i + 1]
            at_state = chain[step_i]
            action = next(
                (name for name in sorted(targets)
                 if targets[name] == needed_state), None)
            if action is None:
                action = observed
            if action is None:
                action = next(
                    (name for name in sorted(targets)
                     if targets[name] == at_state), None)
            if action is None and self.discovery is not None:
                # L10 Phase 4: the table is silent — the hop action
                # comes from an edge the ledger itself OBSERVED
                # (an accepted transition whose re-read showed the
                # needed state), never invented. Quarantined edges
                # are excluded by the discovery component itself.
                d_edges = self.discovery.transitions(path)
                action = next(
                    (a for (frm, a), to in sorted(d_edges.items())
                     if frm == at_state and to == needed_state),
                    None)
            if action is None:
                action = prev_action
            if action is None:
                return None
            prev_action = action
            hops.append(self._hop(
                action, needed_state, path, owner, len(hops) + 1,
                self._action_param(view), precondition, hypothesis))
        # requirement applications beyond the chain's own hops: the
        # stage STALLS at the required source state while the last
        # requirements are satisfied, so the postcondition is the
        # required state with no regression (never a move past it)
        for _ in range(extra):
            if prev_action is None:
                return None
            hops.append(self._hop(
                prev_action, required, path, owner, len(hops) + 1,
                self._action_param(view), precondition, hypothesis,
                rationale_extra=(
                    f" (satisfies one of the {len(requirements)} "
                    "requirements the surface publishes for this "
                    "workflow; the stage stalls at the required "
                    "state)")))
        if not hops:
            return None
        if (self._setup_count + len(hops)
                > self.config.max_setup_actions):
            # the budget cannot carry the full minimal sequence:
            # partial establishment would spend requests while
            # leaving the experiment unrunnable — park, never block
            # (the budget said no, the surface never said insecure)
            return None
        if reserve:
            self._setup_count += len(hops)
        return SetupPlan(
            hypothesis_id=hypothesis.hypothesis_id,
            target=precondition.target,
            hops=tuple(hops),
        )

    def _hop(
            self, action: str, result_state: str, path: str,
            owner: str, ordinal: int, action_param: str,
            precondition: Precondition,
            hypothesis: Any,
            rationale_extra: str = "",
    ) -> SetupAction:
        """One authorized setup hop through the surface's own
        vocabulary.

        L10 Phase 10: the action id is unique per TARGET PATH, not
        only per plan ordinal — a plan may hop several workflows
        (the cross-group authority survey probes every published
        group), and the probe-step labels and the executor's
        idempotency token both derive from the action id. Ordinal
        alone would give every hop in such a plan the same labels
        and the same token, so the executor's replay guard would
        refuse every hop after the first as a duplicate of the one
        before it (observed on the L10 dev block: the first hop
        applied, its three siblings came back unexecuted)."""
        action_id = (
            f"setup-{ordinal:02d}"
            f"-{path.replace('/', '-').strip('-')}")
        return SetupAction(
            action_id=action_id,
            hypothesis_id=hypothesis.hypothesis_id,
            target=precondition.target,
            method="POST",
            path=path,
            actor=owner,
            params=((action_param, action),),
            idempotency_key=f"{action_id}:{path.replace('/', '-')}",
            result_state=result_state,
            rationale=(
                f"advance {path} into {result_state!r} as its "
                f"recorded owner, using the surface's own "
                f"{action!r} transition{rationale_extra}"),
        )

    # -- surface vocabulary --------------------------------------------

    def _action_param(self, view: RelationshipView) -> str:
        """The surface's own action-parameter name: the explicit
        config override when set, otherwise the name the view
        observed in the target's own schema (L9 §3: nothing about
        the surface is assumed)."""
        if self.config.action_param:
            return self.config.action_param
        return view.action_param or "action"

    # -- post-result re-evaluation ------------------------------------

    def record_observation(
            self, hypothesis_id: str, target: str,
            observation_id: str) -> Precondition | None:
        """A recorded observation may verify a precondition (e.g. a
        re-read showing the reached state). Nothing else can."""
        verified = self.ledger.verify(
            hypothesis_id, target, observation_id)
        self.events.append(PlannerEvent(
            kind="verified", hypothesis_id=hypothesis_id,
            target=target, detail=observation_id))
        return verified

    def record_setup_failure(
            self, hypothesis_id: str, target: str,
            reason: BlockReason) -> None:
        """A failed setup BLOCKS the hypothesis. This is recorded as
        blocked/inconclusive evidence and NEVER becomes a negative
        security verdict: unattainable preconditions carry
        UnattainableEffect.NEVER_A_VERDICT in the ledger."""
        self._setup_failures[target] = reason
        self.ledger.mark_unattainable(
            hypothesis_id, target, via=f"setup failed: {reason.value}")
        self.events.append(PlannerEvent(
            kind="setup_failed", hypothesis_id=hypothesis_id,
            target=target, detail=reason.value))

    def record_stopped(self, hypothesis_id: str,
                       reason: str) -> None:
        """falsified | evidence_sufficient — the hypothesis leaves
        the schedule either way."""
        self._stopped[hypothesis_id] = reason
        self.events.append(PlannerEvent(
            kind="stopped", hypothesis_id=hypothesis_id,
            detail=reason))

    # -- §6 accounting -------------------------------------------------

    def tally(self) -> dict[str, Any]:
        verified = sum(
            1 for e in self.events if e.kind == "verified")
        failed = sum(
            1 for e in self.events if e.kind == "setup_failed")
        declared = sum(
            1 for e in self.events if e.kind == "declared")
        parked = sum(
            1 for e in self.events
            if e.kind == "parked_inconclusive")
        # unknown = declared preconditions that ended neither
        # verified nor failed (the investigation ended first)
        unknown = max(0, declared - verified - failed)
        tally = {
            "prerequisites_identified": declared,
            "prerequisites_verified": verified,
            "prerequisites_failed": failed,
            "prerequisites_unknown": unknown,
            "setup_actions_attempted": self._setup_count,
            "hypotheses_parked_inconclusive": parked,
            "hypotheses_stopped": len(self._stopped),
            "setup_failures_by_reason": {
                r.value: sum(1 for v in self._setup_failures.values()
                             if v is r)
                for r in BlockReason},
            "assertions": dict(self.assertions.tally()),
        }
        # L10 Phase 4: the discovery component's own accounting,
        # reported only when one is attached (a bare L9 planner
        # reports exactly what it reported before)
        if self.discovery is not None:
            tally["workflow_discovery"] = {
                "probes_attempted": self.discovery.actions_spent,
                "probe_budget": self.discovery.max_discovery_actions,
                "contradictions": len(self.discovery.contradictions),
            }
        return tally

    # -- internals ------------------------------------------------------

    def _park(self, hyp_id: str,
              unmet: tuple[Precondition, ...]) -> PlannerDecision:
        """No authorized way to verify or establish the remaining
        preconditions: the hypothesis is parked. This is
        INCONCLUSIVE evidence, never a negative security verdict
        and never a finding."""
        self.events.append(PlannerEvent(
            kind="parked_inconclusive", hypothesis_id=hyp_id,
            detail=",".join(p.target for p in unmet)))
        return PlannerDecision.INCONCLUSIVE

    def _transition_need(
            self, precondition: Precondition, hypothesis: Any,
            view: RelationshipView,
    ) -> tuple[str, str, tuple[str, ...]] | None:
        """(required source state, current state, chain) for one
        transition precondition, derived from the hypothesis's own
        probe step and the surface's state description — or None
        when the surface exposes too little to derive anything."""
        path = precondition.target.split(":", 2)[1]
        chain = view.workflow_chains.get(path)
        targets = view.workflow_action_targets.get(path)
        if not chain or not targets:
            # L10 Phase 4: where the surface publishes NO chain or
            # NO action table, the need may still be derivable from
            # the transitions the ledger itself observed. The
            # published schema keeps priority everywhere it exists.
            return self._discovery_transition_need(
                precondition, hypothesis, view, path)
        step = next(
            (s for s in hypothesis.plan.steps
             if s.method == "POST" and s.path == path),
            None)
        if step is None:
            return None
        action = next(
            (value for key, value in step.params
             if key == self._action_param(view) and value in targets),
            None)
        if action is None:
            return None
        result = targets[action]
        if result not in chain:
            return None
        idx = chain.index(result)
        if idx == 0:
            return None  # no source state to reach
        required = chain[idx - 1]
        current = self._state.get(path) or view.workflow_state.get(path)
        if not current or current not in chain:
            return None
        return required, current, chain

    def _discovery_transition_need(
            self, precondition: Precondition, hypothesis: Any,
            view: RelationshipView, path: str,
    ) -> tuple[str, str, tuple[str, ...]] | None:
        """Need derivation when the surface publishes NO chain and
        NO action table (L10 Phase 4): the need is derived from the
        edges the ledger itself OBSERVED — the action's own observed
        source state on the discovery's forward-only chain. Nothing
        is invented: with no observed edge for the action there is
        no need, and the caller treats the precondition as unmet
        (never a verdict)."""
        if self.discovery is None:
            return None
        chain = self.discovery.chain(path)
        if not chain:
            return None
        step = next(
            (s for s in hypothesis.plan.steps
             if s.method == "POST" and s.path == path),
            None)
        if step is None:
            return None
        action = next(
            (value for key, value in step.params
             if key == self._action_param(view)),
            None)
        if action is None:
            return None
        sources = sorted({
            frm for frm, a in self.discovery.transitions(path)
            if a == action})
        if not sources:
            return None
        current = self._state.get(path) or view.workflow_state.get(path)
        if not current or current not in chain:
            return None
        # prefer a source state forward-reachable from the current
        # state; when none is (the observed source sits behind the
        # current state on the chain) the first observed source is
        # named anyway and the caller fails closed on chain order —
        # a forward-only machine is never rewound
        reachable = [
            s for s in sources
            if self.discovery.reachable(path, current, s) is True]
        required = reachable[0] if reachable else sources[0]
        return required, current, chain

    # -- remediation support (L9 §3: post-result re-evaluation) -------

    def transition_need(
            self, precondition: Precondition, hypothesis: Any,
            view: RelationshipView,
    ) -> tuple[str, str, tuple[str, ...]] | None:
        """Public form of the internal derivation: (required source
        state, current state, chain) for one transition precondition,
        or None when the surface exposes too little to derive it."""
        return self._transition_need(precondition, hypothesis, view)

    def ensure_declared(self, hypothesis: Any,
                        view: RelationshipView
                        ) -> tuple[Precondition, ...]:
        """Declare the workflow-transition preconditions a plan
        depends on, when nothing was declared for it yet, and return
        the declared preconditions (the existing ones when already
        declared).

        Generator-emitted hypotheses arrive with their full
        structured precondition set; plans emitted by the other
        proposers carry none. The remediation path needs the
        transition preconditions in the ledger either way (the
        accounting and the never-a-verdict bookkeeping live there),
        and the derivation is the same view-driven one the generator
        uses — the surface's own workflow paths and state chains,
        nothing hard-coded."""
        existing = self.ledger.get(hypothesis.hypothesis_id)
        if existing:
            return tuple(existing)
        preconds: list[Precondition] = []
        for path in sorted({s.path for s in hypothesis.plan.steps
                            if s.method == "POST"
                            and s.path in view.workflow_paths}):
            chain = view.workflow_chains.get(path)
            preconds.append(Precondition(
                kind=PreconditionKind.WORKFLOW_TRANSITION,
                target=f"transition:{path}:source-state",
                status=(PreconditionStatus.ESTABLISHABLE
                        if chain else PreconditionStatus.INFERRED),
                establish_via=(
                    "authorized setup transition as the "
                    "workflow owner"),
            ))
        self.ledger.declare(hypothesis.hypothesis_id, tuple(preconds))
        if preconds:
            self.events.append(PlannerEvent(
                kind="declared",
                hypothesis_id=hypothesis.hypothesis_id,
                target=",".join(p.target for p in preconds)))
        return tuple(preconds)


class PlannedHypothesis:
    """Adapter that lets the planner decide over a registered probe
    plan: the plan carries the hypothesis id and the probe steps the
    transition derivation reads."""

    __slots__ = ("hypothesis_id", "plan")

    def __init__(self, plan: Any) -> None:
        self.hypothesis_id = plan.hypothesis_id
        self.plan = plan
