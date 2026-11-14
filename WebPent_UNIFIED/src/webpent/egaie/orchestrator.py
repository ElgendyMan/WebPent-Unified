"""EGAIE InvestigationOrchestrator: the minimal closed loop.

Round structure: propose (advisory only) -> select by information gain
-> validate scope -> execute -> CausalGuard -> (on confirmed) seal a
CompleteProofBundle and replay-verify -> update state, repetition
register, world model -> record a deterministic decision.

Promotion discipline: a hypothesis is only set to CONFIRMED when
CausalGuard returned "confirmed" AND the sealed bundle replays valid.
Clean verdicts contradict; blocked/inconclusive outcomes feed the
repetition register and eventually force a strategy switch. Scope
denial is fail-closed: nothing executes, nothing is observed.
"""
from __future__ import annotations

from typing import Any

from webpent.egaie.differential import (
    DISPOSITION_ACTION_BLOCKED,
    VERDICT_INCONCLUSIVE,
    DifferentialGenerator,
    ProbeStep,
    RelationshipTracker,
    RelationshipView,
)
from webpent.egaie.planner import (
    BlockReason,
    PlannedHypothesis,
    PreconditionKind,
    StatefulPlanner,
)
from webpent.egaie.repetition import RepetitionRegister
from webpent.egaie.schemas import (
    DecisionAction,
    DecisionRecord,
    EvidenceItem,
    EvidenceKind,
    HypothesisStatus,
    InvestigationState,
    ProposedExperiment,
)
from webpent.egaie.selection import InformationGainSelector

# UNIFIED MERGE (2026-11-02): the orchestrator body is the l10
# lineage's, byte-identical except this header and the gated
# selector call marked below. Rationale: the 0.34.0 rewrite
# narrowed the loop to the minimal closed loop and dropped the
# planner-driven remediation, discovery-probe and availability
# machinery the L9/L10 contracts (and 26 tests) are written
# against; the restored body is a strict superset whose extra
# paths are all gated on planner/remediator presence, so the
# planner-less loop is behaviorally identical to 0.34.0's.


OUTCOME_CONFIRMED = "confirmed"
OUTCOME_CLEAN = "clean"
OUTCOME_INCONCLUSIVE = "inconclusive"
OUTCOME_UNVERIFIED = "unverified"


class InvestigationOrchestrator:
    def __init__(
        self,
        experiment_port: Any,
        validation_port: Any,
        proof_port: Any,
        model_port: Any,
        selector: InformationGainSelector | None = None,
        proposer: Any = None,
        planner: StatefulPlanner | None = None,
        remediator: Any = None,
    ) -> None:
        self.experiment_port = experiment_port
        self.validation_port = validation_port
        self.proof_port = proof_port
        self.model_port = model_port
        self.selector = selector or InformationGainSelector()
        self.proposer = proposer
        # Optional L9 stateful planner: when present, an outcome
        # classified as a blocked precondition (the source state a
        # probe needed was not established) triggers ONE bounded
        # remediation cycle — authorized setup transitions through
        # the ordinary action path, then a re-run. When absent the
        # loop is byte-identical to the pre-L9 behavior.
        self.planner = planner
        # Optional independent remediation strategy (L9 §6 baseline D):
        # an object with remediate(port, experiment) that derives its
        # setup from its OWN static recipe list, never from the
        # planner's reasoning. It rides the same execution machinery,
        # oracle and budgets; only the setup derivation differs.
        self.remediator = remediator
        self.register = RepetitionRegister()

    def run(
        self, state: InvestigationState, max_rounds: int
    ) -> InvestigationState:
        # Work on a deterministic copy: the caller's state is never
        # mutated in place, and resumed runs replay from the snapshot.
        working = InvestigationState.from_dict(state.to_dict())
        while True:
            if self.proposer is not None:
                proposals = self.proposer.propose(working)
                if proposals:
                    working.proposal_log.append({
                        "round": working.round,
                        "experiment_ids": [
                            p.experiment_id for p in proposals
                        ],
                    })
                for proposal in proposals:
                    working.add_experiment(proposal)
            if working.round >= max_rounds:
                working.terminal_reason = "round_budget_exhausted"
                break
            working.round += 1
            pending = working.pending_experiments()
            unresolved = working.unresolved_hypotheses()
            if not pending and not unresolved:
                working.terminal_reason = "objectives_complete"
                break
            if pending and not self.experiment_port.scope_allowed:
                working.terminal_reason = "scope_denied"
                break
            # UNIFIED MERGE (2026-11-02): the availability input
            # rides only on the planner-driven loop. With no
            # planner attached the call keeps the pre-L9 shape so
            # legacy selectors (and the ablation baselines that
            # inject their own) are called exactly as before.
            if self.planner is not None:
                decision = self.selector.select(
                    working, pending, self.register,
                    unavailable_hypotheses=(
                        self._unavailable_hypotheses()),
                    state_advancing_families=(
                        DifferentialGenerator.PRISTINE_FAMILIES),
                    remaining_rounds=max_rounds - working.round)
            else:
                decision = self.selector.select(
                    working, pending, self.register)
            working.record_decision(decision)
            if decision.action is not DecisionAction.SELECT:
                continue
            chosen = {
                e.experiment_id: e for e in pending
            }[decision.selected_experiment_id]
            self._run_experiment(working, chosen)
        return working

    def _unavailable_hypotheses(self) -> frozenset[str]:
        """Hypotheses the planner's ledger has marked unattainable:
        selection never retries them (L10 phase 5). Read-only over
        the planner's own accounting; empty when no planner is
        attached, so the pre-L9 loop is unchanged."""
        planner = self.planner
        if planner is None:
            return frozenset()
        return frozenset(
            hypothesis_id
            for hypothesis_id, preconds
            in planner.ledger.entries.items()
            if any(p.blocks_execution for p in preconds))

    def _run_experiment(
        self, state: InvestigationState, experiment: ProposedExperiment
    ) -> None:
        # L10 Phase 10: establish the experiment's own workflow
        # prerequisites BEFORE its first execution, not only after a
        # blocked verdict. A probe whose differential is only
        # observable once the surface's own published requirements
        # are satisfied (e.g. a transition gated on a completed
        # checklist) returns a misleading verdict when it is judged
        # on unprepared state: both sides are denied by the surface's
        # requirement gate, the denial reads as an identity decision,
        # and the hypothesis is scored clean without the setup ever
        # being attempted (the verdict is clean, not blocked, so the
        # remediation loop never fires). The derivation is the same
        # observation-driven one the remediation cycle uses — the
        # surface's own chain, action table and published
        # requirements, the recorded owner as the hop actor, every
        # hop verified by its own re-read — and it fails closed: a
        # hop that cannot be established blocks the hypothesis and
        # never becomes a verdict. Gated to the planner-driven
        # strategies: baseline C (prerequisite reasoning ablated)
        # and baseline D (its own remediation strategy) keep their
        # L9 semantics, so the comparison stays fair.
        if (self.remediator is None
                and self.planner is not None
                and self.planner.config.prerequisite_reasoning):
            self._establish_preconditions(experiment, pre_execution=True)
        baseline, candidate, control = self.experiment_port.execute(
            experiment
        )
        observations = {
            "experiment_id": experiment.experiment_id,
            "baseline": baseline,
            "candidate": candidate,
            "control": control,
        }
        state.observations.append(observations)
        self._harvest_state_observations(observations)
        causal = self.validation_port.validate(
            baseline, candidate, control
        )
        # bounded replanning on unexpected results (L10 Phase 3): the
        # planner may revise its setup from the new observations and
        # try again, up to a small round cap so requests stay
        # bounded. A static-recipe strategy (baseline D) keeps its
        # L9 one-cycle semantics: its recipe is fixed, so a second
        # round is definitionally identical work — re-firing it could
        # only burn the shared setup budget without incorporating any
        # new information. Either way, a round that derives no
        # authorized setup ends the loop.
        replan_rounds = 1 if self.remediator is not None else 3
        rounds = 0
        while (causal.get("verdict") == VERDICT_INCONCLUSIVE
               and causal.get("disposition")
               == DISPOSITION_ACTION_BLOCKED
               and rounds < replan_rounds
               and (self.planner is not None
                    or self.remediator is not None)):
            retried = self._remediate(experiment)
            if retried is None:
                break
            rounds += 1
            baseline, candidate, control = retried
            observations = {
                "experiment_id": experiment.experiment_id,
                "baseline": baseline,
                "candidate": candidate,
                "control": control,
            }
            state.observations[-1] = observations
            self._harvest_state_observations(observations)
            causal = self.validation_port.validate(
                baseline, candidate, control
            )
        model_result = self.model_port.update(
            state, experiment, observations, causal
        )
        state.world_model_updates.extend(
            model_result.get("world_model", []))
        state.attack_graph_updates.extend(
            model_result.get("attack_graph", []))
        verdict = causal["verdict"]
        if verdict == "confirmed":
            outcome, status, kind = self._confirm(
                state, experiment, baseline, candidate, control, causal
            )
        elif verdict == "clean":
            outcome = OUTCOME_CLEAN
            status = HypothesisStatus.CONTRADICTED
            kind = EvidenceKind.CONTRADICTING
        else:
            outcome = OUTCOME_INCONCLUSIVE
            status = None
            kind = None
        state.mark_experiment_outcome(experiment.experiment_id, outcome)
        if status is not None and kind is not None:
            self._update_hypothesis(state, experiment, status, kind, verdict)
        self.register.record(experiment.signature, outcome)
        if self.register.is_exhausted(experiment.signature):
            state.record_decision(DecisionRecord(
                round=state.round,
                action=DecisionAction.STRATEGY_SWITCH,
                selected_experiment_id="",
                scores={},
                alternatives=(),
                rationale=(
                    f"signature exhausted by repeated uninformative "
                    f"outcomes: {experiment.signature}"
                ),
            ))

    def _harvest_state_observations(
        self, observations: dict[str, Any]
    ) -> None:
        """L10 Phase 10: the planner's state belief follows every
        re-read the investigation has already gathered. An executed
        experiment's own baseline, candidate and control re-reads are
        observations of the surface's state; a belief that ignores
        them derives setup plans against states the surface has long
        since left, and its hop counts oversatisfy the very
        requirements they aim at (an application past the last unmet
        requirement is an error the surface never guards). Only
        executed GET re-reads are harvested — an HTTP success alone
        never proves a transition, here as in the judgment — and the
        update is a plain belief correction (observable, demotable),
        not registered as an assertion. Read-only when no planner is
        attached, so the pre-L9 loop is unchanged."""
        planner = self.planner
        if planner is None:
            return
        state_field = self.experiment_port.bindings.state_field
        for composite in (observations.get("baseline"),
                          observations.get("candidate"),
                          observations.get("control")):
            if not isinstance(composite, dict):
                continue
            for step in composite.get("steps") or ():
                if not isinstance(step, dict):
                    continue
                if (step.get("method") != "GET"
                        or step.get("execution") != "executed"):
                    continue
                structured = step.get("structured")
                if not isinstance(structured, dict):
                    continue
                state = structured.get(state_field)
                path = step.get("path")
                if (
                    isinstance(state, str) and state
                    and isinstance(path, str) and path
                ):
                    planner.observe_state(path, state)

    def _establish_preconditions(
        self, experiment: ProposedExperiment, pre_execution: bool = False,
    ) -> int:
        """Derive and execute the authorized setup transitions the
        experiment's own workflow-transition preconditions need, and
        return how many were established (L10 Phase 10).

        This is the derivation the L9 remediation cycle runs after a
        blocked verdict, lifted to run BEFORE the experiment's first
        execution: a differential that is only observable once the
        surface's own published requirements are satisfied must be
        judged on prepared state the first time, because an
        unprepared first run does not report blocked — both sides are
        denied by the requirement gate and the denial reads as an
        identity decision, so there is no second chance. The
        derivation uses only what the surface publishes and what the
        investigation has observed (its state chains, action table,
        published requirements and recorded owners); every hop runs
        through the experiment port's ordinary action path
        (authority, scope, capability, idempotency: the production
        path, unchanged) and is verified with its own re-read — never
        the hop's HTTP status. Fail-closed: a hop the re-read does
        not confirm BLOCKS the hypothesis and never becomes a
        negative security verdict, and a precondition with no
        derivable authorized setup stays unmet while the remaining
        establishable preconditions are still attempted (L9 §3: one
        unmet precondition must not strand the ones that can be
        reached).

        ``pre_execution`` (L10 Phase 10) restricts establishment to
        same-transition differentials: probes whose candidate and
        control steps POST the SAME action value. Such a probe
        compares one transition's authority across two contexts, so
        a requirement gate the surface itself publishes (an
        incomplete checklist, an unmet stage) masks BOTH sides
        identically and the comparison cannot resolve the authority
        question until the requirement is met — establishing it is
        what makes the probe's own measurement possible. A probe
        whose control POSTs a DIFFERENT action (the workflow-order
        family's unknown-action negative control, for example)
        measures the surface's discrimination BETWEEN actions at the
        state it observed, and advancing the chain before it runs
        would destroy the very condition it measures; such probes
        keep their L9 semantics: unprepared first execution, and
        establishment only after an explicit blocked verdict. The
        criterion is structural (which transitions the probe's own
        plan compares), never a family or fixture name."""
        planner: StatefulPlanner = self.planner
        port = self.experiment_port
        plan = port.plan_for(experiment.signature)
        if pre_execution:
            probed_actions = {
                value
                for purpose in ("candidate", "control")
                for step in plan.steps
                if step.purpose == purpose and step.method == "POST"
                for key, value in (step.params or ())
                if key == port.bindings.action_param}
            candidate_actions = {
                value
                for step in plan.steps
                if step.purpose == "candidate" and step.method == "POST"
                for key, value in (step.params or ())
                if key == port.bindings.action_param}
            control_actions = {
                value
                for step in plan.steps
                if step.purpose == "control" and step.method == "POST"
                for key, value in (step.params or ())
                if key == port.bindings.action_param}
            # same-transition differential only (see docstring): the
            # candidate and control must POST at least one shared
            # action value for establishment to serve the probe's
            # own comparison rather than replace it
            if not (candidate_actions & control_actions):
                return 0
        hyp = PlannedHypothesis(plan)
        view = RelationshipTracker(
            port.ledger, bindings=port.bindings).view()
        planner.ensure_declared(hyp, view)
        # L10 Phase 3: seed the investigation-wide assertion ledger
        # from the view (state beliefs start INFERRED, never facts)
        # and register each transition assertion as the dependent of
        # its state belief, so a contradiction demotes it for
        # re-evaluation instead of standing unexamined.
        planner.link_assertions(hyp.hypothesis_id, view)
        established = 0
        reevaluate: set[str] = set()
        for precond in planner.ledger.get(hyp.hypothesis_id):
            if precond.kind is not PreconditionKind.WORKFLOW_TRANSITION:
                continue
            need = planner.transition_need(precond, hyp, view)
            if need is None:
                continue
            required, current, _chain = need
            if current == required:
                continue
            setup = planner.setup_plan(precond, hyp, view)
            if setup is None:
                # no authorized setup derivable for this
                # precondition: it stays unmet (the planner parks
                # such hypotheses; no verdict either way) while the
                # remaining establishable preconditions are still
                # attempted (L9 §3: one unmet precondition must not
                # strand the ones that can be reached)
                continue
            # L10 Phase 3: execute the minimal hop sequence in
            # order, verifying EACH hop with its own re-read — never
            # the hop's HTTP status — and stop at the first hop the
            # re-read does not confirm (fail-closed). A failed hop
            # BLOCKS the hypothesis and never becomes a negative
            # security verdict; it also must not strand later
            # establishable preconditions.
            verify = None
            reached: str | None = None
            for hop in setup.hops:
                records = port.run_setup_steps(
                    hop.to_steps(port.bindings.idem_param, hop.path),
                    experiment.experiment_id,
                )
                post = records.get(f"{hop.action_id}-setup")
                verify = records.get(f"{hop.action_id}-verify")
                # a hop is confirmed only when its action was
                # ACCEPTED and its re-read shows the expected state:
                # HTTP success alone never proves a transition, and
                # a re-read alone cannot distinguish an accepted
                # stall hop (satisfying a published requirement
                # beyond the chain's hops) from a refused one
                accepted = (
                    post is not None
                    and post.execution == "executed"
                    and 200 <= post.status_code < 300)
                structured = (
                    verify.structured if verify is not None else None)
                observed = (
                    structured.get(port.bindings.state_field)
                    if isinstance(structured, dict) else None)
                if accepted and observed == hop.result_state:
                    reevaluate |= planner.assert_state(
                        hop.path, hop.result_state,
                        verify.record_id if verify is not None else "")
                    planner.observe_state(hop.path, hop.result_state)
                    hop_action = next(
                        (value for key, value in hop.params
                         if key == port.bindings.action_param), "")
                    if hop_action:
                        planner.note_advancement(hop.path, hop_action)
                    reached = hop.result_state
                else:
                    if observed is not None:
                        reevaluate |= planner.refute_state(
                            hop.path, observed,
                            verify.record_id
                            if verify is not None else "")
                    # outcome vocabulary (L10 Phase 3): an ACCEPTED
                    # hop whose re-read did not confirm its result
                    # state is "executed but state not reached"; a
                    # refused or unexecuted hop is "transition
                    # unavailable" — the surface said no. A refusal
                    # is never an executed-without-effect report.
                    planner.record_setup_failure(
                        hyp.hypothesis_id, precond.target,
                        BlockReason.TRANSITION_WITHOUT_EFFECT
                        if accepted else BlockReason.UNAVAILABLE)
                    reached = None
                    break
            # re-evaluation (L10 Phase 3): every OBSERVED precondition
            # resting on an invalidated state belief goes back to
            # INFERRED — it gates nothing again until a new
            # observation re-verifies it. Never a verdict either way.
            # This runs BEFORE record_observation below: the fresh
            # observation this cycle just gathered is exactly the
            # re-verification a demoted belief asks for, and it must
            # not be immediately undone by its own demotion.
            if reevaluate:
                planner.demote_assertion_dependents(reevaluate)
                reevaluate = set()
            if reached == required:
                planner.record_observation(
                    hyp.hypothesis_id, precond.target,
                    verify.record_id if verify is not None else "",
                )
                established += 1
        return established

    def _remediate(
        self, experiment: ProposedExperiment
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
        """One bounded planner remediation cycle (L9 §3/§4): the
        judgment classified this experiment's outcome as a blocked
        precondition, so derive the authorized setup transitions the
        hypothesis's preconditions need, execute them through the
        experiment port's ordinary action path (authority, scope,
        capability, idempotency: the production path, unchanged),
        verify each with the re-read — never the setup's own HTTP
        status — and re-run the experiment once so it can be judged
        on comparable state.

        Returns the re-executed composites, or None when no
        authorized setup was derivable, a setup failed to establish
        its state, or nothing needed establishing. A failed setup
        BLOCKS the hypothesis in the planner's ledger and never
        becomes a negative security verdict; the outcome then stands
        as inconclusive evidence, which the caller already treats as
        no status change."""
        if self.remediator is not None:
            # Baseline D delegates the whole cycle to its own
            # independently written strategy; the port machinery,
            # oracle and budgets it uses are the shared production
            # path, so the comparison stays fair.
            return self.remediator.remediate(
                self.experiment_port, experiment)
        planner: StatefulPlanner = self.planner
        if not planner.config.prerequisite_reasoning:
            # §6 baseline C: the same planner with prerequisite
            # reasoning ablated — candidate generation is unchanged,
            # but a blocked outcome is never remediated. The
            # outcome stands as inconclusive evidence, which the
            # caller already treats as no status change.
            return None
        established = self._establish_preconditions(experiment)
        if not established:
            # L10 Phase 4: nothing was established through the
            # published schema — where the surface publishes none,
            # the attached discovery component may spend its own
            # bounded budget on probes before the hypothesis is
            # parked. Returns the re-executed composites when an
            # accepted probe justified one re-run, else None.
            port = self.experiment_port
            view = RelationshipTracker(
                port.ledger, bindings=port.bindings).view()
            hyp = PlannedHypothesis(port.plan_for(experiment.signature))
            return self._discovery_remediation(
                planner, port, view, hyp, experiment)
        # The re-run is a distinct investigation step with its own
        # idempotency tokens (the port's remediation ordinal), while
        # plain repetitions of the experiment keep the original
        # tokens and deduplicate against them.
        port = self.experiment_port
        port.mark_remediated(experiment.experiment_id)
        return port.execute(experiment)

    # -- L10 Phase 4: bounded novel workflow discovery ----------------

    def _discovery_remediation(
            self, planner: StatefulPlanner, port: Any,
            view: RelationshipView, hyp: PlannedHypothesis,
            experiment: ProposedExperiment,
    ) -> Any:
        """Spend the attached discovery component's own explicit
        budget on probes — ONLY where the surface publishes no chain
        and no action table for the experiment's own path, so a
        complete schema yields byte-identical behavior.

        A probe is the same production request every setup hop makes
        (the authority, the G-02 wrappers, the idempotency key and
        the observation ledger) plus a verification re-read: POST,
        then a read-only re-read whose state — never the HTTP
        status — decides what was learned. An accepted probe whose
        re-read shows movement LEARNS one edge; an accepted probe
        (movement or a gate-advancing stall) justifies ONE re-run of
        the experiment so the differential judgment decides on
        comparable state; a refused probe is recorded as a refusal
        of the gate and parks without a re-run. Probes never record
        a setup failure and never become verdicts. The experiment's
        own action is never probed: its re-run is the only
        legitimate retry of it."""
        discovery = planner.discovery
        if discovery is None:
            return None
        # the experiment's own actions, from its own plan steps:
        # probed never
        own: dict[str, set[str]] = {}
        for step in hyp.plan.steps:
            if step.method != "POST":
                continue
            action = next(
                (value for key, value in step.params
                 if key == port.bindings.action_param), None)
            if action:
                own.setdefault(step.path, set()).add(action)
        silent = sorted(
            path for path, actions in own.items()
            if actions
            and not view.workflow_chains.get(path)
            and not view.workflow_action_targets.get(path))
        if not silent:
            return None
        # mine the ledger first: everything the investigation has
        # already observed is evidence before anything is probed
        discovery.mine(port.ledger, view, port.bindings)
        for path in silent:
            current = planner.current_state(path, view)
            if not current:
                continue
            for candidate in discovery.candidates(path, current, view):
                if candidate.action in own[path]:
                    continue
                probe_id = discovery.reserve(
                    path, candidate.from_state, candidate.action,
                    candidate.actor)
                if probe_id is None:
                    # already probed once, or the discovery budget
                    # is spent: the dedup and the budget hold across
                    # remediation cycles
                    continue
                accepted, observed, observation_id = self._run_probe(
                    port, path, candidate.action, candidate.actor,
                    probe_id, experiment.experiment_id)
                outcome = discovery.record_result(
                    path, candidate.action, candidate.from_state,
                    observed, observation_id, accepted,
                    candidate.actor)
                if observed:
                    # the state belief follows the probe's own
                    # re-read, never the stale view
                    planner.observe_state(path, observed)
                if outcome in ("learned", "stall"):
                    return self._rerun_after_probe(
                        planner, port, path, candidate.actor,
                        probe_id, experiment)
        return None

    def _run_probe(
            self, port: Any, path: str, action: str, actor: str,
            probe_id: str, experiment_id: str,
    ) -> tuple[bool, str | None, str]:
        """One discovery probe through the ordinary production path:
        the POST and its verification re-read, exactly as every
        setup hop. Returns (accepted, observed state, observation
        id); the acceptance is the HTTP outcome, the LEARNING is the
        re-read's state."""
        steps = (
            ProbeStep(
                purpose="discovery", label=f"{probe_id}-probe",
                method="POST", path=path, actor=actor,
                params=(
                    (port.bindings.action_param, action),
                    (port.bindings.idem_param,
                     f"{probe_id}:{path.replace('/', '-')}"),
                )),
            ProbeStep(
                purpose="discovery", label=f"{probe_id}-verify",
                method="GET", path=path, actor=actor),
        )
        records = port.run_setup_steps(steps, experiment_id)
        post = records.get(f"{probe_id}-probe")
        verify = records.get(f"{probe_id}-verify")
        accepted = (
            post is not None
            and post.execution == "executed"
            and 200 <= post.status_code < 300)
        structured = (
            verify.structured if verify is not None else None)
        observed = (
            structured.get(port.bindings.state_field)
            if isinstance(structured, dict) else None)
        observation_id = (
            verify.record_id if verify is not None else "")
        return accepted, observed, observation_id

    def _rerun_after_probe(
            self, planner: StatefulPlanner, port: Any, path: str,
            actor: str, probe_id: str, experiment: ProposedExperiment,
    ) -> Any:
        """An accepted probe moved the surface (or satisfied a
        gate): ONE re-run of the experiment, judged by the
        differential judgment. Afterwards a read-only re-read keeps
        the state belief honest — the re-run's own action may have
        moved the surface, and the belief follows the re-read, never
        the stale view. The re-read costs no discovery budget and
        writes no transition."""
        port.mark_remediated(experiment.experiment_id)
        result = port.execute(experiment)
        verify = ProbeStep(
            purpose="discovery", label=f"{probe_id}-rerun-verify",
            method="GET", path=path, actor=actor)
        records = port.run_setup_steps(
            (verify,), experiment.experiment_id)
        record = records.get(f"{probe_id}-rerun-verify")
        if record is not None and record.execution == "executed":
            structured = record.structured
            if isinstance(structured, dict):
                state = structured.get(port.bindings.state_field)
                if isinstance(state, str) and state:
                    planner.observe_state(path, state)
        return result

    def _confirm(
        self,
        state: InvestigationState,
        experiment: ProposedExperiment,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        control: dict[str, Any],
        causal: dict[str, Any],
    ) -> tuple[str, HypothesisStatus | None, EvidenceKind | None]:
        bundle = self.proof_port.build(
            experiment, baseline, candidate, control, causal
        )
        verified = self.proof_port.verify(bundle)
        state.proof_bundles_verified.append({
            "experiment_id": experiment.experiment_id,
            "signature": experiment.signature,
            "replay_valid": verified["replay_valid"] is True,
            "seal_valid": verified.get("seal_valid"),
            "verdict_match": verified.get("verdict_match"),
            "digest_match": verified.get("digest_match"),
            "runtime_provenance": dict(bundle.runtime_provenance),
        })
        if verified["replay_valid"] is True:
            evidence = EvidenceItem(
                evidence_id=f"ev-{experiment.experiment_id}",
                kind=EvidenceKind.SUPPORTING,
                source="causal_guard",
                ref=experiment.experiment_id,
                summary=(
                    f"sealed bundle replay-valid, verdict "
                    f"{causal['verdict']}"
                ),
                round=state.round,
            )
            state.add_evidence(evidence)
            return (
                OUTCOME_CONFIRMED,
                HypothesisStatus.CONFIRMED,
                EvidenceKind.SUPPORTING,
            )
        return OUTCOME_UNVERIFIED, None, None

    def _update_hypothesis(
        self,
        state: InvestigationState,
        experiment: ProposedExperiment,
        status: HypothesisStatus,
        kind: EvidenceKind,
        verdict: str,
    ) -> None:
        # Explicit binding first: an experiment names the hypothesis it
        # probes. Family matching is a fallback for unbound experiments
        # and must never leak a verdict onto a different case's
        # hypothesis than the one the evidence was gathered against.
        if experiment.hypothesis_id:
            bound = [
                h for h in state.hypotheses
                if h.hypothesis_id == experiment.hypothesis_id
                and h.status.value in ("proposed", "supported")
            ]
            if bound:
                state.set_hypothesis_status(
                    bound[0].hypothesis_id, status)
                if kind is not EvidenceKind.SUPPORTING:
                    state.add_evidence(EvidenceItem(
                        evidence_id=f"ev-{experiment.experiment_id}",
                        kind=kind,
                        source="causal_guard",
                        ref=experiment.experiment_id,
                        summary=f"guard verdict {verdict}",
                        round=state.round,
                    ))
                return
        unresolved = [
            h for h in state.unresolved_hypotheses()
            if h.family == experiment.family
        ]
        if not unresolved:
            return
        target = sorted(unresolved, key=lambda h: h.hypothesis_id)[0]
        state.set_hypothesis_status(target.hypothesis_id, status)
        if kind is not EvidenceKind.SUPPORTING:
            state.add_evidence(EvidenceItem(
                evidence_id=f"ev-{experiment.experiment_id}",
                kind=kind,
                source="causal_guard",
                ref=experiment.experiment_id,
                summary=f"guard verdict {verdict}",
                round=state.round,
            ))
