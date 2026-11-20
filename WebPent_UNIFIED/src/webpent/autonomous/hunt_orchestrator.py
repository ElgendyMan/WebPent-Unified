"""Autonomous Hunt Orchestrator — the unified self-directed hunt loop.

This is the piece that turns WebPent from a collection of strong but
disconnected components into one autonomous bug hunter. It owns the full
lifecycle:

    recon -> hypothesis -> rank -> execute (gated) -> observe -> prove -> learn

and delegates every dangerous step to the existing, already-audited
components:

* planning + task construction  -> ``smart_campaigns`` (advisory only)
* bounded execution             -> ``AutonomousController`` + injected
                                   ``ActionExecutor`` (scope/authority/budget/
                                   idempotency/cleanup all enforced there)
* proof + promotion             -> deterministic validators + sealed
                                   ``ProofBundle`` (never bypassed here)
* learning                     -> isolated security reasoning memory (advisory)

The orchestrator adds no new execution authority. It is the loop, not the
muscle. If a runtime dependency (executor, handler) is missing it fails
closed with an explicit typed stop reason rather than falling back to raw
transport.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit

from webpent.autonomous.coverage_packs import pack_hypothesis_seeds
from webpent.autonomous.hunt_budget import (
    REHYPOTHESIZE_BASE as _REHYPOTHESIZE_BASE,
)
from webpent.autonomous.hunt_budget import (
    recommend_rehypothesize_rounds,
    recommend_round_budget,
)
from webpent.autonomous.hunt_contracts import (
    HuntOutcome,
    HuntPhase,
    HuntStopReason,
    redact,
)
from webpent.autonomous.hunt_discovery import discover_from_records
from webpent.autonomous.hunt_replanning import (
    gaps_from_coverage_ledger,
    synthesize_gap_hypotheses,
)
from webpent.autonomous.hunt_state import AutonomousHuntState

TaskHandler = Callable[[Any], Any]

# Discovery merge gates (red-team R26: previously unnamed literals).
_MAX_DISCOVERY_SEEDS_PER_ROUND = 8
_SEED_KEY_MAX = 160

# Advisory seed merge gate: intel memory + coverage packs combined per
# rehypothesize round (v80 Task 3). Advisory seeds reorder only.
_MAX_ADVISORY_SEEDS_PER_ROUND = 8

# Stop reasons produced by the bounded controller that map 1:1 onto ours.
_CONTROLLER_STOP_MAP = {
    "iteration_limit_reached": HuntStopReason.ITERATION_LIMIT,
    "action_budget_exhausted": HuntStopReason.BUDGET_EXHAUSTED,
    "no_new_ready_task": HuntStopReason.NO_NEW_READY_TASK,
    "same_action_repeated": HuntStopReason.SAME_ACTION_REPEATED,
    "expected_information_gain_below_threshold": (
        HuntStopReason.INFORMATION_GAIN_BELOW_THRESHOLD
    ),
}


class AutonomousHuntOrchestrator:
    """Run one bounded, self-directed hunt from recon to report.

    Parameters
    ----------
    action_executor:
        The existing ``ActionExecutor``. Required for any execution; a hunt
        that reaches the execute phase without one stops with
        ``RUNTIME_DEPENDENCIES_MISSING`` rather than touching the network.
    handler:
        The task handler (typically ``build_smart_campaign_handler``). Same
        requirement as the executor.
    controller:
        Optional pre-built ``AutonomousController``. When omitted one is
        constructed with the supplied executor and iteration bound.
    memory:
        Optional learning-memory adapter. Advisory only; it may reorder
        hypotheses but can never promote a finding.
    max_iterations:
        Hard bound on loop iterations. Clamped to [1, 10].
    """

    def __init__(
        self,
        *,
        action_executor: Any | None = None,
        handler: TaskHandler | None = None,
        controller: Any | None = None,
        memory: Any | None = None,
        max_iterations: int = 5,
        minimum_information_gain: float = 0.05,
        event_sink: Callable[[dict[str, Any]], None] | None = None,
        intel: Any | None = None,
        deadends: Any | None = None,
        auth_recheck: Callable[[], str | None] | None = None,
    ) -> None:
        self.action_executor = action_executor
        self.handler = handler
        self.memory = memory
        self.event_sink = event_sink
        self.intel = intel
        self.deadends = deadends
        self.auth_recheck = auth_recheck
        # Consecutive quiet rehypothesize rounds (v81 budget allocator).
        self._quiet_rounds = 0
        self.max_iterations = max(1, min(10, int(max_iterations)))
        self.minimum_information_gain = float(minimum_information_gain)
        if controller is not None:
            self.controller = controller
        else:
            from webpent.shared.autonomous_controller import AutonomousController

            self.controller = AutonomousController(
                action_executor=action_executor,
                max_iterations=self.max_iterations,
            )

    # ------------------------------------------------------------------ #
    # Phase implementations
    # ------------------------------------------------------------------ #

    def _phase_recon(self, state: AutonomousHuntState) -> None:
        """Seed the knowledge model from whatever recon already produced.

        Recon itself is performed by the existing recon nodes before the
        orchestrator is invoked; here we only normalize what is present and
        record the phase. An empty knowledge model is not an error — the
        hypothesis phase will simply produce nothing and the loop stops with
        ``NO_NEW_READY_TASK``.
        """
        knowledge = state.target_knowledge or {}
        state.record_phase(
            HuntPhase.RECON,
            status="ok" if knowledge else "empty",
            reason="" if knowledge else "no_target_knowledge_supplied",
            detail={"entities": len(knowledge.get("entities", []) or [])},
        )

    def _phase_hypothesis(self, state: AutonomousHuntState) -> None:
        """Generate advisory hypotheses via the real generator contract.

        The real ``HypothesisGenerator.generate`` takes a validated
        ``TargetKnowledgeV2`` plus an ``AttackGraph``; the knowledge bridge
        (``hunt_knowledge.hypothesis_inputs``) adapts the state's knowledge
        into that pair. The generator is advisory: it produces ranked
        candidates, never requests and never promotions. If it is
        unavailable, or the knowledge cannot be faithfully represented, the
        phase is recorded as blocked and the loop stops cleanly.
        """
        try:
            from webpent.autonomous.hunt_knowledge import hypothesis_inputs
            from webpent.research.hypothesis_generator import HypothesisGenerator
        except Exception as exc:  # pragma: no cover - import guard
            state.record_phase(
                HuntPhase.HYPOTHESIS,
                status="blocked",
                reason=f"hypothesis_generator_unavailable:{type(exc).__name__}",
            )
            return
        prepared = hypothesis_inputs(
            state.target_knowledge,
            engagement_id=state.engagement_id,
            target_url=state.target_url,
        )
        if prepared is None:
            state.record_phase(
                HuntPhase.HYPOTHESIS,
                status="blocked" if state.target_knowledge else "empty",
                reason="no_target_knowledge_supplied"
                if not state.target_knowledge
                else "target_knowledge_not_coercible",
            )
            return
        knowledge, graph = prepared
        try:
            generator = HypothesisGenerator()
            generated = generator.generate(knowledge, graph)
        except Exception as exc:
            state.record_phase(
                HuntPhase.HYPOTHESIS,
                status="blocked",
                reason=f"hypothesis_generation_failed:{type(exc).__name__}",
            )
            return
        hypotheses = _coerce_hypotheses(generated)
        hypotheses = _resolve_hypothesis_targets(hypotheses, state.target_url)
        state.hypotheses = hypotheses
        state.record_phase(
            HuntPhase.HYPOTHESIS,
            status="ok" if hypotheses else "empty",
            detail={"count": len(hypotheses)},
        )

    def _phase_rank(self, state: AutonomousHuntState) -> None:
        """Rank hypotheses, applying advisory learning hints if present.

        The learning hint can only reorder; it is capped so a stale or
        adversarial memory cannot dominate the deterministic ranking.
        """
        ranked = list(state.hypotheses)
        if state.learning_hints:
            ranked = _apply_learning_hints(ranked, state.learning_hints)
        state.hypotheses = ranked
        state.record_phase(
            HuntPhase.RANK,
            status="ok" if ranked else "empty",
            detail={"count": len(ranked), "hint_count": len(state.learning_hints)},
        )

    def _phase_execute(self, state: AutonomousHuntState) -> dict[str, Any]:
        """Run one bounded controller iteration.

        All scope/authority/budget/idempotency/cleanup enforcement happens
        inside the controller and executor. The orchestrator only supplies
        state and reads back the additive update.
        """
        if self.action_executor is None or self.handler is None:
            state.record_phase(
                HuntPhase.EXECUTE,
                status="blocked",
                reason=HuntStopReason.RUNTIME_DEPENDENCIES_MISSING.value,
            )
            return {"__blocked__": HuntStopReason.RUNTIME_DEPENDENCIES_MISSING}
        update = self.controller.run(
            state.as_controller_state(),
            handler=self.handler,
            iterations=1,
        )
        outcome_count = len(_outcomes_of(update))
        state.record_phase(
            HuntPhase.EXECUTE,
            status="ok",
            detail={
                "outcomes": outcome_count,
                "stop_reason": _controller_stop_reason(update),
            },
        )
        return update

    def _phase_observe(self, state: AutonomousHuntState, update: Mapping[str, Any]) -> None:
        """Fold controller output back into the hunt state."""
        outcomes = _outcomes_of(update)
        state.outcomes.extend([dict(item) for item in outcomes if isinstance(item, Mapping)])
        state.positive_evidence_ledger = list(
            update.get("positive_evidence_ledger", state.positive_evidence_ledger) or []
        )
        state.negative_evidence_ledger = list(
            update.get("negative_evidence_ledger", state.negative_evidence_ledger) or []
        )
        if "knowledge_gaps" in update:
            state.knowledge_gaps = list(update.get("knowledge_gaps") or [])
        else:
            # The real AutonomousController never emits ``knowledge_gaps``;
            # its per-class coverage lives in ``coverage_ledger``. Derive the
            # gap records from there (critique C1a), bounded and ordered.
            derived = gaps_from_coverage_ledger(update.get("coverage_ledger"))
            if derived:
                state.knowledge_gaps = derived
        state.findings = list(update.get("findings", state.findings) or [])
        for signature in update.get("completed_action_signatures", []) or []:
            text = str(signature).strip()[:160]
            if text and text not in state.seen_action_signatures:
                state.seen_action_signatures.append(text)
        state.record_phase(
            HuntPhase.OBSERVE,
            status="ok",
            detail={
                "positive": len(state.positive_evidence_ledger),
                "negative": len(state.negative_evidence_ledger),
            },
        )

    def _phase_prove(self, state: AutonomousHuntState, update: Mapping[str, Any]) -> None:
        """Collect sealed proof bundles produced by the execution path.

        The orchestrator never builds or seals a bundle itself and never
        promotes a finding. It only records bundles the existing path
        already produced, and refuses any bundle that does not verify.
        """
        bundles = list(update.get("proof_bundles", []) or [])
        for record in _outcomes_of(update):
            if not isinstance(record, Mapping):
                continue
            sealed = record.get("proof_bundle_sealed")
            candidate = record.get("proof_bundle")
            if sealed and candidate is not None:
                bundles.append(candidate)
        verified: list[dict[str, Any]] = []
        refused = 0
        for bundle in bundles:
            if not _bundle_verifies(bundle):
                refused += 1
                continue
            # A promotion-grade bundle must carry its negative control.
            if not _bundle_field(bundle, "negative_control_digest"):
                refused += 1
                continue
            # A bundle produced by another engagement never promotes here.
            if not _belongs_to_engagement(bundle, state.engagement_id):
                refused += 1
                continue
            verified.append(bundle)
        state.proof_bundles.extend(verified)
        linked = _link_findings(state, verified)
        state.record_phase(
            HuntPhase.PROVE,
            status="ok" if verified else "empty",
            detail={
                "verified": len(verified),
                "offered": len(bundles),
                "refused": refused,
                "findings_linked": linked,
            },
        )

    def _phase_learn(self, state: AutonomousHuntState) -> None:
        """Update advisory learning hints from this iteration's outcomes.

        Hints are capped at 0.75 so they can reorder but never override the
        deterministic ranking. The memory layer is advisory: it has no
        promotion authority.
        """
        if self.memory is None:
            state.record_phase(HuntPhase.LEARN, status="skipped", reason="no_memory_adapter")
            return
        try:
            hints = self.memory.update(state)
        except Exception as exc:
            state.record_phase(
                HuntPhase.LEARN,
                status="blocked",
                reason=f"memory_update_failed:{type(exc).__name__}",
            )
            return
        if isinstance(hints, Mapping):
            state.learning_hints = {
                str(key)[:120]: max(0.0, min(0.75, float(value)))
                for key, value in hints.items()
            }
        state.record_phase(
            HuntPhase.LEARN,
            status="ok",
            detail={"hints": len(state.learning_hints)},
        )
        if self.intel is not None:
            try:
                self.intel.update_from_state(state)
                self.intel.save()
            except Exception as exc:  # intel must never break a hunt
                state.record_phase(
                    HuntPhase.LEARN,
                    status="skipped",
                    reason="intel_update_failed",
                    detail={"error": redact(str(exc))[:200]},
                )
        if self.deadends is not None:
            try:
                self.deadends.update_from_state(state)
                self.deadends.save()
            except Exception as exc:  # the dead-end store must never break a hunt
                state.record_phase(
                    HuntPhase.LEARN,
                    status="skipped",
                    reason="deadend_update_failed",
                    detail={"error": redact(str(exc))[:200]},
                )

    def _phase_rehypothesize(self, state: AutonomousHuntState) -> int:
        """Seed the next iteration with hypotheses built from observation.

        Two advisory seed sources, merged through the same bounded path:
        discovery candidates (suggestion 3) and the knowledge gaps the
        controller reported. The phase can reorder candidates but can
        never mint a request or promote a finding. Returns the number of
        new seeds; zero means the hunt has nothing left to chase.
        """
        added = self._merge_discovery_hypotheses(state)
        added += self._merge_gap_hypotheses(state)
        added += self._merge_advisory_seeds(state)
        if added and state.learning_hints:
            state.hypotheses = _apply_learning_hints(
                state.hypotheses, state.learning_hints
            )
        return added

    def _merge_advisory_seeds(self, state: AutonomousHuntState) -> int:
        """Merge intel-memory and coverage-pack seeds (advisory, bounded).

        Intel seeds come first (proof-verified history on this exact
        target), pack seeds second (classes with no validator coverage).
        Both are capped and deduped against hypotheses already held; the
        phase still cannot mint a request or promote a finding.
        """
        advisory: list[dict[str, Any]] = []
        demoted = 0
        if self.intel is not None:
            try:
                advisory.extend(self.intel.hypothesis_seeds(state.target_url))
            except Exception as exc:  # intel must never break a hunt
                state.record_phase(
                    HuntPhase.HYPOTHESIS,
                    status="skipped",
                    reason="intel_seeds_unavailable",
                    detail={"error": redact(str(exc))[:200]},
                )
        advisory.extend(pack_hypothesis_seeds())
        advisory = advisory[:_MAX_ADVISORY_SEEDS_PER_ROUND]

        known: set[str] = set()
        for item in state.hypotheses:
            key = str(
                item.get("gap_id") or item.get("hypothesis_id") or item.get("id") or ""
            )[:_SEED_KEY_MAX]
            if key:
                known.add(key)
        fresh: list[dict[str, Any]] = []
        for seed in advisory:
            if not isinstance(seed, dict):
                continue
            hypothesis_id = f"advisory:{seed.get('source', 'x')}:{seed.get('vuln_class', 'x')}"[
                :_SEED_KEY_MAX
            ]
            if hypothesis_id in known:
                continue
            known.add(hypothesis_id)
            item = dict(seed)
            item["hypothesis_id"] = hypothesis_id
            item.setdefault("target_url", str(state.target_url or "")[:500])
            item["priority"] = max(0.0, min(0.75, float(seed.get("priority") or 0.5)))
            # Dead-end memory (v81) demotes advisory pack seeds only, and
            # only by re-ranking: intel seeds carry proof history (a class
            # verified on this target outranks negative memory), and
            # discovery/gap seeds carry fresh evidence that negative memory
            # must never suppress. A demoted seed stays in the list.
            if self.deadends is not None and str(seed.get("source")) != "intel":
                try:
                    penalty = self.deadends.penalty_for(
                        state.target_url,
                        str(seed.get("vuln_class", "")),
                        str(item.get("target_url") or ""),
                    )
                except Exception:  # the store must never break the merge
                    penalty = 0.0
                if penalty > 0:
                    item["priority"] = max(0.05, item["priority"] - penalty)
                    item["rationale"] = (
                        f"{str(item.get('rationale') or '')} "
                        "[dead-end memory: advisory demotion]"
                    )[:240]
                    demoted += 1
            fresh.append(item)
        if not fresh:
            return 0
        state.hypotheses = list(state.hypotheses) + fresh
        state.record_phase(
            HuntPhase.HYPOTHESIS,
            status="ok",
            detail={
                "advisory_seeds": len(fresh),
                "dead_end_demoted": demoted,
                "sources": sorted({str(item.get("source")) for item in fresh}),
            },
        )
        return len(fresh)

    def _merge_discovery_hypotheses(self, state: AutonomousHuntState) -> int:
        """Merge discovery anomaly seeds, deduped against everything held.

        Discovery seeds carry stable ``gap_id`` signatures, so a seed the
        loop has already merged (or already executed against) is skipped:
        repeated quiet rounds add nothing and convergence still holds
        (critique B3). Targets are projected onto the hunt's own scoped
        target; the planner's same-origin check still applies downstream.
        """
        discovery = state.discovery or {}
        seeds = [s for s in discovery.get("hypotheses", []) or [] if isinstance(s, dict)]
        if not seeds:
            return 0
        known: set[str] = set()
        for item in state.hypotheses:
            key = str(
                item.get("gap_id") or item.get("hypothesis_id") or item.get("id") or ""
            )[:_SEED_KEY_MAX]
            if key:
                known.add(key)
        fresh: list[dict[str, Any]] = []
        for seed in seeds:
            gap_id = str(seed.get("gap_id") or "")[:_SEED_KEY_MAX]
            if not gap_id or gap_id in known:
                continue
            known.add(gap_id)
            item = dict(seed)
            item.setdefault("hypothesis_id", f"gap:{gap_id}")
            probe = str((seed.get("anomaly") or {}).get("probe") or "").strip()
            if _origin_of(probe) and _origin_of(probe) == _origin_of(
                str(state.target_url or "")
            ):
                # The divergent endpoint is the actionable payload: aim
                # the seed at it, not at the hunt's generic target.
                item["target_url"] = probe[:500]
            elif not _origin_of(str(item.get("target_url") or "")):
                item["target_url"] = str(state.target_url)[:500]
            fresh.append(item)
            if len(fresh) >= _MAX_DISCOVERY_SEEDS_PER_ROUND:
                break
        if not fresh:
            return 0
        state.hypotheses = list(state.hypotheses) + fresh
        state.record_phase(
            HuntPhase.HYPOTHESIS,
            status="ok",
            detail={
                "source": "discovery",
                "added": len(fresh),
                "total": len(state.hypotheses),
            },
        )
        return len(fresh)

    def _merge_gap_hypotheses(self, state: AutonomousHuntState) -> int:
        """Seed hypotheses from observed knowledge gaps (existing path)."""
        if not state.knowledge_gaps:
            # Nothing was observed as missing: stay silent. Recording an
            # empty re-hypothesis attempt on every quiet iteration would
            # flood the phase trace with noise.
            return 0
        try:
            fresh = synthesize_gap_hypotheses(
                state.knowledge_gaps,
                engagement_id=state.engagement_id,
                target_url=state.target_url,
                seen_hypotheses=state.hypotheses,
            )
        except Exception as exc:  # pragma: no cover - defensive guard
            state.record_phase(
                HuntPhase.HYPOTHESIS,
                status="blocked",
                reason=f"gap_rehypothesis_failed:{type(exc).__name__}",
                detail={"source": "knowledge_gaps"},
            )
            return 0
        if not fresh:
            # Record the dedup-empty outcome once, not on every quiet
            # iteration: after the first, it is steady state, not news
            # (critique C6). The trace stays bounded regardless, but a
            # ten-iteration hunt should not carry nine identical records.
            already_recorded = any(
                record.status == "empty" and record.reason == "no_new_gap_hypotheses"
                for record in state.phase_trace
            )
            if not already_recorded:
                state.record_phase(
                    HuntPhase.HYPOTHESIS,
                    status="empty",
                    reason="no_new_gap_hypotheses",
                    detail={"source": "knowledge_gaps", "added": 0},
                )
            return 0
        state.hypotheses = list(state.hypotheses) + fresh
        state.record_phase(
            HuntPhase.HYPOTHESIS,
            status="ok",
            detail={
                "source": "knowledge_gaps",
                "added": len(fresh),
                "total": len(state.hypotheses),
            },
        )
        return len(fresh)

    def _phase_discover(self, state: AutonomousHuntState) -> None:
        """Mine this round's outcome records for advisory candidates.

        Pure, deterministic, evidence-bounded: anomaly hypotheses, route
        variants, endpoint candidates, sibling parameters and hybrid
        scenarios. Nothing here executes, schedules, or confirms; every
        candidate carries an origin and a stable signature, and minted
        signatures are remembered so later rounds never re-probe the
        same candidate (critique B6). A round that only re-mints known
        candidates produces no new evidence and the loop still converges
        (critique B3).
        """
        try:
            prior = list((state.discovery or {}).get("anomalies", []) or [])
            result = discover_from_records(
                state.outcomes,
                seen_signatures=set(state.discovery_signatures),
                prior_anomalies=prior,
            )
        except Exception as exc:  # pragma: no cover - defensive guard
            state.record_phase(
                HuntPhase.OBSERVE,
                status="blocked",
                reason=f"discovery_failed:{type(exc).__name__}",
            )
            return
        state.discovery = result
        for group_key in ("routes", "endpoints", "params"):
            for candidate in result.get(group_key, []) or []:
                if not isinstance(candidate, dict):
                    continue
                signature = str(candidate.get("signature") or "")[:_SEED_KEY_MAX]
                if signature and signature not in state.discovery_signatures:
                    state.discovery_signatures.append(signature)
        # Hybrid scenarios dedup across rounds too: a capability pair
        # that stays present must not re-mint its scenario every round
        # (red-team R8b). The engine dedups on the bare signature, so the
        # "discovery:" prefix of scenario_id is stripped here.
        for scenario in result.get("hybrids", []) or []:
            if not isinstance(scenario, dict):
                continue
            signature = str(scenario.get("scenario_id") or "").removeprefix(
                "discovery:"
            )[:_SEED_KEY_MAX]
            if signature and signature not in state.discovery_signatures:
                state.discovery_signatures.append(signature)
        produced_any = any(
            result.get(key) for key in ("hypotheses", "routes", "endpoints", "params", "hybrids")
        )
        state.record_phase(
            HuntPhase.OBSERVE,
            status="ok" if produced_any else "empty",
            reason=(
                "discovery_candidates"
                if produced_any
                else "no_new_discovery_candidates"
            ),
            detail={
                "anomalies": len(result.get("anomalies", []) or []),
                "hypotheses": len(result.get("hypotheses", []) or []),
                "routes": len(result.get("routes", []) or []),
                "endpoints": len(result.get("endpoints", []) or []),
                "params": len(result.get("params", []) or []),
                "hybrids": len(result.get("hybrids", []) or []),
            },
        )

    def _phase_report(self, state: AutonomousHuntState) -> None:
        detail: dict[str, Any] = {
            "outcome": state.outcome.value if state.outcome else "unknown"
        }
        if self.deadends is not None:
            with contextlib.suppress(Exception):  # advisory only; never break the report
                detail["round_budget_recommendation"] = recommend_round_budget(
                    self.max_iterations,
                    self.deadends.dead_end_ratio(state.target_url),
                )
        state.record_phase(HuntPhase.REPORT, status="ok", detail=detail)

    # ------------------------------------------------------------------ #
    # Main loop
    # ------------------------------------------------------------------ #

    def run(self, state: AutonomousHuntState) -> AutonomousHuntState:
        """Run the hunt to a typed terminal state."""
        state.max_iterations = self.max_iterations
        self._phase_recon(state)
        self._emit(state)
        self._phase_hypothesis(state)
        self._emit(state)
        self._phase_rank(state)
        self._emit(state)

        for iteration in range(self.max_iterations):
            state.iteration = iteration
            if self.auth_recheck is not None:
                refusal = self.auth_recheck()
                if refusal:
                    state.stop_reason = HuntStopReason.AUTHORIZATION_REVOKED
                    state.outcome = HuntOutcome.BLOCKED
                    state.record_phase(
                        HuntPhase.OBSERVE,
                        status="blocked",
                        reason="authorization_revoked_mid_hunt",
                        detail={"refusal": redact(refusal)},
                    )
                    break

            fingerprint_before = state.evidence_fingerprint()

            update = self._phase_execute(state)
            self._emit(state)
            if "__blocked__" in update:
                state.stop_reason = update["__blocked__"]
                state.outcome = HuntOutcome.BLOCKED
                break

            self._phase_observe(state, update)
            self._phase_prove(state, update)
            self._phase_learn(state)
            self._phase_discover(state)
            self._emit(state)

            controller_reason = _controller_stop_reason(update)
            if controller_reason and controller_reason in _CONTROLLER_STOP_MAP:
                mapped = _CONTROLLER_STOP_MAP[controller_reason]
                # A controller-level "iteration limit" is not terminal for the
                # hunt while our own bound still has room; treat only the
                # genuine convergence stops as terminal.
                if mapped is not HuntStopReason.ITERATION_LIMIT:
                    state.stop_reason = mapped
                    state.outcome = _outcome_for(mapped, state)
                    break

            evidence_gained = state.has_new_evidence_since(fingerprint_before)
            if evidence_gained:
                # P1-01 (0.33.0): a PRODUCTIVE round resets the consecutive
                # quiet-round streak. The old code only reset the counter on
                # the convergence break (a dead write) and on the rehypo-
                # path's final else — so one productive round sandwiched
                # between quiet ones still accumulated and stopped the hunt
                # early with NO_NEW_EVIDENCE.
                self._quiet_rounds = 0
            if not evidence_gained:
                # Before declaring convergence, give the observed knowledge
                # gaps one chance to become new hypothesis seeds. A hunt
                # that learns nothing new and has no gaps to chase is
                # genuinely done; one with gaps is not.
                if self._phase_rehypothesize(state) > 0:
                    # v81 budget allocator: on a target whose probed surface
                    # is mostly recorded dead ends, consecutive quiet rounds
                    # stop earlier. Advisory only: the cap can reduce rounds
                    # (floor 1) and never raises any bound; without a
                    # dead-end store the pre-v81 behavior is unchanged.
                    self._quiet_rounds += 1
                    cap = _REHYPOTHESIZE_BASE
                    if self.deadends is not None:
                        try:
                            cap = recommend_rehypothesize_rounds(
                                self.deadends.dead_end_ratio(state.target_url)
                            )
                        except Exception:  # the allocator must never break a hunt
                            cap = _REHYPOTHESIZE_BASE
                        if self._quiet_rounds >= cap:
                            state.stop_reason = HuntStopReason.NO_NEW_EVIDENCE
                            state.outcome = _outcome_for(state.stop_reason, state)
                            state.record_phase(
                                HuntPhase.OBSERVE,
                                status="empty",
                                reason="budget_capped_rehypothesis",
                                detail={
                                    "quiet_rounds": self._quiet_rounds,
                                    "recommended_rounds": cap,
                                },
                            )
                            break
                    continue
                self._quiet_rounds = 0
                state.stop_reason = HuntStopReason.NO_NEW_EVIDENCE
                state.outcome = _outcome_for(state.stop_reason, state)
                break
        else:
            state.stop_reason = HuntStopReason.ITERATION_LIMIT
            state.outcome = _outcome_for(state.stop_reason, state)

        if state.stop_reason is None:
            state.stop_reason = HuntStopReason.COMPLETED
            state.outcome = _outcome_for(state.stop_reason, state)

        self._phase_report(state)
        self._emit(state)
        return state

    def _emit(self, state: AutonomousHuntState) -> None:
        """Stream the latest phase record to the event sink, if attached.

        The sink is observability only: it can never change hunt state, and
        a raising sink is swallowed so it can never turn into a hunt failure.
        """
        sink = getattr(self, "event_sink", None)
        if sink is None:
            return
        try:
            records = state.phase_trace
        except AttributeError:
            return
        if not records:
            return
        record = records[-1]
        phase = getattr(record, "phase", None)
        status = getattr(record, "status", None)
        reason = getattr(record, "reason", None)
        if isinstance(record, dict):
            phase = record.get("phase")
            status = record.get("status")
            reason = record.get("reason")
        try:
            # Emit the enum's value ("hypothesis") rather than its repr
            # ("HuntPhase.HYPOTHESIS") so event consumers can match phases.
            emitted_phase = phase.value if hasattr(phase, "value") else str(phase)
            sink({"phase": str(emitted_phase), "status": str(status), "reason": str(reason or "")})
        except Exception:
            return


def _outcomes_of(update: Mapping[str, Any]) -> list[Any]:
    """Read executed-task records from the controller's additive update.

    The real controller reports under ``campaign_task_outcomes``; the
    ``task_outcomes`` key is kept as a compatibility fallback so scripted
    controllers in tests keep working unchanged.
    """
    raw = update.get("campaign_task_outcomes")
    if not raw:
        raw = update.get("task_outcomes")
    return list(raw) if raw else []


def _controller_stop_reason(update: Mapping[str, Any]) -> str:
    """Resolve the controller's typed stop reason from its update.

    The real controller reports through ``stop_decision.reason`` (a
    ``StopDecision.as_dict()`` mapping). Top-level ``stop_reason`` and
    ``smart_replanning.stop_reason`` are accepted as fallbacks so
    scripted controllers keep working unchanged.
    """
    decision = update.get("stop_decision")
    if isinstance(decision, Mapping):
        reason = str(decision.get("reason") or "").strip()
        if reason:
            return reason
    reason = str(update.get("stop_reason") or "").strip()
    if reason:
        return reason
    replanning = update.get("smart_replanning")
    if isinstance(replanning, Mapping):
        return str(replanning.get("stop_reason") or "").strip()
    return ""


def _bundle_field(bundle: Any, name: str) -> Any:
    if isinstance(bundle, Mapping):
        return bundle.get(name)
    return getattr(bundle, name, None)


def _has_negative_control(bundle: Any) -> bool:
    """A promotion-grade bundle must bind its negative control."""
    return bool(_bundle_field(bundle, "negative_control_digest"))


def _belongs_to_engagement(bundle: Any, engagement_id: str) -> bool:
    """Refuse bundles produced under a different engagement id."""
    value = _bundle_field(bundle, "engagement_id")
    return bool(value) and str(value) == str(engagement_id)


def _link_findings(
    state: AutonomousHuntState, verified: list[dict[str, Any] | Any]
) -> int:
    """Create report-linked findings from verified bundles (deduped by seal)."""
    seen = {str(item.get("proof_digest")) for item in state.findings}
    linked = 0
    for bundle in verified:
        seal = _bundle_field(bundle, "seal_digest")
        if seal is None or str(seal) in seen:
            continue
        seen.add(str(seal))
        state.findings.append(
            {
                "finding_id": str(_bundle_field(bundle, "finding_id") or ""),
                "engagement_id": str(_bundle_field(bundle, "engagement_id") or ""),
                "proof_digest": str(seal),
                "source": "proof_bundle",
            }
        )
        linked += 1
    return linked


def _outcome_for(reason: HuntStopReason, state: AutonomousHuntState) -> HuntOutcome:
    """Map a stop reason to a terminal outcome.

    A hunt with at least one verified proof bundle is CONFIRMED regardless of
    why the loop stopped; a hunt that hit a governance bound without proof is
    BLOCKED; anything else is INCONCLUSIVE.
    """
    if state.proof_bundles:
        return HuntOutcome.CONFIRMED
    if reason in {
        HuntStopReason.SCOPE_DENIED,
        HuntStopReason.AUTHORITY_DENIED,
        HuntStopReason.CAPABILITY_BLOCKED,
        HuntStopReason.RUNTIME_DEPENDENCIES_MISSING,
        HuntStopReason.OPERATOR_HALT,
        HuntStopReason.ERROR,
    }:
        return HuntOutcome.BLOCKED
    return HuntOutcome.INCONCLUSIVE


def _origin_of(value: str) -> str:
    """Return scheme://netloc for a full URL, or "" when not a URL."""
    parts = urlsplit(str(value))
    if not parts.scheme or not parts.hostname:
        return ""
    return f"{parts.scheme.lower()}://{parts.netloc}"


def _resolve_hypothesis_targets(
    hypotheses: list[dict[str, Any]], target_url: str
) -> list[dict[str, Any]]:
    """Resolve research hypotheses onto the hunt's own target origin.

    The research generator labels assets with endpoint canonical keys
    ("GET /login"). The planner only accepts same-origin URLs, so each
    unresolvable target is joined onto the origin the endpoint was
    actually observed on. No host is invented: a hypothesis that cannot
    be resolved against the target origin is kept unchanged, and the
    planner's own same-origin check still applies downstream.
    """
    origin = _origin_of(target_url)
    if not origin:
        return hypotheses
    resolved: list[dict[str, Any]] = []
    for item in hypotheses:
        url = str(item.get("target_url") or "").strip()
        if _origin_of(url):
            resolved.append(item)
            continue
        candidate = str(item.get("affected_asset") or url).strip()
        method = ""
        path = ""
        if candidate.startswith("/"):
            path = candidate.split("?", 1)[0]
        else:
            head, _, tail = candidate.partition(" ")
            if head.isupper() and tail.startswith("/"):
                method = head
                path = tail.split("?", 1)[0]
        if not path or "://" in path or not path.startswith("/"):
            resolved.append(item)
            continue
        updated = dict(item)
        updated["target_url"] = f"{origin}{path[:400]}"[:500]
        if method:
            updated["request_method"] = method.upper()[:12]
        resolved.append(updated)
    return resolved


def _coerce_hypotheses(generated: Any) -> list[dict[str, Any]]:
    """Normalize whatever the generator returns into a list of dicts."""
    if generated is None:
        return []
    items = generated if isinstance(generated, (list, tuple)) else [generated]
    result: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, Mapping):
            result.append(dict(item))
        elif hasattr(item, "as_dict"):
            try:
                result.append(dict(item.as_dict()))
            except Exception:
                continue
        elif hasattr(item, "__dict__"):
            result.append({k: v for k, v in vars(item).items() if not k.startswith("_")})
    return result


def _apply_learning_hints(
    hypotheses: list[dict[str, Any]], hints: Mapping[str, float]
) -> list[dict[str, Any]]:
    """Reorder hypotheses by advisory hints, capped and deterministic.

    The hint is added to any existing ``priority``/``score`` field and the
    list is re-sorted stably, so equal scores keep their original order.

    The cap is applied here as well as in ``_phase_learn``: a caller that
    builds hints by hand (or a memory adapter that bypasses the phase) must
    not be able to hand this function an unbounded value and let a single
    hint dominate the deterministic ranking.
    """
    capped = {
        str(key)[:120]: max(0.0, min(0.75, float(value))) for key, value in hints.items()
    }

    def _score(item: dict[str, Any]) -> float:
        base = 0.0
        for key in ("priority", "score", "expected_information_gain"):
            value = item.get(key)
            if isinstance(value, (int, float)):
                base = float(value)
                break
        key = str(item.get("pattern_id") or item.get("id") or item.get("hypothesis_id") or "")
        return base + float(capped.get(key, 0.0))

    return sorted(hypotheses, key=_score, reverse=True)


def _bundle_verifies(bundle: Any) -> bool:
    """Refuse any proof bundle that does not verify its seal."""
    if bundle is None:
        return False
    verify = getattr(bundle, "verify_seal", None)
    if callable(verify):
        try:
            return bool(verify())
        except Exception:
            return False
    if isinstance(bundle, Mapping):
        return bool(bundle.get("sealed")) and bool(bundle.get("seal_digest"))
    return False


def run_autonomous_hunt(
    *,
    engagement_id: str,
    target_url: str,
    target_knowledge: Mapping[str, Any] | None = None,
    action_executor: Any | None = None,
    handler: TaskHandler | None = None,
    memory: Any | None = None,
    max_iterations: int = 5,
) -> AutonomousHuntState:
    """Convenience entry point: build state, run the orchestrator, return it."""
    state = AutonomousHuntState(
        engagement_id=engagement_id,
        target_url=target_url,
        target_knowledge=dict(target_knowledge or {}),
        max_iterations=max_iterations,
    )
    orchestrator = AutonomousHuntOrchestrator(
        action_executor=action_executor,
        handler=handler,
        memory=memory,
        max_iterations=max_iterations,
    )
    return orchestrator.run(state)


__all__ = ["AutonomousHuntOrchestrator", "run_autonomous_hunt"]
