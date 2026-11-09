# src/webpent/agents/strategist/agent.py
"""webpent.agents.strategist.agent

V7 Cognitive Upgrade — Section 4: The Strategist as a recurring
decision function.

Per the plan (Section 4):

    "Introduce the Strategist as a new, recurring decision function —
    not a single fixed position in the graph, but a piece of logic
    invoked at specific, well-defined checkpoints: after
    ``hypothesis_analyzer``, after each of the four deep-probing
    agents, after ``devils_advocate``/``exploit_chainer``, and —
    centrally — as the decision logic behind the new Rabbit Hole
    loop-back conditional edge."

    "At each checkpoint, the Strategist consults: the Mental Model
    (what do we know), the Goal Tree (what are we still trying to do),
    the Hypothesis pool with current confidence scores, Dynamic
    Prioritization's ranking, and the Risk Manager's remaining
    budget/caps. It picks exactly one of a small, closed set of
    actions: continue the existing linear pipeline as today; promote
    a specific hypothesis into an actionable investigation; enter a
    specific Rabbit Hole branch; de-prioritize or abandon a branch
    (informed by Self-Critique); or escalate to a human via HITL for
    an ambiguous or scope-adjacent case."

    "The Strategist's authority is bounded exactly the same way
    ``exploit_chainer``'s is today. It can *rank and recommend*; it
    cannot authorize execution, cannot expand scope, and cannot
    override the Risk Manager's caps."

This module implements the Strategist as a graph node that runs at
the primary checkpoint: after all discovery nodes (hypothesis +
deep-probers) have completed, before ``payload_generator``. At this
checkpoint, the Strategist:

  1. Ranks the open hypotheses via Dynamic Prioritization
     (:func:`webpent.shared.prioritization.rank_open_hypotheses`).
  2. For each hypothesis above the promotion threshold, promotes it
     to a :class:`Finding` via
     :func:`webpent.shared.prioritization.promote_hypothesis_to_finding`.
  3. Marks the promoted hypothesis's status as ``promoted``.
  4. Writes a Decision Log entry for each promotion decision.

The promoted Findings enter ``state["findings"]`` with
``confidence_level="Pending"`` — exactly the state
``payload_generator`` expects. The existing pipeline (payload_generator
-> execution_sandbox [HITL-gated] -> validator -> devils_advocate)
processes them with NO new execution path.

Safety properties inherited:

  * **HITL** — promoted Findings go through ``execution_sandbox``,
    which is still HITL-gated on every pass.
  * **Scope enforcement** — the Findings carry the hypothesis's
    ``target_url``, which was already scope-checked by
    ``scope_enforcer`` (or will be re-checked by the Rabbit Hole
    node's scope re-check for Rabbit Hole-spawned hypotheses).
  * **Deterministic gates** — the promotion decision is 100%
    deterministic arithmetic (score >= threshold). The LLM is NEVER
    asked to pick the action.
  * **Fail-closed** — any exception in the Strategist is non-fatal;
    the node returns an empty state update and the linear pipeline
    continues (no hypotheses promoted, no crash).
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any

from langchain_core.messages import AIMessage

from webpent.models.hypothesis import Hypothesis, HypothesisOrigin, HypothesisStatus
from webpent.state.reducers import model_get
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)


def _is_re_entry_pass(state: PentestState) -> bool:
    """Detect whether this Strategist invocation is a re-entry from Rabbit Hole.

    V8 P0 A2: a re-entry pass is one where the graph routed back from
    ``rabbit_hole_node`` to ``strategist_node`` via the new
    ``route_after_rabbit_hole`` conditional edge. We detect this by
    checking for the presence of any RABBIT_HOLE-origin hypothesis in
    state — Rabbit Hole is the ONLY producer of that origin, and it
    runs AFTER the first-pass Strategist, so any RABBIT_HOLE-origin
    hypothesis in state means Rabbit Hole has already run and the
    Strategist is being invoked for the second (or later) time.

    Pure read-only check — no state mutation.
    """
    hypotheses = state.get("hypotheses") or []
    rabbit_hole_origin = (
        HypothesisOrigin.RABBIT_HOLE.value
        if hasattr(HypothesisOrigin, "RABBIT_HOLE")
        else "rabbit_hole"
    )
    return any(getattr(h, "origin", None) == rabbit_hole_origin for h in hypotheses)


# POST-P0 Phase 2 (memory read-back): fixed bounded demotion applied to
# open hypotheses whose vuln_class has a NEGATIVE persisted outcome for
# this exact target (negative lessons / abandoned+refuted ledger rows).
# Demotion-only by construction: memory can lower a priority, never
# raise one, and can never confirm anything.
_NEGATIVE_PRIOR_DEMOTION = 0.05


def _retrieve_learned_strategy(state: PentestState) -> dict[str, Any]:
    """Fail-closed, scoped memory read-back for this engagement's target.

    Delegates to shared/learned_context.retrieve_learned_strategy: the
    returned record is retrieved-only (validator negative lessons + the
    strategist's own structured-hypothesis ledger), bounded, and scoped
    to (client_id, engagement_id, target). Missing scope -> empty dict
    (no memory influence at all), never an unscoped read.
    """
    try:
        from webpent.shared.learned_context import (
            retrieve_learned_strategy_from_state,
        )

        learned = retrieve_learned_strategy_from_state(state)
        return learned or {}
    except Exception as exc:
        logger.warning("Strategist: learned-strategy retrieval failed closed: %s", exc)
        return {}


def _apply_negative_prior(
    ranked: list[tuple[Hypothesis, float]],
    learned: dict[str, Any],
) -> tuple[list[tuple[Hypothesis, float]], frozenset[str]]:
    """Apply the demotion-only negative prior to a ranked list.

    Hypotheses whose vuln_class carries a negative persisted outcome for
    this exact target get a bounded -0.05 on their ranking score before
    promotion decisions. Ties keep the original (deterministic) order —
    Python's sort is stable. Never promotes: scores only decrease.
    """
    try:
        from webpent.shared.learned_context import negative_outcome_classes

        demote = negative_outcome_classes(learned)
    except Exception:
        demote = frozenset()
    if not learned or not demote:
        return ranked, demote
    adjusted: list[tuple[Hypothesis, float]] = []
    for hypothesis, score in ranked:
        cls = str(model_get(hypothesis, "vuln_class") or "").lower()
        if cls in demote:
            adjusted.append((hypothesis, float(score) - _NEGATIVE_PRIOR_DEMOTION))
        else:
            adjusted.append((hypothesis, float(score)))
    adjusted.sort(key=lambda pair: -pair[1])  # stable: ties keep prior order
    return adjusted, demote


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def strategist_node(state: PentestState) -> dict[str, Any]:
    """LangGraph node: the Strategist promotion checkpoint.

    Runs after all discovery nodes (hypothesis + deep-probers) and
    before ``payload_generator``. Promotes high-scoring hypotheses to
    Findings so the existing pipeline can process them.

    V8 P0 A2 — RE-ENTRY MODE: when invoked via the
    ``route_after_rabbit_hole`` conditional edge (i.e. Rabbit Hole
    just emitted new RABBIT_HOLE-origin hypotheses), the Strategist
    FILTERS the hypothesis pool to RABBIT_HOLE-origin UNEXPLORED
    hypotheses only. Heuristic, RAG-informed, and cross-reasons
    hypotheses that were already decided in the first pass are NOT
    re-processed — this is the "process only NEW hypotheses on
    re-entry" requirement. The Strategist also increments
    ``state["rabbit_hole_loop_back_count"]`` on every re-entry pass,
    which the router uses to bound the loop.

    Per Section 4: "The Strategist's authority is bounded exactly the
    same way ``exploit_chainer``'s is today. It can *rank and
    recommend*; it cannot authorize execution, cannot expand scope,
    and cannot override the Risk Manager's caps."

    Returns a partial state update with:
      * ``findings`` — new :class:`Finding` objects (one per promoted
        hypothesis that passes the existing deterministic gates).
      * ``hypotheses`` — updated :class:`Hypothesis` objects (status
        changed to ``promoted`` for each promoted hypothesis).
      * ``decision_log`` — Decision Log entries for each promotion.
      * ``rabbit_hole_loop_back_count`` — incremented on re-entry
        passes (V8 P0 A2).
      * ``messages`` — a summary :class:`AIMessage`.
      * ``current_phase`` — set to ``"strategist"``.
    """
    try:
        from webpent.shared.prioritization import (
            PrioritizationAction,
            promote_hypothesis_to_finding,
            rank_open_hypotheses,
            recommend_action,
        )
    except Exception as exc:
        logger.error("Strategist: prioritization import failed: %s", exc)
        return {
            "messages": [AIMessage(content="Strategist: skipped (import error).")],
            "current_phase": "strategist",
        }

    # P1 coverage remediation: do not impose a fixed top-N promotion cap.
    # The existing prioritization, deterministic promotion gates, payload
    # budget, execution sandbox, and validator remain the safety boundaries.
    # A hard cap here silently drops whole vulnerability families before they
    # reach validation, so coverage is now represented explicitly in the
    # ledger instead of being inferred from a truncated batch.

    try:
        hypotheses: list[Hypothesis] = list(state.get("hypotheses") or [])
    except Exception:
        hypotheses = []
    try:
        from webpent.shared.trust_matrix import build_trust_matrix

        trust_matrix = build_trust_matrix(state.get("findings") or [])
    except Exception as exc:
        logger.warning("Strategist: trust matrix unavailable: %s", exc)
        trust_matrix = {"schema_version": 1, "entries": {}, "sample_count": 0}

    if not hypotheses:
        logger.info("Strategist: no hypotheses to rank — skipping.")
        return {
            "trust_matrix": trust_matrix,
            "messages": [AIMessage(content="Strategist: no hypotheses to rank.")],
            "current_phase": "strategist",
        }

    # V8 P0 A2: detect re-entry mode. On re-entry, filter to
    # RABBIT_HOLE-origin UNEXPLORED hypotheses only — heuristic and
    # cross-reasons hypotheses already decided in the first pass are
    # not re-processed. This is the "process only NEW hypotheses on
    # re-entry" requirement.
    is_re_entry = _is_re_entry_pass(state)
    rabbit_hole_origin = (
        HypothesisOrigin.RABBIT_HOLE.value
        if hasattr(HypothesisOrigin, "RABBIT_HOLE")
        else "rabbit_hole"
    )
    unexplored_status = (
        HypothesisStatus.UNEXPLORED.value
        if hasattr(HypothesisStatus, "UNEXPLORED")
        else "unexplored"
    )

    # POST-P0 Phase 2 (memory read-back): one bounded, scoped retrieval
    # per pass. The record is advisory (state transparency + planner
    # injection) and its ONLY ranking effect is the demotion-only prior
    # applied after rank_open_hypotheses below.
    learned = _retrieve_learned_strategy(state)

    if is_re_entry:
        # Increment the loop-back counter FIRST so the router sees the
        # updated value on the next pass. The router uses this to
        # bound the loop against
        # RabbitHolePolicy.max_loop_back_iterations.
        current_count = int(state.get("rabbit_hole_loop_back_count") or 0)
        new_count = current_count + 1
        # Filter to RABBIT_HOLE-origin UNEXPLORED hypotheses only.
        # V10 EXHAUSTIVE AUDIT (reviewer follow-up): model_get, not
        # getattr — getattr(h, "origin", None) silently returns None
        # for a dict-shaped hypothesis (post-checkpoint round-trip)
        # instead of raising, so this filter would silently drop every
        # RABBIT_HOLE-origin hypothesis on re-entry without any log
        # line, same failure mode prioritization.rank_open_hypotheses
        # had before its fix (see _coerce_hypothesis there).
        hypotheses_for_ranking = [
            h
            for h in hypotheses
            if model_get(h, "origin") == rabbit_hole_origin
            and model_get(h, "status") == unexplored_status
        ]
        logger.info(
            "Strategist RE-ENTRY (loop-back %d): filtering to %d "
            "RABBIT_HOLE-origin UNEXPLORED hypothesis(ies) (out of %d total).",
            new_count,
            len(hypotheses_for_ranking),
            len(hypotheses),
        )
        if not hypotheses_for_ranking:
            # No new RABBIT_HOLE hypotheses to process — nothing to do.
            # Still bump the counter so the router doesn't loop forever.
            return {
                "rabbit_hole_loop_back_count": new_count,
                "trust_matrix": trust_matrix,
                "messages": [
                    AIMessage(
                        content=(
                            f"Strategist re-entry {new_count}: no new "
                            f"RABBIT_HOLE-origin hypotheses to promote."
                        )
                    )
                ],
                "current_phase": "strategist",
            }
        # Pass the FILTERED list to rank_open_hypotheses — but we still
        # need to return updates for the FULL hypothesis list (with
        # status mutations) so the merge_lists reducer correctly
        # updates the right hypotheses.
        ranked = rank_open_hypotheses(hypotheses_for_ranking, state)
        # POST-P0 Phase 2: demotion-only negative prior from scoped memory.
        ranked, _reentry_demoted = _apply_negative_prior(ranked, learned)
        open_count = len(ranked)
    else:
        # First-pass: rank the entire open pool (V7 behaviour).
        new_count = int(state.get("rabbit_hole_loop_back_count") or 0)
        ranked = rank_open_hypotheses(hypotheses, state)
        # POST-P0 Phase 2: demotion-only negative prior from scoped memory.
        ranked, _first_pass_demoted = _apply_negative_prior(ranked, learned)
        open_count = len(ranked)
        logger.info(
            "Strategist FIRST PASS: ranked %d open hypothesis(ies) (out of %d total).",
            open_count,
            len(hypotheses),
        )

    if not ranked:
        # Even if nothing got ranked, on re-entry we still need to
        # bump the counter so the router falls through next time.
        result: dict[str, Any] = {
            "messages": [AIMessage(content="Strategist: no open hypotheses to promote.")],
            "current_phase": "strategist",
        }
        if is_re_entry:
            result["rabbit_hole_loop_back_count"] = new_count
        result["trust_matrix"] = trust_matrix
        return result

    # Recommend an action for each ranked hypothesis. Promote those
    # that get PROMOTE; mark ABANDONED ones as abandoned; leave DEFER
    # and RABBIT_HOLE ones in the pool.
    new_findings: list[Any] = []
    updated_hypotheses: list[Hypothesis] = []
    decision_log_entries: list[dict[str, Any]] = []
    coverage_entries: dict[str, dict[str, Any]] = {}
    promoted_count = 0
    abandoned_count = 0
    cadence_overrides: dict[str, tuple[Any, str]] = {}
    cadence_discovery_count: int | None = None

    # Phase 1.4: run the recurring discovery-cadence checkpoint against the
    # highest-ranked branch. The checkpoint is bounded and only changes the
    # disposition of that one candidate; it never authorizes execution.
    try:
        from webpent.shared.self_critique import (
            SelfCritiqueAction,
            SelfCritiqueCheckpoint,
            recommend_self_critique_action,
            should_fire_every_n_discoveries,
        )

        last_check_count = int(state.get("self_critique_last_discovery_count") or 0)
        mental_model = state.get("mental_model") or {}
        discovery_count = len(mental_model.get("nodes") or {})
        if ranked and should_fire_every_n_discoveries(
            state,
            last_check_count=last_check_count,
        ):
            cadence_hypothesis = ranked[0][0]
            critique_action, critique_rule, _ = recommend_self_critique_action(
                state,
                checkpoint=SelfCritiqueCheckpoint.EVERY_N_DISCOVERIES,
                hypothesis=cadence_hypothesis,
                branch_id=str(model_get(cadence_hypothesis, "id", "")),
            )
            if critique_action is SelfCritiqueAction.ABANDON:
                cadence_overrides[str(model_get(cadence_hypothesis, "id", ""))] = (
                    PrioritizationAction.ABANDON,
                    critique_rule,
                )
            elif critique_action is SelfCritiqueAction.DEPRIORITIZE:
                cadence_overrides[str(model_get(cadence_hypothesis, "id", ""))] = (
                    PrioritizationAction.DEFER,
                    critique_rule,
                )
            cadence_discovery_count = discovery_count
    except Exception as exc:
        logger.warning("Strategist: discovery-cadence checkpoint failed: %s", exc)

    def record_coverage(
        hypothesis: Any,
        *,
        status: str,
        action: str,
        reason: str,
        validator_route: str | None,
        score_value: float,
    ) -> None:
        """Record bounded, report-safe disposition metadata for one candidate."""
        hypothesis_id = str(model_get(hypothesis, "id", ""))
        if not hypothesis_id:
            return
        vuln_class = str(model_get(hypothesis, "vuln_class", "unknown"))
        coverage_entries[hypothesis_id] = {
            "hypothesis_id": hypothesis_id,
            "vuln_class": vuln_class,
            "status": status,
            "action": action,
            "reason": reason,
            "validator_route": validator_route,
            "score": round(float(score_value), 6),
        }

    for hypothesis, score in ranked:
        validator_route: str | None = None
        try:
            # _classify_finding is the validator agent's single routing
            # authority. SimpleNamespace is sufficient because it reads only
            # the deterministic vuln_class field and avoids duplicating the
            # supported-class matrix in this advisory node.
            from webpent.agents.validator.agent import _classify_finding

            validator_route = _classify_finding(
                SimpleNamespace(vuln_class=model_get(hypothesis, "vuln_class"))
            )
        except Exception as exc:
            logger.debug("Strategist: validator coverage lookup failed: %s", exc)

        try:
            # V8 P0 A2: on re-entry, the loop-back IS available —
            # flip the rabbit_hole_available flag so recommend_action
            # can route mid-score RABBIT_HOLE hypotheses back to a
            # new Rabbit Hole branch if appropriate. On first pass,
            # keep rabbit_hole_available=False (V7 behaviour).
            action, score_val, rule = recommend_action(
                hypothesis,
                state,
                rabbit_hole_available=is_re_entry,
            )
            cadence_override = cadence_overrides.get(
                str(model_get(hypothesis, "id", ""))
            )
            if cadence_override is not None:
                action, cadence_rule = cadence_override
                rule = f"{rule}; self_critique={cadence_rule}"
        except Exception as exc:
            logger.debug(
                "Strategist: recommend_action failed for %s: %s",
                model_get(hypothesis, "id", "<unknown>"),
                exc,
            )
            record_coverage(
                hypothesis,
                status="blocked",
                action="error",
                reason="recommend_action_failed",
                validator_route=validator_route,
                score_value=score,
            )
            continue

        # P0 wiring: expensive promotions must pass the real
        # self-critique checkpoint before entering payload generation.
        # The helper owns its Decision Log entry; this node only applies
        # the bounded recommendation and records coverage.
        self_critique_rule = ""
        if action == PrioritizationAction.PROMOTE:
            try:
                from webpent.shared.self_critique import (
                    SelfCritiqueAction,
                    SelfCritiqueCheckpoint,
                    recommend_self_critique_action,
                    should_fire_before_promotion,
                )

                if should_fire_before_promotion(hypothesis):
                    critique_action, self_critique_rule, _llm_contribution = (
                        recommend_self_critique_action(
                            state,
                            checkpoint=SelfCritiqueCheckpoint.BEFORE_PROMOTION,
                            hypothesis=hypothesis,
                            branch_id=str(model_get(hypothesis, "id", "")),
                        )
                    )
                    if critique_action is SelfCritiqueAction.ABANDON:
                        action = PrioritizationAction.ABANDON
                    elif critique_action is SelfCritiqueAction.DEPRIORITIZE:
                        action = PrioritizationAction.DEFER
                    if self_critique_rule:
                        rule = f"{rule}; self_critique={self_critique_rule}"
            except Exception as exc:
                logger.warning(
                    "Strategist: self-critique checkpoint failed for %s: %s",
                    model_get(hypothesis, "id", "<unknown>"),
                    exc,
                )
                action = PrioritizationAction.DEFER
                self_critique_rule = "self_critique_error"
                rule = f"{rule}; self_critique=self_critique_error"

        # Authorized-active coverage policy: do not let the weighted
        # prioritization score silently remove an in-scope validator route
        # from the current campaign.  This is bounded execution, not
        # confirmation: the hypothesis must already have a deterministic
        # validator route, must remain above the abandon floor, and must not
        # have been explicitly deprioritized by self-critique.  The promoted
        # Finding still enters the existing payload/validator pipeline, where
        # causal evidence and negative-control gates remain mandatory.
        hypothesis_vuln_class = str(model_get(hypothesis, "vuln_class", ""))
        idor_bac_promotion_guard = hypothesis_vuln_class == "idor"
        bounded_validator_execution = (
            validator_route is not None
            and not idor_bac_promotion_guard
            and action in (
                PrioritizationAction.DEFER,
                PrioritizationAction.RABBIT_HOLE,
            )
            and not self_critique_rule
            and str(state.get("scan_mode") or "") == "authorized-active"
            and score > 0.15
            and bool(model_get(hypothesis, "target_url", ""))
        )
        if bounded_validator_execution:
            action = PrioritizationAction.PROMOTE
            rule = (
                f"{rule}; authorized-active bounded validator execution "
                f"(score={score:.4f} > ABANDON_THRESHOLD=0.15)"
            )

        if validator_route is None:
            # Fail closed: a prioritization recommendation is not a
            # validator.  Missing-validator classes must never enter the
            # Finding/payload pipeline, even when deterministic_match or a
            # high score would otherwise recommend PROMOTE.
            if action == PrioritizationAction.PROMOTE:
                action = PrioritizationAction.DEFER
                rule = f"{rule}; blocked: missing deterministic validator route"
            record_coverage(
                hypothesis,
                status="missing-validator",
                action=str(action.value),
                reason="no_deterministic_validator_route",
                validator_route=None,
                score_value=score,
            )

        elif action not in (PrioritizationAction.PROMOTE, PrioritizationAction.ABANDON):
            record_coverage(
                hypothesis,
                status="blocked",
                action=str(action.value),
                reason=(
                    "idor_requires_target_backed_bac_evidence"
                    if idor_bac_promotion_guard
                    else (
                        "self_critique_deprioritized"
                        if self_critique_rule
                        and action == PrioritizationAction.DEFER
                        else "prioritization_gate_deferred"
                    )
                ),
                validator_route=validator_route,
                score_value=score,
            )

        if action == PrioritizationAction.PROMOTE:
            try:
                finding = promote_hypothesis_to_finding(hypothesis, state)
            except Exception as exc:
                logger.warning(
                    "Strategist: promote_hypothesis_to_finding failed for %s: %s",
                    model_get(hypothesis, "id", "<unknown>"),
                    exc,
                )
                record_coverage(
                    hypothesis,
                    status="blocked",
                    action=str(getattr(action, "value", action)),
                    reason="promotion_conversion_failed",
                    validator_route=validator_route,
                    score_value=score,
                )
                continue

            if finding is not None:
                new_findings.append(finding)
                record_coverage(
                    hypothesis,
                    status="tested",
                    action=str(action.value),
                    reason="promoted_to_validator_pipeline",
                    validator_route=validator_route,
                    score_value=score,
                )
                # Mark the hypothesis as promoted (terminal state).
                updated_hyp = hypothesis.model_copy(
                    update={
                        "status": HypothesisStatus.PROMOTED.value,
                    }
                )
                updated_hypotheses.append(updated_hyp)
                promoted_count += 1
                # V8 P0 A2: on re-entry, set branch_id = str(hypothesis.id)
                # so the Decision Log entry is traceable to the Rabbit
                # Hole branch that spawned this hypothesis. This makes
                # the closed loop auditable end-to-end: rabbit_hole_node
                # writes rabbit_hole_entered with branch_id=str(h.id),
                # and the Strategist's promotion entry carries the SAME
                # branch_id — a reviewer can query
                # get_entries_by_branch(str(h.id)) and see the full
                # lifecycle (entered -> promoted).
                entry: dict[str, Any] = {
                    "decision_type": "hypothesis_promoted",
                    "rule_fired": rule,
                    "outcome": f"promoted to finding {finding.id}",
                    "entity_refs": [str(hypothesis.id), str(finding.id)],
                }
                if is_re_entry or getattr(hypothesis, "origin", None) == rabbit_hole_origin:
                    entry["branch_id"] = str(hypothesis.id)
                    entry["metadata"] = {
                        "origin": rabbit_hole_origin,
                        "loop_back_pass": new_count,
                        "promoted_via": "strategist_re_entry",
                    }
                decision_log_entries.append(entry)
            else:
                record_coverage(
                    hypothesis,
                    status="blocked",
                    action=str(getattr(action, "value", action)),
                    reason="promotion_gate_returned_no_finding",
                    validator_route=validator_route,
                    score_value=score,
                )
        elif action == PrioritizationAction.ABANDON:
            # Mark the hypothesis as abandoned (terminal state).
            updated_hyp = hypothesis.model_copy(
                update={
                    "status": HypothesisStatus.ABANDONED.value,
                }
            )
            updated_hypotheses.append(updated_hyp)
            if validator_route is not None:
                record_coverage(
                    hypothesis,
                    status="blocked",
                    action=str(action.value),
                    reason="prioritization_gate_abandoned",
                    validator_route=validator_route,
                    score_value=score,
                )
            abandoned_count += 1
            entry_abandon: dict[str, Any] = {
                "decision_type": "self_critique",
                "rule_fired": rule,
                "outcome": "abandoned",
                "entity_refs": [str(hypothesis.id)],
            }
            if is_re_entry or getattr(hypothesis, "origin", None) == rabbit_hole_origin:
                entry_abandon["branch_id"] = str(hypothesis.id)
                entry_abandon["metadata"] = {
                    "origin": rabbit_hole_origin,
                    "loop_back_pass": new_count,
                    "abandoned_via": "strategist_re_entry",
                }
            decision_log_entries.append(entry_abandon)
        # DEFER and RABBIT_HOLE: leave in pool, no state change.

    pass_label = "re-entry" if is_re_entry else "first pass"
    summary = (
        f"Strategist ({pass_label}): ranked {open_count} open hypothesis(ies), "
        f"promoted {promoted_count}, abandoned {abandoned_count}."
    )
    logger.info(summary)

    # Best-effort Decision Log persistence (Phase 6).
    for entry in decision_log_entries:
        try:
            from webpent.memory.decision_log import log_decision

            log_decision(**entry)
        except Exception as exc:
            logger.warning("Strategist: Decision Log persistence failed: %s", exc)

    # V9 P0 B8: persist updated hypotheses to the structured-hypotheses
    # store. Previously save_structured_hypothesis was dead code (never
    # called). Now every hypothesis that the Strategist promoted or
    # abandoned is persisted so the audit trail (belief → investigation
    # → finding) is recoverable from the DB across engagements. Best-
    # effort — persistence failures are logged but do not crash the
    # strategist (the in-state hypotheses are still correct).
    for updated_hyp in updated_hypotheses:
        try:
            from webpent.memory.lessons import get_lessons_manager

            mgr = get_lessons_manager()
            mgr.save_structured_hypothesis(updated_hyp)
        except Exception as exc:
            logger.warning(  # V9 FIX B-07: was debug, now warning
                "Strategist: structured-hypothesis persistence failed for %s: %s",
                getattr(updated_hyp, "id", "<unknown>"),
                exc,
            )

    status_counts = {"tested": 0, "missing-validator": 0, "blocked": 0}
    for entry in coverage_entries.values():
        status = entry["status"]
        if status in status_counts:
            status_counts[status] += 1
    coverage_ledger = {
        "schema_version": 1,
        "selection_policy": "coverage-based-no-fixed-top-n",
        "candidate_count": len(coverage_entries),
        "status_counts": status_counts,
        "entries": coverage_entries,
    }

    result: dict[str, Any] = {
        "findings": new_findings,
        "coverage_ledger": coverage_ledger,
        "hypotheses": updated_hypotheses,
        "trust_matrix": trust_matrix,
        "decision_log": decision_log_entries,
        # POST-P0 Phase 2: transparency record (retrieved-only, advisory).
        "learned_strategy": learned,
        "messages": [AIMessage(content=summary)],
        "current_phase": "strategist",
    }
    # V8 P0 A2: bump the loop-back counter on re-entry passes so the
    # router bounds the loop.
    if is_re_entry:
        result["rabbit_hole_loop_back_count"] = new_count
    if cadence_discovery_count is not None:
        result["self_critique_last_discovery_count"] = cadence_discovery_count
    return result
