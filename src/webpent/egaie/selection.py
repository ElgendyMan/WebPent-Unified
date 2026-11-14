"""EGAIE information-gain experiment selection.

Scores pending experiments deterministically: expected gain plus an
unresolved-family bonus, minus execution cost, execution risk, and a
repetition penalty for signatures that already returned uninformative
outcomes. The LLM (or any proposer) may put experiments on the table,
but selection, termination and strategy switches are decided here, from
recorded evidence only.
"""
from __future__ import annotations

from webpent.egaie.repetition import RepetitionRegister
from webpent.egaie.schemas import (
    DecisionAction,
    DecisionRecord,
    EvidenceKind,
    InvestigationState,
    ProposedExperiment,
)

FAMILY_BONUS = 0.5
REPETITION_PENALTY = 1.0
EXHAUSTED_SCORE = -1000.0


class InformationGainSelector:
    """Deterministic information-gain selection over pending
    experiments.

    The score is the 0.34.0 formula — expected gain plus an
    unresolved-family bonus, minus execution cost, execution risk and
    a repetition penalty — extended (UNIFIED MERGE 2026-11-02, from
    the l10 Phase 5 contracts) with state-record terms the engine
    already keeps:

    - a hypothesis the evidence has resolved is never re-probed;
    - a hypothesis whose prerequisites the planner marked
      unavailable is never retried (opt-in via
      ``unavailable_hypotheses``);
    - evidence-backed confidence lifts a candidate; contradicting
      evidence lowers it;
    - a hypothesis whose earlier experiment came back blocked
      carries that history;
    - state-advancing mutation families are penalized at equal
      value (opt-in via ``state_advancing_families``);
    - when the remaining rounds cannot cover the pending pool,
      cost and risk weigh more (opt-in via ``remaining_rounds``).

    Every term is zero when the caller supplies no availability
    information and the state carries no signal, so the legacy call
    shape keeps the legacy formula exactly. Selection only chooses
    WHAT to run next: the oracle, not this selector, decides what
    the evidence means.
    """

    SUPPORTED_CONFIDENCE_LIFT = 0.25
    EVIDENCE_LIFT = 0.25
    BLOCKED_HISTORY_PENALTY = 0.5
    STATE_ADVANCING_PENALTY = 0.25

    @staticmethod
    def _experiment_owners(
            state: InvestigationState) -> dict[str, str]:
        return {
            e.experiment_id: e.hypothesis_id for e in state.experiments
        }

    def _evidence_tally(
            self, state: InvestigationState) -> dict[str, int]:
        """Net evidence per hypothesis id: +1 supporting, -1
        contradicting. Evidence refs name the experiment they were
        gathered against; the ref itself may also be a hypothesis id
        (both shapes appear in the record)."""
        owners = self._experiment_owners(state)
        tally: dict[str, int] = {}
        for item in state.evidence:
            target = owners.get(item.ref, item.ref)
            if not target:
                continue
            if item.kind is EvidenceKind.SUPPORTING:
                tally[target] = tally.get(target, 0) + 1
            elif item.kind is EvidenceKind.CONTRADICTING:
                tally[target] = tally.get(target, 0) - 1
        return tally

    @staticmethod
    def _blocked_hypotheses(state: InvestigationState) -> set[str]:
        owners = InformationGainSelector._experiment_owners(state)
        return {
            owners[experiment_id]
            for experiment_id, outcome in (
                state.experiment_outcomes.items())
            if outcome == "blocked" and experiment_id in owners
        }

    def select(
        self,
        state: InvestigationState,
        candidates: list[ProposedExperiment],
        register: RepetitionRegister,
        unavailable_hypotheses: frozenset[str] = frozenset(),
        state_advancing_families: frozenset[str] = frozenset(),
        remaining_rounds: int | None = None,
    ) -> DecisionRecord:
        if not candidates:
            return DecisionRecord(
                round=state.round,
                action=DecisionAction.TERMINATE,
                selected_experiment_id="",
                scores={},
                alternatives=(),
                rationale="no pending experiments remain",
            )

        statuses = {
            h.hypothesis_id: h.status for h in state.hypotheses
        }
        resolved = {
            hypothesis_id for hypothesis_id, status in statuses.items()
            if status.value not in ("proposed", "supported")
        }
        supported = {
            hypothesis_id for hypothesis_id, status in statuses.items()
            if status.value == "supported"
        }
        blocked = self._blocked_hypotheses(state)
        evidence = self._evidence_tally(state)
        unresolved_families = {
            record.family for record in state.unresolved_hypotheses()
        }
        # A budget that cannot cover the pending pool weighs cost and
        # risk more heavily: a cheaper experiment that can still
        # discriminate beats an expensive one that may never run.
        if remaining_rounds is None:
            budget_scale = 1.0
        else:
            budget_scale = max(
                1.0, len(candidates) / max(remaining_rounds, 1))

        scores: dict[str, float] = {}
        for candidate in candidates:
            hypothesis_id = candidate.hypothesis_id
            if (
                register.is_exhausted(candidate.signature)
                or (hypothesis_id and hypothesis_id in resolved)
                or (hypothesis_id
                    and hypothesis_id in unavailable_hypotheses)
            ):
                scores[candidate.experiment_id] = EXHAUSTED_SCORE
                continue
            penalty = (
                REPETITION_PENALTY
                * register.uninformative_count(candidate.signature)
            )
            bonus = (
                FAMILY_BONUS if candidate.family in unresolved_families
                else 0.0
            )
            confidence = (
                self.SUPPORTED_CONFIDENCE_LIFT
                if hypothesis_id and hypothesis_id in supported
                else 0.0
            )
            net_evidence = (
                self.EVIDENCE_LIFT * evidence[hypothesis_id]
                if hypothesis_id and hypothesis_id in evidence
                else 0.0
            )
            history = (
                -self.BLOCKED_HISTORY_PENALTY
                if hypothesis_id and hypothesis_id in blocked
                else 0.0
            )
            advancing = (
                -self.STATE_ADVANCING_PENALTY
                if candidate.family in state_advancing_families
                else 0.0
            )
            scores[candidate.experiment_id] = round(
                candidate.gain_estimate + bonus + confidence
                + net_evidence + history + advancing
                - candidate.cost * budget_scale
                - candidate.risk * budget_scale - penalty,
                6,
            )

        ranked = sorted(
            candidates,
            key=lambda c: (-scores[c.experiment_id], c.experiment_id),
        )
        best = ranked[0]
        alternatives = tuple(
            (c.experiment_id, scores[c.experiment_id]) for c in ranked
        )

        if scores[best.experiment_id] == EXHAUSTED_SCORE:
            exhausted = ", ".join(
                sorted({
                    c.signature for c in candidates
                    if register.is_exhausted(c.signature)
                }))
            return DecisionRecord(
                round=state.round,
                action=DecisionAction.STRATEGY_SWITCH,
                selected_experiment_id="",
                scores=scores,
                alternatives=alternatives,
                rationale=(
                    "all candidate signatures exhausted by repeated "
                    f"uninformative outcomes: {exhausted}"
                ),
            )

        rationale = (
            f"highest information gain: {best.experiment_id} "
            f"(score {scores[best.experiment_id]}, signature "
            f"{best.signature})"
        )
        return DecisionRecord(
            round=state.round,
            action=DecisionAction.SELECT,
            selected_experiment_id=best.experiment_id,
            scores=scores,
            alternatives=alternatives,
            rationale=rationale,
        )


class ProposalOrderSelector:
    """L10 ablation E: information-gain selection disabled.

    Restored from the l10 lineage by UNIFIED MERGE (2026-11-02) so the
    L10 ablation matrix keeps its E-variant selector. Takes the first
    pending candidate in proposal order — no gain scoring, no family
    bonus, no confidence, evidence, reversibility or budget terms. The
    repetition register still holds (an exhausted signature is never
    re-run) and termination is unchanged. Hypothesis generation and
    state reasoning are untouched upstream of this class."""

    def select(
        self,
        state: InvestigationState,
        candidates: list[ProposedExperiment],
        register: RepetitionRegister,
        unavailable_hypotheses: frozenset[str] = frozenset(),
        state_advancing_families: frozenset[str] = frozenset(),
        remaining_rounds: int | None = None,
    ) -> DecisionRecord:
        if not candidates:
            return DecisionRecord(
                round=state.round,
                action=DecisionAction.TERMINATE,
                selected_experiment_id="",
                scores={},
                alternatives=(),
                rationale="no pending experiments remain",
            )
        for candidate in candidates:
            if not register.is_exhausted(candidate.signature):
                return DecisionRecord(
                    round=state.round,
                    action=DecisionAction.SELECT,
                    selected_experiment_id=candidate.experiment_id,
                    scores={},
                    alternatives=(),
                    rationale=(
                        "proposal-order selection (information-gain "
                        f"ablation): {candidate.experiment_id}"),
                )
        return DecisionRecord(
            round=state.round,
            action=DecisionAction.STRATEGY_SWITCH,
            selected_experiment_id="",
            scores={},
            alternatives=(),
            rationale=(
                "all candidate signatures exhausted by repeated "
                "uninformative outcomes"),
        )
