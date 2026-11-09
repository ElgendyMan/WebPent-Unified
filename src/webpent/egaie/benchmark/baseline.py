"""EGAIE fixed-order baseline.

Same validated pipeline as the adaptive loop (CausalGuard, sealed
bundles, replay), but selection is fixed insertion order with no
information gain, no repetition handling, and no follow-up proposals.
It exists only to be compared against, never to weaken validation.
"""
from __future__ import annotations

from webpent.egaie.orchestrator import InvestigationOrchestrator
from webpent.egaie.repetition import RepetitionRegister
from webpent.egaie.schemas import (
    DecisionAction,
    DecisionRecord,
    InvestigationState,
    ProposedExperiment,
)


class FixedOrderSelector:
    def select(
        self,
        state: InvestigationState,
        candidates: list[ProposedExperiment],
        register: RepetitionRegister,
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
        chosen = candidates[0]
        return DecisionRecord(
            round=state.round,
            action=DecisionAction.SELECT,
            selected_experiment_id=chosen.experiment_id,
            scores={},
            alternatives=(),
            rationale="fixed insertion order",
        )


def build_baseline_orchestrator(
    experiment_port, validation_port, proof_port, model_port
) -> InvestigationOrchestrator:
    return InvestigationOrchestrator(
        experiment_port=experiment_port,
        validation_port=validation_port,
        proof_port=proof_port,
        model_port=model_port,
        selector=FixedOrderSelector(),
        proposer=None,
    )
