"""EGAIE seeds: ground-truth cases -> seeded investigation state.

Seeding is a benchmark concern: every case becomes one PROPOSED
hypothesis plus one stage1 experiment with a neutral, uniform gain
estimate. Nothing here marks anything confirmed; only the validated
closed loop can promote.
"""
from __future__ import annotations

from webpent.egaie.schemas import (
    HypothesisRecord,
    InvestigationState,
    ProposedExperiment,
)


def seed_state(
    cases: list,
    engagement_id: str,
    target_url: str,
) -> InvestigationState:
    state = InvestigationState(
        engagement_id=engagement_id, target_url=target_url)
    for case in cases:
        state.add_hypothesis(HypothesisRecord(
            hypothesis_id=f"h-{case.case_id}",
            family=case.family,
            statement=f"seeded hypothesis for {case.case_id}",
            source="ground_truth_seed",
            origin=case.case_id,
        ))
        state.add_experiment(ProposedExperiment(
            experiment_id=f"e-{case.case_id}",
            family=case.family,
            signature=f"{case.case_id}/{case.family}",
            description=f"stage1 probe for {case.case_id}",
            cost=0.2,
            risk=0.2,
            gain_estimate=0.5,
            rationale="uniform seed",
            hypothesis_id=f"h-{case.case_id}",
        ))
    return state
