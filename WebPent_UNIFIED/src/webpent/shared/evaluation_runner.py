"""Canonical local evaluation runner surface.

Evaluation remains offline and delegates to the single behavior/evaluation
implementation.  It cannot qualify a live target or promote a finding.
"""

from collections.abc import Iterable

from webpent.shared.behavior_scenarios import BehaviorScenarioResult, BehaviorScenarioRunner
from webpent.shared.evaluation import (
    BehaviorEvaluation,
    QualificationScorecard,
    evaluate_behavior_results,
)


def run_local_behavior_evaluation() -> tuple[
    tuple[BehaviorScenarioResult, ...], BehaviorEvaluation
]:
    """Run the deterministic local behavior suite and return its projection."""
    results = tuple(BehaviorScenarioRunner().run_all())
    return results, evaluate_behavior_results(results)


def evaluate(results: Iterable[BehaviorScenarioResult]) -> BehaviorEvaluation:
    """Evaluate already-produced local results without adding authority."""
    return evaluate_behavior_results(results)


__all__ = [
    "BehaviorEvaluation",
    "QualificationScorecard",
    "evaluate",
    "run_local_behavior_evaluation",
]
