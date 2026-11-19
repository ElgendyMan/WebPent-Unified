"""Deterministic benchmark orchestration and memory-learning measurements."""

from __future__ import annotations

from dataclasses import dataclass

from webpent.irta.generator import AdversarialMutator, MutationKind, generate_target
from webpent.irta.metrics.scoring import CaseOutcome, ScoreCard, score_outcomes


@dataclass(frozen=True)
class DifficultyTier:
    name: str
    mutation: MutationKind | None
    expected_case_count: int


@dataclass(frozen=True)
class BenchmarkResult:
    targets: int
    cases: int
    tiers: tuple[str, ...]
    score: ScoreCard


@dataclass(frozen=True)
class LearningMeasurement:
    baseline_cases: int
    later_cases: int
    baseline_recall: float
    later_recall: float

    @property
    def recall_delta(self) -> float:
        return self.later_recall - self.baseline_recall


DEFAULT_TIERS = (
    DifficultyTier("baseline", None, 4),
    DifficultyTier("response-adversarial", MutationKind.DENIAL_AS_EMPTY_SUCCESS, 4),
    DifficultyTier("permission-adversarial", MutationKind.PERMISSION_ALIAS, 4),
    DifficultyTier("partial-disclosure", MutationKind.PARTIAL_OBJECT_ACCESS, 4),
)


class IrtaBenchmark:
    """Produce reproducible benchmark inputs; execution remains external."""

    def build(
        self,
        seeds: tuple[int, ...],
        tiers: tuple[DifficultyTier, ...] = DEFAULT_TIERS,
    ) -> BenchmarkResult:
        if not seeds or not tiers:
            raise ValueError("benchmark requires at least one target and one difficulty tier")
        mutator = AdversarialMutator()
        cases = 0
        names: list[str] = []
        for seed in seeds:
            base = generate_target(seed)
            for tier in tiers:
                target = base if tier.mutation is None else mutator.mutate(base, tier.mutation)
                target.validate()
                cases += tier.expected_case_count
                names.append(f"{target.target_id}:{tier.name}")
        # No detection result is fabricated: an unexecuted benchmark is blocked.
        score = score_outcomes(tuple(CaseOutcome(name, True, "blocked", False) for name in names))
        return BenchmarkResult(len(seeds), cases, tuple(names), score)


def measure_learning(baseline: ScoreCard, later: ScoreCard) -> LearningMeasurement:
    return LearningMeasurement(
        baseline_cases=baseline.evaluated,
        later_cases=later.evaluated,
        baseline_recall=baseline.recall,
        later_recall=later.recall,
    )
