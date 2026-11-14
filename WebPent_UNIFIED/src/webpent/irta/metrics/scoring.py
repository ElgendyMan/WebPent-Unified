"""IRTA v2 scoring primitives with explicit blocked/inconclusive handling."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CaseOutcome:
    case_id: str
    ground_truth_positive: bool
    disposition: str
    scored: bool = True


@dataclass(frozen=True)
class ScoreCard:
    evaluated: int
    tp: int
    tn: int
    fp: int
    fn: int
    blocked: int
    inconclusive: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        denominator = self.precision + self.recall
        return 2 * self.precision * self.recall / denominator if denominator else 0.0


def score_outcomes(outcomes: tuple[CaseOutcome, ...]) -> ScoreCard:
    tp = tn = fp = fn = blocked = inconclusive = 0
    for outcome in outcomes:
        if not outcome.scored or outcome.disposition in {
            "blocked",
            "observation_only",
            "out_of_scope",
        }:
            blocked += 1
            continue
        if outcome.disposition == "inconclusive":
            inconclusive += 1
            continue
        detected = outcome.disposition in {"confirmed", "positive"}
        if outcome.ground_truth_positive and detected:
            tp += 1
        elif not outcome.ground_truth_positive and not detected:
            tn += 1
        elif detected:
            fp += 1
        else:
            fn += 1
    return ScoreCard(tp + tn + fp + fn, tp, tn, fp, fn, blocked, inconclusive)
