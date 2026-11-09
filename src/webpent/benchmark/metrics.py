"""Deterministic benchmark metrics for lab evaluation artifacts."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class BenchmarkReport:
    """Metric result with explicit denominators and no inferred findings."""

    true_positive_count: int
    false_positive_count: int
    missed_count: int
    predicted_count: int
    expected_count: int
    negative_case_count: int
    precision: float
    recall: float
    false_discovery_rate: float
    false_positive_rate: float
    evidence_quality: float
    coverage: float
    reproducibility: float
    elapsed_seconds: float = 0.0
    llm_tokens: int = 0

    def as_dict(self) -> dict[str, int | float]:
        return {
            "true_positive_count": self.true_positive_count,
            "false_positive_count": self.false_positive_count,
            "missed_count": self.missed_count,
            "predicted_count": self.predicted_count,
            "expected_count": self.expected_count,
            "negative_case_count": self.negative_case_count,
            "precision": self.precision,
            "recall": self.recall,
            "false_discovery_rate": self.false_discovery_rate,
            "false_positive_rate": self.false_positive_rate,
            "evidence_quality": self.evidence_quality,
            "coverage": self.coverage,
            "reproducibility": self.reproducibility,
            "elapsed_seconds": self.elapsed_seconds,
            "llm_tokens": self.llm_tokens,
        }


def evaluate(
    predicted: Iterable[str],
    expected: Iterable[str],
    *,
    evidence_complete: Mapping[str, bool] | None = None,
    tested_surface_count: int = 0,
    total_surface_count: int = 0,
    independent_runs: Iterable[Iterable[str]] = (),
    negative_case_ids: Iterable[str] = (),
    elapsed_seconds: float = 0.0,
    llm_tokens: int = 0,
) -> BenchmarkReport:
    """Evaluate exact finding keys without inferring unknown negatives.

    ``false_discovery_rate`` is the fraction of predictions not present in the
    declared positive ground truth.  ``false_positive_rate`` is only computed
    against an explicit negative-case universe; when that universe is absent it
    is zero because the denominator is unknown, not because the run is perfect.
    """
    predicted_set = {str(item).strip() for item in predicted if str(item).strip()}
    expected_set = {str(item).strip() for item in expected if str(item).strip()}
    negative_set = {
        str(item).strip() for item in negative_case_ids if str(item).strip()
    }
    true_positive = predicted_set & expected_set
    false_positive = predicted_set - expected_set
    missed = expected_set - predicted_set
    complete = evidence_complete or {}
    evidence_quality = (
        sum(bool(complete.get(item, False)) for item in predicted_set) / len(predicted_set)
        if predicted_set
        else 0.0
    )
    runs = [
        {str(item).strip() for item in run if str(item).strip()}
        for run in independent_runs
    ]
    reproducibility = 0.0
    if runs and predicted_set:
        reproducibility = sum(1 for run in runs if run == predicted_set) / len(runs)
    negative_hits = predicted_set & negative_set
    return BenchmarkReport(
        true_positive_count=len(true_positive),
        false_positive_count=len(false_positive),
        missed_count=len(missed),
        predicted_count=len(predicted_set),
        expected_count=len(expected_set),
        negative_case_count=len(negative_set),
        precision=len(true_positive) / len(predicted_set) if predicted_set else 0.0,
        recall=len(true_positive) / len(expected_set) if expected_set else 0.0,
        false_discovery_rate=(
            len(false_positive) / len(predicted_set) if predicted_set else 0.0
        ),
        false_positive_rate=(
            len(negative_hits) / len(negative_set) if negative_set else 0.0
        ),
        evidence_quality=round(evidence_quality, 6),
        coverage=(
            max(0, min(tested_surface_count, total_surface_count)) / total_surface_count
            if total_surface_count > 0
            else 0.0
        ),
        reproducibility=round(reproducibility, 6),
        elapsed_seconds=round(max(0.0, float(elapsed_seconds)), 6),
        llm_tokens=max(0, int(llm_tokens)),
    )


__all__ = ["BenchmarkReport", "evaluate"]
