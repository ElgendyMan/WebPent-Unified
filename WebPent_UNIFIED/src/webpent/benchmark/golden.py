"""Pure golden benchmark cases for deterministic WebPent evaluation.

The cases are contract fixtures, not live-target findings.  They exercise the
metric boundary and make the distinction between discovery, evidence quality,
and strict confirmation explicit.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from webpent.benchmark.metrics import BenchmarkReport, evaluate


@dataclass(frozen=True)
class GoldenBenchmarkCase:
    """One declared benchmark case with an explicit positive/negative universe."""

    case_id: str
    expected_case_ids: tuple[str, ...]
    negative_case_ids: tuple[str, ...]
    predicted_case_ids: tuple[str, ...]
    evidence_complete: Mapping[str, bool]
    independent_runs: tuple[tuple[str, ...], ...]
    tested_surface_count: int = 0
    total_surface_count: int = 0

    def evaluate(self) -> BenchmarkReport:
        """Return metrics for this case without performing I/O."""
        return evaluate(
            self.predicted_case_ids,
            self.expected_case_ids,
            evidence_complete=self.evidence_complete,
            tested_surface_count=self.tested_surface_count,
            total_surface_count=self.total_surface_count,
            independent_runs=self.independent_runs,
            negative_case_ids=self.negative_case_ids,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "expected_case_ids": list(self.expected_case_ids),
            "negative_case_ids": list(self.negative_case_ids),
            "predicted_case_ids": list(self.predicted_case_ids),
            "evidence_complete": dict(self.evidence_complete),
            "independent_runs": [list(run) for run in self.independent_runs],
            "metrics": self.evaluate().as_dict(),
        }


@dataclass(frozen=True)
class GoldenBenchmarkResult:
    """Stable projection of all golden benchmark cases."""

    cases: tuple[GoldenBenchmarkCase, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "fixture_type": "offline-contract-golden",
            "live_findings_claimed": False,
            "cases": [case.as_dict() for case in self.cases],
        }


def default_golden_cases() -> tuple[GoldenBenchmarkCase, ...]:
    """Return the repository's small, deterministic metric contract corpus."""
    return (
        GoldenBenchmarkCase(
            case_id="complete-evidence-and-replay",
            expected_case_ids=("idor", "workflow"),
            negative_case_ids=("known-negative",),
            predicted_case_ids=("idor", "workflow"),
            evidence_complete={"idor": True, "workflow": True},
            independent_runs=(
                ("idor", "workflow"),
                ("idor", "workflow"),
                ("idor", "workflow"),
            ),
            tested_surface_count=4,
            total_surface_count=4,
        ),
        GoldenBenchmarkCase(
            case_id="incomplete-evidence-and-drift",
            expected_case_ids=("idor", "workflow"),
            negative_case_ids=("known-negative", "noise"),
            predicted_case_ids=("idor", "known-negative"),
            evidence_complete={"idor": True, "known-negative": False},
            independent_runs=(
                ("idor", "known-negative"),
                ("idor", "known-negative"),
                ("idor",),
            ),
            tested_surface_count=2,
            total_surface_count=4,
        ),
    )


def run_golden_benchmark(
    cases: Iterable[GoldenBenchmarkCase] | None = None,
) -> GoldenBenchmarkResult:
    """Evaluate only declared cases; this function performs no external I/O."""
    selected = tuple(cases) if cases is not None else default_golden_cases()
    if not selected:
        raise ValueError("at least one golden benchmark case is required")
    case_ids = [case.case_id for case in selected]
    if len(set(case_ids)) != len(case_ids):
        raise ValueError("golden benchmark case_id values must be unique")
    return GoldenBenchmarkResult(cases=selected)


__all__ = [
    "GoldenBenchmarkCase",
    "GoldenBenchmarkResult",
    "default_golden_cases",
    "run_golden_benchmark",
]
