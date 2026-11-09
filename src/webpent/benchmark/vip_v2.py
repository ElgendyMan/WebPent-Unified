"""Offline VIP v2 qualification helpers.

This module measures supplied deterministic runs only. It never contacts a
lab, invents ground truth, or treats candidate evidence as confirmation.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from webpent.benchmark.metrics import BenchmarkReport, evaluate
from webpent.benchmark.qualification import (
    OfflineQualificationResult,
    QualificationFixture,
    QualificationRun,
    run_offline_qualification,
)


@dataclass(frozen=True)
class VIPV2Metrics:
    """Explicit offline discovery/proof/replay metrics."""

    benchmark: BenchmarkReport
    proof_rate: float
    replay_success_rate: float
    deterministic_runs: bool
    independent_run_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            **self.benchmark.as_dict(),
            "proof_rate": self.proof_rate,
            "replay_success_rate": self.replay_success_rate,
            "deterministic_runs": self.deterministic_runs,
            "independent_run_count": self.independent_run_count,
        }


def qualify_vip_v2(
    fixtures: Iterable[QualificationFixture],
    runner: Callable[[QualificationFixture, int], QualificationRun],
    *,
    repetitions: int = 3,
) -> OfflineQualificationResult:
    """Run a caller-supplied offline fixture runner at least three times."""
    if int(repetitions) < 3:
        raise ValueError("vip_v2_requires_at_least_three_repetitions")
    return run_offline_qualification(fixtures, runner, repetitions=int(repetitions))


def measure_vip_v2(
    result: OfflineQualificationResult,
    *,
    expected_case_ids: Iterable[str],
    negative_case_ids: Iterable[str] = (),
    total_surface_count: int = 0,
    tested_surface_count: int = 0,
    evidence_complete: Mapping[str, bool] | None = None,
) -> VIPV2Metrics:
    """Compute discovery and proof/replay rates from an existing result."""
    runs = result.matrix.runs
    candidate = {case_id for run in runs for case_id in run.candidate_case_ids}
    confirmed = {case_id for run in runs for case_id in run.confirmed_case_ids}
    proof = {case_id for run in runs for case_id in run.proof_case_ids}
    replay = {case_id for run in runs for case_id in run.replay_case_ids}
    benchmark = evaluate(
        candidate,
        expected_case_ids,
        evidence_complete=evidence_complete,
        tested_surface_count=tested_surface_count,
        total_surface_count=total_surface_count,
        independent_runs=(run.candidate_case_ids for run in runs),
        negative_case_ids=negative_case_ids,
    )
    confirmed_count = len(confirmed)
    proof_rate = len(proof) / confirmed_count if confirmed_count else 0.0
    replay_success_rate = len(proof & replay) / len(proof) if proof else 0.0
    return VIPV2Metrics(
        benchmark=benchmark,
        proof_rate=round(proof_rate, 6),
        replay_success_rate=round(replay_success_rate, 6),
        deterministic_runs=result.reproducible,
        independent_run_count=len(runs),
    )


__all__ = ["VIPV2Metrics", "measure_vip_v2", "qualify_vip_v2"]
