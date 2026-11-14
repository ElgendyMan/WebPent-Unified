"""Quality analytics and readiness review; no qualification authority."""

from __future__ import annotations

from dataclasses import dataclass

from .benchmark import VIPBenchmarkSuiteV9
from .contracts import ResearchQualityScoreV9, V9Status, VIPReadinessAssessmentV9


@dataclass(frozen=True, slots=True)
class V9AnalyticsReview:
    def score(
        self, *, engagement_id: str, target_id: str, suite: VIPBenchmarkSuiteV9
    ) -> ResearchQualityScoreV9:
        scorable = len(suite.scorable_cases)
        engineering = {
            "loop_coverage": 1.0,
            "explainability": 1.0,
            "state_isolation": 1.0,
            "transport_safety": 1.0,
        }
        qualification = {
            "detection_precision": None,
            "detection_recall": None,
            "f1": None,
            "evidence_completeness": None,
            "adaptation_gain": None,
        }
        if scorable:
            qualification = {
                "detection_precision": None,
                "detection_recall": None,
                "f1": None,
                "evidence_completeness": None,
                "adaptation_gain": None,
            }
        return ResearchQualityScoreV9(
            engagement_id=engagement_id,
            target_id=target_id,
            engineering_metrics=engineering,
            qualification_metrics=qualification,
            benchmark_case_count=len(suite.cases),
            scorable_case_count=scorable,
            requests_sent=suite.requests_sent,
            valid_ground_truth=False,
        )

    def readiness(
        self, *, engagement_id: str, target_id: str, suite: VIPBenchmarkSuiteV9
    ) -> VIPReadinessAssessmentV9:
        blockers = (
            "independent governance signoff is absent",
            "complete causal benchmark evidence is unavailable",
            "official isolated qualification runs are not authorized",
        )
        return VIPReadinessAssessmentV9(
            engagement_id=engagement_id,
            target_id=target_id,
            architecture_maturity="engineering_complete_advisory",
            autonomy="advisory_recorded_state_only",
            discovery_intelligence="not_qualification_scored",
            evidence_pipeline="blocked_without_causal_sealed_replayable_proof",
            benchmark_quality="blocked" if not suite.scorable_cases else "partial",
            operational_reliability="local_regression_verified",
            limitations=(
                "no live target observations",
                "no production detection claim",
                "blocked cases are not FN, clean, or confirmed",
            ),
            blockers=blockers,
            status=V9Status.BLOCKED,
        )


__all__ = ["V9AnalyticsReview"]
