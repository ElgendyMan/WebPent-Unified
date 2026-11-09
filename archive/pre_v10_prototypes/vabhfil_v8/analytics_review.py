"""Quality score and readiness review backed only by benchmark artifacts."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import (
    AutonomousResearchIntelligenceScoreV8,
    V8Status,
    VIPReadinessReportV8,
)


@dataclass(frozen=True, slots=True)
class AutonomousResearchQualityEvaluatorV8:
    def score(
        self,
        *,
        engagement_id: str,
        target_id: str,
        benchmark: dict[str, object],
        investigation_count: int = 0,
        hypothesis_count: int = 0,
        memory_lesson_count: int = 0,
    ) -> AutonomousResearchIntelligenceScoreV8:
        total = int(benchmark.get("registered_scenario_count", 0))
        scorable = int(benchmark.get("scorable_case_count", 0))
        valid = total > 0 and scorable == total and bool(benchmark.get("ground_truth_valid", False))
        if not valid:
            values = (None,) * 6
        else:
            depth = min(1.0, investigation_count / max(1, total * 2))
            values = (
                depth,
                min(1.0, hypothesis_count / max(1, total)),
                1.0,
                1.0,
                1.0,
                min(1.0, memory_lesson_count / max(1, total)),
            )
        return AutonomousResearchIntelligenceScoreV8(
            engagement_id=engagement_id,
            target_id=target_id,
            autonomy=values[0],
            reasoning_depth=values[1],
            evidence_quality=values[2],
            investigation_efficiency=values[3],
            adaptability=values[4],
            learning_improvement=values[5],
            benchmark_case_count=total,
            scorable_case_count=scorable,
            requests_sent=int(benchmark.get("requests_sent", 0)),
            valid_ground_truth=valid,
            real_world_detection_rate=None,
        )


@dataclass(frozen=True, slots=True)
class VIPArchitectureReadinessReviewerV8:
    def review(
        self,
        *,
        engagement_id: str,
        target_id: str,
        score: AutonomousResearchIntelligenceScoreV8,
        benchmark: dict[str, object],
    ) -> VIPReadinessReportV8:
        blockers = (
            "valid ground truth and complete causal evidence are unavailable",
            (
                "all benchmark results must remain blocked until realistic model, oracle, proof, "
                "and replay coexist"
            ),
            "P10/VIP authority requires governance outside this advisory component",
        )
        limitations = (
            "recorded-state reasoning is not equivalent to live detection",
            "no real-world detection rate is claimed",
            "benchmark runner sends zero requests",
        )
        return VIPReadinessReportV8(
            engagement_id=engagement_id,
            target_id=target_id,
            architecture="advisory layered architecture; central authorities remain external",
            autonomy="promising research orchestration; qualification unproven",
            research_intelligence=(
                "expert reasoning contracts implemented; measured quality unavailable"
            ),
            evidence_pipeline="fail-closed and evidence-aware; no complete proof set in this run",
            benchmark_quality="BLOCKED" if score.scorable_case_count == 0 else "ADVISORY",
            remaining_limitations=limitations,
            remaining_blockers=blockers,
            governance_status="P10 closed; VIP NOT_QUALIFIED; human signoff false",
            status=V8Status.BLOCKED,
        )


__all__ = ["AutonomousResearchQualityEvaluatorV8", "VIPArchitectureReadinessReviewerV8"]
