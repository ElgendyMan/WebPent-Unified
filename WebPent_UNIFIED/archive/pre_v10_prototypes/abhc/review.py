"""Senior technical review for ABHC v3."""

from __future__ import annotations

from collections.abc import Sequence
from hashlib import sha256

from .contracts import (
    AdvisoryDisposition,
    AutonomousResearchReviewReport,
    BoundaryCandidate,
    EvolvingHypothesis,
    ExperimentPlan,
    FindingConfidenceReport,
    PotentialAttackChain,
    ResearchMission,
)


class AutonomousResearchReview:
    """Challenge autonomous research output; it has no promotion authority."""

    def review(
        self,
        *,
        missions: Sequence[ResearchMission],
        hypotheses: Sequence[EvolvingHypothesis],
        boundaries: Sequence[BoundaryCandidate],
        experiments: Sequence[ExperimentPlan],
        chains: Sequence[PotentialAttackChain],
        quality_reports: Sequence[FindingConfidenceReport],
    ) -> AutonomousResearchReviewReport:
        challenges: list[str] = []
        if not missions:
            challenges.append("no_research_missions")
        if not hypotheses:
            challenges.append("no_hypotheses")
        if not boundaries:
            challenges.append("no_security_boundaries")
        if not experiments:
            challenges.append("no_experiment_plans")
        if any(plan.selected and plan.blocked_reason for plan in experiments):
            challenges.append("blocked_experiment_selected")
        complete = sum(1 for report in quality_reports if report.confidence_justified)
        if complete == 0:
            challenges.append("no_quality_report_meets_complete_evidence_bar")
        if any(not chain.required_validation for chain in chains):
            challenges.append("chain_validation_requirements_missing")
        disposition = (
            AdvisoryDisposition.ADVISORY_CANDIDATE
            if not challenges
            else AdvisoryDisposition.INSUFFICIENT_EVIDENCE
        )
        if not hypotheses or not boundaries:
            disposition = AdvisoryDisposition.BLOCKED
        review_material = (
            "|".join(item.mission_id for item in missions)
            + "|"
            + "|".join(item.hypothesis_id for item in hypotheses)
        )
        review_id = "review:" + sha256(review_material.encode()).hexdigest()[:16]
        return AutonomousResearchReviewReport(
            review_id=review_id,
            hypothesis_count=len(hypotheses),
            boundary_count=len(boundaries),
            chain_count=len(chains),
            evidence_complete_count=complete,
            challenged_count=len(challenges),
            disposition=disposition,
            challenges=tuple(challenges),
        )


__all__ = ["AutonomousResearchReview"]
