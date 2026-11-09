"""Senior technical review without promotion authority."""

from __future__ import annotations

from .contracts import (
    Disposition,
    EvidenceAssessment,
    Hypothesis,
    SeniorSecurityReview,
)


class SeniorResearchReviewer:
    def review(
        self,
        *,
        target_ref: str,
        hypothesis: Hypothesis,
        evidence: EvidenceAssessment,
        real_boundary: bool,
        failed_assumption: bool,
        impact_demonstrated: bool,
    ) -> SeniorSecurityReview:
        challenges: list[str] = []
        if not real_boundary:
            challenges.append("real security boundary is not established")
        if not failed_assumption:
            challenges.append("failed assumption is not demonstrated")
        if not impact_demonstrated:
            challenges.append("impact is not demonstrated")
        if hypothesis.alternative_explanations:
            challenges.append("alternative explanations remain")
        if not evidence.strong_enough_for_confirmation:
            challenges.append("causal, negative-control, proof, and replay evidence is incomplete")
        complete = not challenges
        disposition = Disposition.ADVISORY if complete else Disposition.INSUFFICIENT
        return SeniorSecurityReview(
            target_ref=target_ref,
            hypothesis_id=hypothesis.hypothesis_id,
            real_boundary=real_boundary,
            failed_assumption=failed_assumption,
            impact_demonstrated=impact_demonstrated,
            evidence_complete=evidence.strong_enough_for_confirmation,
            alternative_explanation_exists=bool(hypothesis.alternative_explanations),
            disposition=disposition,
            challenges=tuple(challenges),
            no_finding_created=True,
            no_governance_override=True,
        )
