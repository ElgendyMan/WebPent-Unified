"""Autonomous reviewer v3; a challenge layer, not a qualification authority."""

from __future__ import annotations

from .contracts import AutonomousSecurityAssessment, VulnerabilityReasoningReport


class AutonomousSecurityReviewerV3:
    """Review reasoning and evidence completeness with fail-closed dispositions."""

    def review(
        self,
        report: VulnerabilityReasoningReport,
        *,
        proof_bundle_complete: bool = False,
        replay_verified: bool = False,
        central_review_status: str = "not_run",
        impact_supported: bool = False,
    ) -> AutonomousSecurityAssessment:
        if not isinstance(report, VulnerabilityReasoningReport):
            raise TypeError("vulnerability_reasoning_report_required")
        validity = []
        evidence = []
        impact = []
        reasoning = []
        reproducibility = []
        if not report.hypothesis_id or not report.security_boundary:
            validity.append("security_boundary_or_hypothesis_missing")
        if not report.evidence_refs:
            evidence.append("evidence_refs_missing")
        if not report.causal_oracle_present:
            evidence.append("causal_oracle_missing")
        if not impact_supported:
            impact.append("impact_not_causally_supported")
        if not report.alternative_explanations:
            reasoning.append("alternative_explanation_not_recorded")
        if not proof_bundle_complete:
            reproducibility.append("sealed_proof_bundle_missing")
        if not replay_verified:
            reproducibility.append("replay_not_verified")
        challenges = validity + evidence + impact + reasoning + reproducibility
        status = "advisory_ready" if not challenges else "blocked"
        return AutonomousSecurityAssessment(
            engagement_id="advisory",
            target_id="advisory",
            hypothesis_id=report.hypothesis_id,
            validity_challenges=tuple(validity),
            evidence_challenges=tuple(evidence),
            impact_challenges=tuple(impact),
            reasoning_challenges=tuple(reasoning),
            reproducibility_challenges=tuple(reproducibility),
            status=status,
            central_review_status=str(central_review_status),
        )

    assess = review


AutonomousSecurityReviewer = AutonomousSecurityReviewerV3
ReviewerV3 = AutonomousSecurityReviewerV3

__all__ = ["AutonomousSecurityReviewer", "AutonomousSecurityReviewerV3", "ReviewerV3"]
