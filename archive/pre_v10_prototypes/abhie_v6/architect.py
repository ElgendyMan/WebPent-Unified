"""Advisory autonomous security architect review for ABHIE v6."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from webpent.asros.quality_controller import ResearchQualityController

from .contracts import ArchitectReviewReport, V6Status


class ArchitectReviewV6:
    """Challenge research quality while delegating authority to central gates."""

    VERSION = "abhie-architect-review-v6"

    def __init__(self, controller: ResearchQualityController | None = None) -> None:
        self.controller = controller or ResearchQualityController()

    def review(
        self,
        *,
        engagement_id: str,
        target_id: str,
        subject_id: str,
        hypothesis: Mapping[str, Any],
        argument_chain: Any | None = None,
        scope_allowed: bool = True,
        evidence_refs: Sequence[str] = (),
        causal_oracle_passed: bool = False,
        negative_control_passed: bool = False,
        proof_sealed: bool = False,
        proof_replayable: bool = False,
        observation_count: int = 0,
        claim: str = "",
    ) -> ArchitectReviewReport:
        before = self.controller.review_before(
            hypothesis=hypothesis,
            argument_chain=argument_chain,
            scope_allowed=scope_allowed,
        )
        after = self.controller.review_after(
            hypothesis_id=subject_id,
            evidence_refs=evidence_refs,
            causal_oracle_passed=causal_oracle_passed,
            negative_control_passed=negative_control_passed,
            proof_sealed=proof_sealed,
            proof_replayable=proof_replayable,
            claim=claim,
            observation_count=observation_count,
        )
        validity = tuple(
            issue.message
            for issue in before.issues
            if issue.code in {"reason_missing", "argument_chain_missing"}
        ) or ("assumption violation remains a hypothesis until causally validated",)
        evidence = tuple(
            issue.message
            for issue in after.issues
            if issue.code
            in {"evidence_refs_missing", "causal_proof_missing", "negative_control_missing"}
        ) or ("evidence must remain linked to redacted references",)
        impact = (
            "impact must be demonstrated by an approved oracle, not inferred from reachability",
        )
        alternatives = ("alternative explanations must be addressed before any conclusion",)
        reproducibility = tuple(
            issue.message
            for issue in after.issues
            if issue.code in {"proof_not_sealed", "proof_not_replayable"}
        ) or ("replay must be independently repeatable",)
        status = (
            V6Status.BLOCKED
            if after.status.value in {"blocked", "insufficient"}
            else V6Status.ADVISORY
        )
        return ArchitectReviewReport(
            engagement_id=str(engagement_id),
            target_id=str(target_id),
            subject_id=str(subject_id),
            validity_challenges=validity,
            evidence_challenges=evidence,
            impact_challenges=impact,
            alternative_challenges=alternatives,
            reproducibility_challenges=reproducibility,
            central_pre_status=before.status.value,
            central_post_status=after.status.value,
            status=status,
        )


__all__ = ["ArchitectReviewV6"]
