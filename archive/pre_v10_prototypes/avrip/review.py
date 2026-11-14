"""AVRIP v2 senior research review.

This is a technical quality assessment only.  It cannot approve a finding,
open a gate, create a proof bundle, or replace the central quality controller.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from webpent.avrip.evidence import EvidenceAssessment
from webpent.avrip.reasoning import DeepHypothesis


class ReviewDisposition(str, Enum):
    INSUFFICIENT = "insufficient"
    ADVISORY_READY = "advisory_ready"
    BLOCKED = "blocked"


class SeniorResearchAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: int = Field(default=2, frozen=True)
    hypothesis_id: str = Field(min_length=1, max_length=240)
    reasoning_valid: bool
    evidence_sufficient_for_review: bool
    alternative_explanations_reviewed: bool
    impact_assessment: str = Field(min_length=3, max_length=500)
    missing_controls: tuple[str, ...] = Field(default=(), max_length=16)
    disposition: ReviewDisposition
    creates_finding: bool = False
    grants_signoff: bool = False
    changes_qualification: bool = False
    execution_capability: bool = False
    reviewer_role: str = "ai_technical_review_non_human"


class SeniorResearchReviewerV2:
    """Apply conservative review gates to a hypothesis and its actual evidence."""

    def assess(
        self,
        *,
        hypothesis: DeepHypothesis,
        evidence: EvidenceAssessment,
        alternative_explanations: Iterable[str] = (),
        central_review_passed: bool = False,
    ) -> SeniorResearchAssessment:
        if not isinstance(hypothesis, DeepHypothesis):
            raise TypeError("deep_hypothesis_required")
        if evidence.hypothesis_id != hypothesis.hypothesis_id:
            raise ValueError("review_evidence_hypothesis_mismatch")
        alternatives = tuple(
            str(item).strip() for item in alternative_explanations if str(item).strip()
        )
        reasoning_valid = (
            hypothesis.status == "potential"
            and len(hypothesis.reasoning_chain) == 5
            and bool(hypothesis.validation_strategy)
        )
        complete_evidence = not evidence.missing_requirements and not evidence.conflicts
        controls = tuple(
            dict.fromkeys(
                (
                    *evidence.missing_requirements,
                    "central_quality_review" if not central_review_passed else "",
                )
            )
        )
        missing = tuple(item for item in controls if item)
        sufficient = bool(reasoning_valid and complete_evidence and central_review_passed)
        disposition = (
            ReviewDisposition.ADVISORY_READY if sufficient else ReviewDisposition.INSUFFICIENT
        )
        return SeniorResearchAssessment(
            hypothesis_id=hypothesis.hypothesis_id,
            reasoning_valid=reasoning_valid,
            evidence_sufficient_for_review=complete_evidence,
            alternative_explanations_reviewed=bool(alternatives),
            impact_assessment=(
                "Potential impact is documented but remains unconfirmed; central validation "
                "and independent controls are still required."
            ),
            missing_controls=missing,
            disposition=disposition,
        )


__all__ = [
    "ReviewDisposition",
    "SeniorResearchAssessment",
    "SeniorResearchReviewerV2",
]
