"""Bounded, passive business-logic abuse-case proposals."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from webpent.models.workflows import BusinessLogicHypothesisSpec, WorkflowObservation
from webpent.shared.workflow_understanding import generate_business_logic_hypotheses


class AbuseCaseProposal(BaseModel):
    """A proposal for a separately authorized investigation, never a finding."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    fingerprint: str = Field(..., min_length=8, max_length=128)
    target_id: str = Field(..., min_length=1, max_length=200)
    engagement_id: str = Field(..., min_length=1, max_length=200)
    hypothesis: BusinessLogicHypothesisSpec
    required_controls: list[str] = Field(
        default_factory=lambda: [
            "scope_compiler_and_action_authority",
            "target_backed_causal_signal",
            "independent_negative_control",
            "central_sealed_replayable_proof_bundle",
        ],
        max_length=8,
    )
    promotion_status: str = "candidate_only"


class AbuseCaseGenerator:
    """Convert canonical workflow hypotheses into safe review proposals."""

    def generate(
        self,
        observations: Iterable[WorkflowObservation],
        *,
        target_id: str,
        engagement_id: str,
        target_url: str,
    ) -> list[AbuseCaseProposal]:
        target_id = target_id.strip()
        engagement_id = engagement_id.strip()
        target_url = target_url.strip()
        if not target_id or not engagement_id or not target_url:
            raise ValueError("target_and_engagement_context_required")
        hypotheses = generate_business_logic_hypotheses(
            list(observations),
            target_url=target_url,
        )
        proposals: list[AbuseCaseProposal] = []
        for hypothesis in hypotheses[:256]:
            proposals.append(
                AbuseCaseProposal(
                    fingerprint=hypothesis.fingerprint,
                    target_id=target_id,
                    engagement_id=engagement_id,
                    hypothesis=hypothesis,
                )
            )
        return proposals


__all__ = ["AbuseCaseGenerator", "AbuseCaseProposal"]
