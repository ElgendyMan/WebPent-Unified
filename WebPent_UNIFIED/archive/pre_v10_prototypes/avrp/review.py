"""Advanced research quality review with no promotion authority."""

from __future__ import annotations

import hashlib
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.asros.quality_controller import PostExecutionReview, QualityReviewStatus
from webpent.avrp.chains import AttackChainHypothesis
from webpent.models.evidence import canonical_json, redact_sensitive


def _clean(value: Any, limit: int = 500) -> str:
    clean, _ = redact_sensitive(str(value or ""))
    return " ".join(clean.split())[:limit]


class ResearchQualityReview(BaseModel):
    """Review result; it is not a finding, signoff, or qualification decision."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    review_id: str = Field(min_length=3, max_length=160)
    chain_id: str = Field(min_length=3, max_length=160)
    clear_security_boundary: bool
    causal_evidence_present: bool
    alternatives_eliminated: bool
    impact_demonstrated: bool
    reproducible: bool
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=50)
    missing_requirements: tuple[str, ...] = Field(default_factory=tuple, max_length=20)
    status: Literal["advisory_ready", "blocked"]
    finding_created: bool = False
    oracle_overridden: bool = False
    policy_overridden: bool = False
    human_signoff: bool = False
    qualification_effect: bool = False

    @field_validator("review_id", "chain_id", "status", mode="before")
    @classmethod
    def _text(cls, value: Any) -> str:
        return _clean(value, 180)

    @field_validator("evidence_refs", "missing_requirements", mode="before")
    @classmethod
    def _items(cls, value: Any) -> tuple[str, ...]:
        result: list[str] = []
        for item in value or ():
            clean = _clean(item, 260)
            if clean and clean not in result:
                result.append(clean)
        return tuple(result)


class AdvancedResearchQualityReviewer:
    """Apply explicit evidence checks without any promotion authority."""

    def review(
        self,
        chain: AttackChainHypothesis,
        *,
        post_execution_review: PostExecutionReview | None = None,
    ) -> ResearchQualityReview:
        if not isinstance(chain, AttackChainHypothesis):
            raise TypeError("chain must be an AttackChainHypothesis")
        checks = {
            "clear_security_boundary": bool(chain.privilege_boundary.strip()),
            "causal_evidence_present": bool(chain.source_refs) and chain.status != "blocked",
            "alternatives_eliminated": False,
            "impact_demonstrated": False,
            "reproducible": False,
        }
        evidence_refs = chain.source_refs
        if post_execution_review is not None:
            if post_execution_review.hypothesis_id not in {
                chain.chain_id,
                chain.chain_id.removeprefix("chain:"),
            }:
                raise ValueError("post review hypothesis scope mismatch")
            checks["causal_evidence_present"] = (
                post_execution_review.causal_proof_present
                and post_execution_review.negative_control_present
            )
            checks["alternatives_eliminated"] = post_execution_review.negative_control_present
            checks["impact_demonstrated"] = post_execution_review.causal_proof_present
            checks["reproducible"] = (
                post_execution_review.proof_sealed
                and post_execution_review.proof_replayable
                and post_execution_review.status == QualityReviewStatus.ACCEPTED_FOR_REVIEW
            )
            evidence_refs = tuple(
                dict.fromkeys((*chain.source_refs, *post_execution_review.evidence_refs))
            )
        missing = tuple(name for name, passed in checks.items() if not passed)
        payload = {
            "chain_id": chain.chain_id,
            "checks": checks,
            "evidence_refs": sorted(evidence_refs),
        }
        review_id = "review:" + hashlib.sha256(canonical_json(payload).encode()).hexdigest()[:24]
        return ResearchQualityReview(
            review_id=review_id,
            chain_id=chain.chain_id,
            **checks,
            evidence_refs=evidence_refs,
            missing_requirements=missing,
            status="advisory_ready" if not missing else "blocked",
        )


__all__ = ["AdvancedResearchQualityReviewer", "ResearchQualityReview"]
