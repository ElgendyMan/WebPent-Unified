"""Advisory competition and senior review contracts for AVDE."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from webpent.avde.discovery import DiscoveryHypothesis
from webpent.avde.exploration import ValidationPlan
from webpent.models.evidence import redact_sensitive


class ReviewDecision(str, Enum):
    PROCEED_TO_VALIDATION = "proceed_to_validation"
    DEFER = "defer"
    BLOCK = "block"


class ReasoningReview(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    review_id: str = Field(min_length=16, max_length=128)
    hypothesis_id: str = Field(min_length=16, max_length=128)
    decision: ReviewDecision
    competing_explanations: tuple[str, ...] = Field(min_length=1, max_length=8)
    disproof_questions: tuple[str, ...] = Field(min_length=1, max_length=8)
    required_evidence: tuple[str, ...] = Field(min_length=1, max_length=8)
    rationale: str = Field(min_length=8, max_length=700)
    confidence: float = Field(ge=0.0, le=1.0)
    human_signoff: bool = False
    creates_finding: bool = False


class SeniorReasoningReviewer:
    """Apply a non-authoritative challenge review to one proposed plan."""

    def review(self, hypothesis: DiscoveryHypothesis, plan: ValidationPlan) -> ReasoningReview:
        if hypothesis.hypothesis_id != plan.hypothesis_id:
            raise ValueError("hypothesis_plan_mismatch")
        blocked = plan.decision == "blocked" or plan.risk == "blocked"
        decision = ReviewDecision.BLOCK if blocked else ReviewDecision.PROCEED_TO_VALIDATION
        if plan.decision == "deferred":
            decision = ReviewDecision.DEFER
        rationale = (
            "The proposed path is bounded and may proceed only to central validation; "
            "this review is not a finding, approval, or qualification decision."
            if not blocked
            else "The proposal lacks a valid bounded proof path and remains blocked."
        )
        payload = json.dumps(
            {"hypothesis": hypothesis.hypothesis_id, "plan": plan.model_dump(mode="json")},
            sort_keys=True,
            separators=(",", ":"),
        )
        return ReasoningReview(
            review_id=hashlib.sha256(payload.encode()).hexdigest(),
            hypothesis_id=hypothesis.hypothesis_id,
            decision=decision,
            competing_explanations=(
                "route or reachability is not equivalent to a security violation",
                "environmental or identity mismatch may explain the observation",
            ),
            disproof_questions=(
                "does the independent negative control remain protected?",
                "does the causal oracle distinguish candidate from control?",
            ),
            required_evidence=(
                *hypothesis.expected_evidence,
                "sealed and replayable proof references",
            ),
            rationale=redact_sensitive(rationale)[0],
            confidence=0.75 if not blocked else 0.0,
        )


class CompetitionRound(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    round_id: str = Field(min_length=16, max_length=128)
    hypothesis_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    winner_id: str | None = Field(default=None, max_length=128)
    budget: int = Field(ge=0, le=1000)
    rationale: str = Field(min_length=8, max_length=500)
    advisory_only: bool = True


class CompetitionLoop:
    """Select among hypotheses by evidence value under a deterministic budget."""

    def run(
        self,
        hypotheses: Iterable[DiscoveryHypothesis],
        *,
        budget: int = 100,
    ) -> CompetitionRound:
        items = tuple(hypotheses)
        if budget < 0:
            raise ValueError("budget_must_be_non_negative")
        winner = None
        if items and budget:
            winner = sorted(
                items, key=lambda item: (-item.confidence * item.novelty_score, item.hypothesis_id)
            )[0]
        payload = json.dumps(
            {"ids": sorted(item.hypothesis_id for item in items), "budget": budget},
            sort_keys=True,
            separators=(",", ":"),
        )
        return CompetitionRound(
            round_id=hashlib.sha256(payload.encode()).hexdigest(),
            hypothesis_ids=tuple(sorted(item.hypothesis_id for item in items)),
            winner_id=winner.hypothesis_id if winner else None,
            budget=budget,
            rationale=(
                "Winner is advisory and still requires causal oracle, independent control, "
                "central verification, and sealed replayable evidence."
            ),
        )


__all__ = [
    "CompetitionLoop",
    "CompetitionRound",
    "ReasoningReview",
    "ReviewDecision",
    "SeniorReasoningReviewer",
]
