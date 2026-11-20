"""Deterministic confidence signals for planning and triage only."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ConfidenceSignals(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_quality: float = Field(default=0.0, ge=0.0, le=1.0)
    reproducibility: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_completeness: float = Field(default=0.0, ge=0.0, le=1.0)
    negative_control: float = Field(default=0.0, ge=0.0, le=1.0)
    causal_signal: float = Field(default=0.0, ge=0.0, le=1.0)


class ConfidenceAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    score: float = Field(ge=0.0, le=1.0)
    tier: str = Field(pattern="^(unexplored|candidate|supported|verified_pending_bundle)$")
    promotion_allowed: bool = False
    reason: str = Field(min_length=1, max_length=240)


def assess_confidence(signals: ConfidenceSignals) -> ConfidenceAssessment:
    """Score evidence while keeping central ProofBundle promotion authoritative."""
    score = round(
        0.20 * signals.source_quality
        + 0.20 * signals.reproducibility
        + 0.20 * signals.evidence_completeness
        + 0.20 * signals.negative_control
        + 0.20 * signals.causal_signal,
        4,
    )
    if (
        signals.causal_signal >= 1
        and signals.negative_control >= 1
        and signals.reproducibility >= 1
    ):
        return ConfidenceAssessment(
            score=score,
            tier="verified_pending_bundle",
            promotion_allowed=False,
            reason="central_sealed_replayable_bundle_required",
        )
    if score >= 0.6:
        return ConfidenceAssessment(score=score, tier="supported", reason="research_support_only")
    if score > 0:
        return ConfidenceAssessment(
            score=score, tier="candidate", reason="insufficient_verified_evidence"
        )
    return ConfidenceAssessment(score=0.0, tier="unexplored", reason="no_evidence_signals")


__all__ = ["ConfidenceAssessment", "ConfidenceSignals", "assess_confidence"]
