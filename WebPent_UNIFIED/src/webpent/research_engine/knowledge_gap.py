"""Knowledge-gap analysis for bounded autonomous research planning."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class KnowledgeGap(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    gap_id: str = Field(min_length=1, max_length=160)
    engagement_id: str = Field(min_length=1, max_length=160)
    target_id: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=400)
    required_evidence: tuple[str, ...] = Field(default=(), max_length=16)
    severity: float = Field(default=0.5, ge=0.0, le=1.0)
    resolved: bool = False


class KnowledgeGapEngine:
    """Pure planner that never performs network, browser, or tool operations."""

    @staticmethod
    def identify(
        *,
        engagement_id: str,
        target_id: str,
        has_target_backed_observation: bool = False,
        has_negative_control: bool = False,
        has_replayable_proof: bool = False,
        has_application_model: bool = False,
    ) -> tuple[KnowledgeGap, ...]:
        checks = (
            (
                "target_observation",
                "target-backed observation is missing",
                ("target_observation",),
                0.9,
                has_target_backed_observation,
            ),
            (
                "negative_control",
                "independent negative control is missing",
                ("negative_control",),
                0.95,
                has_negative_control,
            ),
            (
                "proof_replay",
                "sealed replayable proof is missing",
                ("sealed_replayable_proof",),
                1.0,
                has_replayable_proof,
            ),
            (
                "application_model",
                "application/entity/workflow model is incomplete",
                ("application_model",),
                0.6,
                has_application_model,
            ),
        )
        return tuple(
            KnowledgeGap(
                gap_id=f"{engagement_id}:{target_id}:{gap_id}",
                engagement_id=engagement_id,
                target_id=target_id,
                description=description,
                required_evidence=evidence,
                severity=severity,
            )
            for gap_id, description, evidence, severity, resolved in checks
            if not resolved
        )


__all__ = ["KnowledgeGap", "KnowledgeGapEngine"]
