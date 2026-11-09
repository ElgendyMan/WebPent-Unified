"""Additive hypothesis management facade over the existing safe lifecycle."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from webpent.models.findings import VulnClass
from webpent.models.hypothesis import Hypothesis, HypothesisOrigin, HypothesisStatus
from webpent.research.hypothesis_engine import HypothesisEngine, TransitionResult


class HypothesisDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    target_id: str = Field(min_length=1, max_length=160)
    vulnerability_class: str = Field(min_length=1, max_length=120)
    reasoning: str = Field(min_length=1, max_length=1_000)
    evidence_needed: tuple[str, ...] = Field(default=(), max_length=16)
    validation_method: str = Field(min_length=1, max_length=240)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class HypothesisManager:
    """Create and transition hypotheses without executing validation actions."""

    def create(
        self, draft: HypothesisDraft, *, engagement_id: str, hypothesis_id: str
    ) -> Hypothesis:
        try:
            vuln_class = VulnClass(draft.vulnerability_class.lower())
        except ValueError:
            vuln_class = VulnClass.UNKNOWN
        evidence_hint = ", ".join(draft.evidence_needed)[:500]
        detail = f"engagement={engagement_id}; validation={draft.validation_method}"
        if evidence_hint:
            detail += f"; evidence_needed={evidence_hint}"
        return Hypothesis(
            id=hypothesis_id,
            target_url=draft.target_id,
            statement=draft.reasoning,
            vuln_class=vuln_class,
            status=HypothesisStatus.UNEXPLORED,
            confidence_score=draft.confidence,
            origin=HypothesisOrigin.HEURISTIC,
            origin_detail=detail,
        )

    def transition(
        self,
        hypothesis: Hypothesis | dict[str, Any],
        target_status: HypothesisStatus | str,
        *,
        reason: str,
        evidence_refs: tuple[str, ...] = (),
    ) -> TransitionResult:
        return HypothesisEngine.transition(
            hypothesis,
            target_status,
            reason=reason,
            evidence_refs=evidence_refs,
        )

    def record_observation(
        self, hypothesis: Hypothesis | dict[str, Any], observation: dict[str, Any]
    ) -> TransitionResult:
        return HypothesisEngine.record_experiment(hypothesis, observation)


__all__ = ["HypothesisDraft", "HypothesisManager"]
