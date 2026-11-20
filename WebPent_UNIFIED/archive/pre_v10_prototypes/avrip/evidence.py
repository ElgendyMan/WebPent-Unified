"""AVRIP v2 evidence intelligence and contradiction analysis."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class EvidencePolarity(str, Enum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    NEUTRAL = "neutral"


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    evidence_id: str = Field(min_length=1, max_length=240)
    hypothesis_id: str = Field(min_length=1, max_length=240)
    source_ref: str = Field(min_length=1, max_length=320)
    description: str = Field(min_length=3, max_length=700)
    polarity: EvidencePolarity
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    causal_signal: bool = False
    independent_control: bool = False
    proof_bundle_sealed: bool = False
    replay_verified: bool = False
    observed: bool = True


class EvidenceConflict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    conflict_id: str = Field(min_length=1, max_length=240)
    evidence_ids: tuple[str, ...] = Field(min_length=2, max_length=16)
    reason: str = Field(min_length=8, max_length=500)
    resolution_required: str = Field(min_length=8, max_length=500)


class EvidenceAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: int = Field(default=2, frozen=True)
    hypothesis_id: str = Field(min_length=1, max_length=240)
    observed_item_count: int = Field(default=0, ge=0)
    supporting_count: int = Field(default=0, ge=0)
    contradicting_count: int = Field(default=0, ge=0)
    neutral_count: int = Field(default=0, ge=0)
    conflicts: tuple[EvidenceConflict, ...] = Field(default=(), max_length=64)
    missing_requirements: tuple[str, ...] = Field(default=(), max_length=16)
    consistency_score: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_strength: float = Field(default=0.0, ge=0.0, le=1.0)
    interpretation: str = Field(pattern="^(supporting|contradictory|mixed|insufficient)$")
    advisory_only: bool = True


class EvidenceIntelligenceV2:
    """Assess evidence supplied by the caller; never fabricate missing evidence."""

    def assess(
        self,
        *,
        hypothesis_id: str,
        items: Iterable[EvidenceItem],
    ) -> EvidenceAssessment:
        supplied = tuple(items)
        if any(item.hypothesis_id != hypothesis_id for item in supplied):
            raise ValueError("evidence_hypothesis_scope_mismatch")
        ordered = tuple(item for item in supplied if item.hypothesis_id == hypothesis_id)
        supporting = sum(item.polarity == EvidencePolarity.SUPPORTS for item in ordered)
        contradicting = sum(item.polarity == EvidencePolarity.CONTRADICTS for item in ordered)
        neutral = sum(item.polarity == EvidencePolarity.NEUTRAL for item in ordered)
        conflicts = self._conflicts(ordered)
        missing: list[str] = []
        if not ordered:
            missing.append("candidate_observation")
        if not any(item.causal_signal for item in ordered):
            missing.append("causal_signal")
        if not any(item.independent_control for item in ordered):
            missing.append("independent_negative_control")
        if not any(item.proof_bundle_sealed for item in ordered):
            missing.append("sealed_proof_bundle")
        if not any(item.replay_verified for item in ordered):
            missing.append("replay_verification")
        confidence = sum(item.confidence for item in ordered) / len(ordered) if ordered else 0.0
        consistency = max(0.0, 1.0 - min(len(conflicts) * 0.25, 1.0))
        strength = round(max(0.0, min(1.0, confidence * consistency)), 3)
        if not ordered or (supporting == 0 and contradicting == 0):
            interpretation = "insufficient"
        elif supporting and contradicting:
            interpretation = "mixed"
        elif supporting:
            interpretation = "supporting"
        else:
            interpretation = "contradictory"
        return EvidenceAssessment(
            hypothesis_id=hypothesis_id,
            observed_item_count=len(ordered),
            supporting_count=supporting,
            contradicting_count=contradicting,
            neutral_count=neutral,
            conflicts=conflicts,
            missing_requirements=tuple(missing),
            consistency_score=round(consistency, 3),
            evidence_strength=strength,
            interpretation=interpretation,
        )

    @staticmethod
    def _conflicts(items: tuple[EvidenceItem, ...]) -> tuple[EvidenceConflict, ...]:
        by_source: dict[str, list[EvidenceItem]] = {}
        for item in items:
            by_source.setdefault(item.source_ref, []).append(item)
        conflicts: list[EvidenceConflict] = []
        for source_ref in sorted(by_source):
            group = by_source[source_ref]
            polarities = {item.polarity for item in group}
            if (
                EvidencePolarity.SUPPORTS in polarities
                and EvidencePolarity.CONTRADICTS in polarities
            ):
                ids = tuple(item.evidence_id for item in group)
                conflicts.append(
                    EvidenceConflict(
                        conflict_id=f"conflict:{hashlib.sha256(source_ref.encode()).hexdigest()[:20]}",
                        evidence_ids=ids[:16],
                        reason=f"Source {source_ref} has incompatible evidence polarities.",
                        resolution_required=(
                            "Reconcile the source with an independent observation "
                            "and causal oracle."
                        ),
                    )
                )
        return tuple(conflicts)


__all__ = [
    "EvidenceAssessment",
    "EvidenceConflict",
    "EvidenceIntelligenceV2",
    "EvidenceItem",
    "EvidencePolarity",
]
