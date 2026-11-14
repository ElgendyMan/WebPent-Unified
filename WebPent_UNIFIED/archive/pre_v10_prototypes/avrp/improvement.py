"""Explainable, target-scoped research self-improvement for AVRP."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import canonical_json, redact_sensitive


def _text(value: Any, limit: int = 400) -> str:
    clean, _ = redact_sensitive(str(value or ""))
    return " ".join(clean.split())[:limit]


class ResearchOutcome(BaseModel):
    """A redacted, already-recorded outcome used for learning only."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    path_id: str = Field(min_length=3, max_length=160)
    target_ref: str = Field(min_length=3, max_length=300)
    engagement_ref: str = Field(min_length=3, max_length=160)
    outcome: Literal["successful", "failed", "blocked", "low_value"]
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=30)
    reason: str = Field(min_length=3, max_length=500)
    value_score: float = Field(ge=0.0, le=1.0)

    @field_validator("path_id", "target_ref", "engagement_ref", "reason", mode="before")
    @classmethod
    def _clean(cls, value: Any) -> str:
        return _text(value)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _refs(cls, value: Any) -> tuple[str, ...]:
        values: list[str] = []
        for item in value or ():
            clean = _text(item, 220)
            if clean and clean not in values:
                values.append(clean)
        return tuple(values[:30])


class PriorityWeightUpdate(BaseModel):
    """One explainable adjustment; it is not an execution or policy decision."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    update_id: str = Field(min_length=3, max_length=160)
    target_ref: str = Field(min_length=3, max_length=300)
    engagement_ref: str = Field(min_length=3, max_length=160)
    signal: str = Field(min_length=3, max_length=120)
    previous_weight: float = Field(ge=0.0, le=2.0)
    updated_weight: float = Field(ge=0.0, le=2.0)
    delta: float = Field(ge=-1.0, le=1.0)
    reason: str = Field(min_length=3, max_length=500)
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=30)
    hidden_state: bool = False
    advisory_only: bool = True

    @field_validator("update_id", "target_ref", "engagement_ref", "signal", "reason", mode="before")
    @classmethod
    def _clean(cls, value: Any) -> str:
        return _text(value)


class SelfImprovementReport(BaseModel):
    """A serializable learning report with explicit scope and updates."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    report_id: str = Field(min_length=3, max_length=160)
    target_ref: str = Field(min_length=3, max_length=300)
    engagement_ref: str = Field(min_length=3, max_length=160)
    analyzed_outcome_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=200)
    updates: tuple[PriorityWeightUpdate, ...] = Field(default_factory=tuple, max_length=100)
    high_value_evidence: tuple[str, ...] = Field(default_factory=tuple, max_length=100)
    rejected_cross_scope: int = Field(ge=0)
    advisory_only: bool = True


class ResearchSelfImprovement:
    """Learn deterministic priority deltas from explicit, same-scope outcomes."""

    _BASE_WEIGHTS = {
        "causal_evidence": 1.0,
        "novelty": 1.0,
        "coverage_gap": 1.0,
        "validation_cost": 1.0,
    }

    def learn(
        self,
        outcomes: Iterable[ResearchOutcome],
        *,
        target_ref: str,
        engagement_ref: str,
    ) -> SelfImprovementReport:
        target = _text(target_ref, 300)
        engagement = _text(engagement_ref, 160)
        if not target or not engagement:
            raise ValueError("target_ref and engagement_ref are required")
        accepted: list[ResearchOutcome] = []
        rejected = 0
        for outcome in tuple(outcomes):
            if not isinstance(outcome, ResearchOutcome):
                raise TypeError("outcomes must contain ResearchOutcome instances")
            if outcome.target_ref != target or outcome.engagement_ref != engagement:
                rejected += 1
                continue
            accepted.append(outcome)
        updates: list[PriorityWeightUpdate] = []
        evidence: list[str] = []
        for signal, delta, reason in self._derive_updates(accepted):
            previous = self._BASE_WEIGHTS[signal]
            updated = min(2.0, max(0.0, previous + delta))
            refs = tuple(
                ref
                for outcome in accepted
                if outcome.outcome in {"successful", "low_value"}
                for ref in outcome.evidence_refs
            )
            refs = tuple(dict.fromkeys(refs))[:30]
            payload = {
                "target_ref": target,
                "engagement_ref": engagement,
                "signal": signal,
                "delta": delta,
                "outcome_ids": sorted(item.path_id for item in accepted),
            }
            update_id = (
                "weight:" + hashlib.sha256(canonical_json(payload).encode()).hexdigest()[:24]
            )
            updates.append(
                PriorityWeightUpdate(
                    update_id=update_id,
                    target_ref=target,
                    engagement_ref=engagement,
                    signal=signal,
                    previous_weight=previous,
                    updated_weight=updated,
                    delta=updated - previous,
                    reason=reason,
                    evidence_refs=refs,
                )
            )
            evidence.extend(refs)
        report_payload = {
            "target_ref": target,
            "engagement_ref": engagement,
            "outcomes": sorted(item.path_id for item in accepted),
            "updates": [item.update_id for item in updates],
        }
        report_id = (
            "learning:" + hashlib.sha256(canonical_json(report_payload).encode()).hexdigest()[:24]
        )
        return SelfImprovementReport(
            report_id=report_id,
            target_ref=target,
            engagement_ref=engagement,
            analyzed_outcome_ids=tuple(item.path_id for item in accepted),
            updates=tuple(sorted(updates, key=lambda item: item.update_id)),
            high_value_evidence=tuple(dict.fromkeys(evidence))[:100],
            rejected_cross_scope=rejected,
        )

    def _derive_updates(
        self, outcomes: list[ResearchOutcome]
    ) -> tuple[tuple[str, float, str], ...]:
        if not outcomes:
            return ()
        successful = sum(item.outcome == "successful" for item in outcomes)
        failed = sum(item.outcome in {"failed", "blocked"} for item in outcomes)
        low_value = sum(item.outcome == "low_value" for item in outcomes)
        updates: list[tuple[str, float, str]] = []
        if successful:
            updates.append(
                (
                    "causal_evidence",
                    min(0.25, 0.05 * successful),
                    "Successful paths had recorded evidence.",
                )
            )
        if failed:
            updates.append(
                (
                    "coverage_gap",
                    min(0.25, 0.05 * failed),
                    "Failed or blocked paths indicate an unresolved coverage gap.",
                )
            )
        if low_value:
            updates.append(
                (
                    "validation_cost",
                    min(0.25, 0.05 * low_value),
                    "Low-value paths increase the cost-awareness weight.",
                )
            )
        if successful and not low_value:
            updates.append(
                ("novelty", 0.05, "Successful non-redundant paths support exploring novel areas.")
            )
        return tuple(updates)


__all__ = [
    "PriorityWeightUpdate",
    "ResearchOutcome",
    "ResearchSelfImprovement",
    "SelfImprovementReport",
]
