"""Deterministic strategy adaptation for bounded ASROS campaigns.

The engine consumes redacted outcomes and emits advisory planning changes.  It
never performs I/O, overrides policy, promotes hypotheses, or creates findings.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ResearchDirection(str, Enum):
    ENDPOINT = "endpoint"
    WORKFLOW = "workflow"
    RELATIONSHIP = "relationship"
    TRUST_BOUNDARY = "trust_boundary"
    EVIDENCE = "evidence"


class OutcomeKind(str, Enum):
    EVIDENCE = "evidence"
    NO_EVIDENCE = "no_evidence"
    BLOCKED = "blocked"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class ResearchOutcome(BaseModel):
    """Redacted feedback from one bounded task."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    task_id: str = Field(min_length=1, max_length=200)
    hypothesis_id: str = Field(min_length=1, max_length=200)
    direction: ResearchDirection
    outcome: OutcomeKind
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    cost: float = Field(default=0.0, ge=0.0, le=1_000_000.0)
    reason: str = Field(default="", max_length=320)

    @field_validator("evidence_refs")
    @classmethod
    def _refs_are_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(str(value).strip()[:240] for value in values if str(value).strip())
        )


class StrategyDecision(BaseModel):
    """Advisory strategy update with explicit adaptation rationale."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    current_direction: ResearchDirection
    next_directions: tuple[ResearchDirection, ...] = Field(default=(), max_length=5)
    priority_multiplier: float = Field(default=1.0, ge=0.0, le=1.0)
    repeated_failure_count: int = Field(default=0, ge=0, le=100_000)
    low_value_count: int = Field(default=0, ge=0, le=100_000)
    rationale: str = Field(min_length=3, max_length=600)
    rejected: bool = False
    advisory_only: bool = True

    @model_validator(mode="after")
    def _cannot_be_authoritative(self) -> StrategyDecision:
        if not self.advisory_only:
            raise ValueError("strategy_decision_must_be_advisory")
        return self


class AdaptiveStrategyEngine:
    """Update strategy from bounded outcomes without executing the next step."""

    _fallbacks = {
        ResearchDirection.ENDPOINT: (
            ResearchDirection.WORKFLOW,
            ResearchDirection.RELATIONSHIP,
            ResearchDirection.TRUST_BOUNDARY,
        ),
        ResearchDirection.WORKFLOW: (
            ResearchDirection.RELATIONSHIP,
            ResearchDirection.TRUST_BOUNDARY,
            ResearchDirection.EVIDENCE,
        ),
        ResearchDirection.RELATIONSHIP: (
            ResearchDirection.TRUST_BOUNDARY,
            ResearchDirection.WORKFLOW,
            ResearchDirection.EVIDENCE,
        ),
        ResearchDirection.TRUST_BOUNDARY: (
            ResearchDirection.RELATIONSHIP,
            ResearchDirection.WORKFLOW,
            ResearchDirection.EVIDENCE,
        ),
        ResearchDirection.EVIDENCE: (
            ResearchDirection.WORKFLOW,
            ResearchDirection.RELATIONSHIP,
            ResearchDirection.ENDPOINT,
        ),
    }

    def decide(
        self,
        *,
        current_direction: ResearchDirection,
        outcomes: tuple[ResearchOutcome, ...] | list[ResearchOutcome] = (),
        hypothesis_failures: int = 0,
        failure_threshold: int = 2,
    ) -> StrategyDecision:
        if hypothesis_failures < 0 or failure_threshold < 1:
            raise ValueError("invalid_strategy_failure_count")
        ordered = tuple(outcomes)
        low_value = sum(
            1
            for item in ordered
            if item.outcome in {OutcomeKind.NO_EVIDENCE, OutcomeKind.INCONCLUSIVE}
        )
        repeated_failures = hypothesis_failures + sum(
            1 for item in ordered if item.outcome in {OutcomeKind.FAILED, OutcomeKind.BLOCKED}
        )
        evidence_count = sum(1 for item in ordered if item.outcome == OutcomeKind.EVIDENCE)
        should_change = low_value > 0 or repeated_failures >= failure_threshold
        next_directions = (
            self._fallbacks[current_direction] if should_change else (current_direction,)
        )
        multiplier = 1.0
        if repeated_failures >= failure_threshold:
            multiplier = max(0.1, round(1.0 - 0.2 * repeated_failures, 3))
        elif low_value:
            multiplier = max(0.5, round(1.0 - 0.1 * low_value, 3))
        rejected = repeated_failures >= failure_threshold * 2 and evidence_count == 0
        rationale = self._rationale(
            current_direction=current_direction,
            low_value=low_value,
            repeated_failures=repeated_failures,
            evidence_count=evidence_count,
            rejected=rejected,
        )
        return StrategyDecision(
            current_direction=current_direction,
            next_directions=next_directions,
            priority_multiplier=multiplier,
            repeated_failure_count=repeated_failures,
            low_value_count=low_value,
            rationale=rationale,
            rejected=rejected,
        )

    @staticmethod
    def _rationale(
        *,
        current_direction: ResearchDirection,
        low_value: int,
        repeated_failures: int,
        evidence_count: int,
        rejected: bool,
    ) -> str:
        if rejected:
            return (
                f"Hypothesis path in {current_direction.value} is repeatedly unsuccessful; "
                "deprioritize and require a materially different validation path."
            )
        if low_value:
            return (
                f"{low_value} low-value outcome(s) in {current_direction.value}; "
                "shift toward workflow, relationship, or trust-boundary analysis."
            )
        if repeated_failures:
            return (
                f"{repeated_failures} blocked/failed outcome(s); reduce priority and "
                "re-check preconditions before any future bounded task."
            )
        return (
            f"Retain {current_direction.value}; {evidence_count} evidence-backed "
            "outcome(s) are available."
        )


__all__ = [
    "AdaptiveStrategyEngine",
    "OutcomeKind",
    "ResearchDirection",
    "ResearchOutcome",
    "StrategyDecision",
]
