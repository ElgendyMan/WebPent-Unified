"""AVRIP v2 deterministic adaptive research strategy optimizer."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from webpent.asros.adaptive_strategy import (
    AdaptiveStrategyEngine,
    OutcomeKind,
    ResearchDirection,
    ResearchOutcome,
    StrategyDecision,
)


class StrategyOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"


class StrategyObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    strategy_id: str = Field(min_length=1, max_length=200)
    direction: ResearchDirection
    outcome: StrategyOutcome
    cost: float = Field(default=0.0, ge=0.0, le=1_000_000.0)
    evidence_quality: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    reason: str = Field(default="", max_length=320)


class StrategyPriority(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    strategy_id: str = Field(min_length=1, max_length=200)
    direction: ResearchDirection
    priority: float = Field(ge=0.0, le=1.0)
    basis: tuple[str, ...] = Field(min_length=1, max_length=8)


class StrategyOptimizationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: int = Field(default=2, frozen=True)
    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    priorities: tuple[StrategyPriority, ...] = Field(default=(), max_length=256)
    decision: StrategyDecision
    learned_observation_count: int = Field(default=0, ge=0)
    deterministic_basis_hash: str = Field(min_length=16, max_length=128)
    advisory_only: bool = True


class ResearchStrategyOptimizerV2:
    """Compute explainable priorities from caller-supplied redacted outcomes."""

    def optimize(
        self,
        *,
        engagement_id: str,
        target_id: str,
        current_direction: ResearchDirection,
        observations: Iterable[StrategyObservation] = (),
        candidate_strategies: Iterable[tuple[str, ResearchDirection]] = (),
    ) -> StrategyOptimizationReport:
        observed = tuple(observations)
        if any(
            item.engagement_id != engagement_id or item.target_id != target_id for item in observed
        ):
            raise ValueError("strategy_observation_scope_mismatch")
        candidates = tuple(candidate_strategies)
        outcome_records = tuple(self._to_research_outcome(item) for item in observed)
        failures = sum(
            1
            for item in observed
            if item.outcome in {StrategyOutcome.FAILURE, StrategyOutcome.BLOCKED}
        )
        engine = AdaptiveStrategyEngine()
        decision = engine.decide(
            current_direction=current_direction,
            outcomes=outcome_records,
            hypothesis_failures=failures,
        )
        priorities = tuple(
            self._priority(strategy_id, direction, observed, decision)
            for strategy_id, direction in sorted(
                candidates, key=lambda item: (item[0], item[1].value)
            )
        )
        import json

        basis = {
            "scope": [engagement_id, target_id],
            "observations": [item.model_dump(mode="json") for item in observed],
            "candidates": [(key, direction.value) for key, direction in candidates],
        }
        basis_hash = hashlib.sha256(
            json.dumps(basis, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return StrategyOptimizationReport(
            engagement_id=engagement_id,
            target_id=target_id,
            priorities=priorities,
            decision=decision,
            learned_observation_count=len(observed),
            deterministic_basis_hash=basis_hash,
        )

    @staticmethod
    def _to_research_outcome(item: StrategyObservation) -> ResearchOutcome:
        outcome = {
            StrategyOutcome.SUCCESS: OutcomeKind.EVIDENCE,
            StrategyOutcome.FAILURE: OutcomeKind.FAILED,
            StrategyOutcome.BLOCKED: OutcomeKind.BLOCKED,
            StrategyOutcome.INCONCLUSIVE: OutcomeKind.INCONCLUSIVE,
        }[item.outcome]
        return ResearchOutcome(
            task_id=f"strategy:{item.strategy_id}",
            hypothesis_id=item.strategy_id,
            direction=item.direction,
            outcome=outcome,
            evidence_refs=item.evidence_refs,
            cost=item.cost,
            reason=item.reason,
        )

    @staticmethod
    def _priority(
        strategy_id: str,
        direction: ResearchDirection,
        observations: tuple[StrategyObservation, ...],
        decision: StrategyDecision,
    ) -> StrategyPriority:
        related = tuple(item for item in observations if item.strategy_id == strategy_id)
        success = sum(1 for item in related if item.outcome == StrategyOutcome.SUCCESS)
        failures = sum(
            1
            for item in related
            if item.outcome in {StrategyOutcome.FAILURE, StrategyOutcome.BLOCKED}
        )
        quality = sum(item.evidence_quality for item in related) / len(related) if related else 0.5
        avg_cost = sum(item.cost for item in related) / len(related) if related else 0.0
        base = 0.5 + 0.15 * min(success, 3) + 0.25 * quality - 0.12 * min(failures, 4)
        cost_penalty = min(avg_cost / 100.0, 0.25)
        direction_bonus = 0.08 if direction in decision.next_directions else 0.0
        value = max(
            0.0,
            min(
                1.0,
                round((base - cost_penalty + direction_bonus) * decision.priority_multiplier, 3),
            ),
        )
        basis = (
            f"successes={success}",
            f"failures={failures}",
            f"evidence_quality={quality:.3f}",
            f"average_cost={avg_cost:.3f}",
            f"adaptive_multiplier={decision.priority_multiplier:.3f}",
        )
        return StrategyPriority(
            strategy_id=strategy_id, direction=direction, priority=value, basis=basis
        )


__all__ = [
    "ResearchStrategyOptimizerV2",
    "StrategyObservation",
    "StrategyOptimizationReport",
    "StrategyOutcome",
    "StrategyPriority",
]
