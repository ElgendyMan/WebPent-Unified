"""
Track experiment outcomes for research value adjustment.

Records structural outcomes per semantic fingerprint and provides
a semantic_redundancy_factor that reduces the expected value of
experiments that have already produced equivalent evidence.

Key design principles:
- NEVER reduce to zero (repetition must remain possible)
- Different actor/query/branch = different fingerprint = no penalty
- Higher information value = faster redundancy accumulation
- Used for VALUE ADJUSTMENT only, never for blocking
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class InformationValue(Enum):
    """Structural classification of actual information produced.
    
    Based purely on observable state deltas, not invented metrics.
    """
    HIGH = "HIGH"          # New observation + new semantic pattern OR anomaly detected
    MEDIUM = "MEDIUM"      # New observation + new pattern, no anomaly
    LOW = "LOW"            # New observation but known semantic pattern
    REDUNDANT = "REDUNDANT"  # No new observation added (duplicate)
    UNKNOWN = "UNKNOWN"    # Insufficient data to classify

    @classmethod
    def classify(cls, *,
                 new_observation_added: bool = False,
                 new_semantic_pattern: bool = False,
                 anomaly_detected: bool = False,
                 new_status_pattern: bool = False,
                 new_cross_user_signal: bool = False,
                 ) -> InformationValue:
        """Classify based on observable state deltas."""
        if not new_observation_added:
            return cls.REDUNDANT
        if anomaly_detected or new_cross_user_signal:
            return cls.HIGH
        if new_semantic_pattern and new_status_pattern:
            return cls.HIGH
        if new_semantic_pattern:
            return cls.MEDIUM
        return cls.LOW

    @property
    def numeric_weight(self) -> float:
        """Weight for redundancy accumulation. Higher value = faster accumulation."""
        return {
            "HIGH": 1.0,
            "MEDIUM": 0.5,
            "LOW": 0.2,
            "REDUNDANT": 0.8,
            "UNKNOWN": 0.0,
        }[self.value]


@dataclass
class ExperimentOutcome:
    """Record of one experiment execution outcome."""
    semantic_fingerprint: str
    new_facts_count: int = 0
    new_observation_added: bool = False
    evidence_classes: set[str] = field(default_factory=set)
    information_value: InformationValue = InformationValue.UNKNOWN
    hypothesis_confidence_delta: float = 0.0
    unresolved_questions_answered: list[str] = field(default_factory=list)
    decision_sequence: int = 0


@dataclass
class FingerprintStats:
    """Per-fingerprint statistics."""
    execution_count: int = 0
    outcomes: list[ExperimentOutcome] = field(default_factory=list)
    evidence_classes: set[str] = field(default_factory=set)
    total_information_weight: float = 0.0
    last_information_value: InformationValue = InformationValue.UNKNOWN
    consecutive_redundant: int = 0


class ExperimentOutcomeTracker:
    """Track experiment outcomes and compute semantic redundancy factors.
    
    The redundancy factor models how much redundant information an
    experiment is expected to produce, based on its semantic fingerprint's
    history. It approaches but never reaches zero.
    """

    # Redundancy curve: factor = 1 / (1 + alpha * accumulated_weight)
    # alpha controls how fast redundancy accumulates
    REDUNDANCY_ALPHA = 1.5

    # Floor: redundancy factor never drops below this (repetition always possible)
    REDUNDANCY_FLOOR = 0.15

    def __init__(self) -> None:
        self._stats: dict[str, FingerprintStats] = {}

    def record(self, outcome: ExperimentOutcome) -> None:
        """Record an experiment outcome."""
        fp = outcome.semantic_fingerprint
        if fp not in self._stats:
            self._stats[fp] = FingerprintStats()

        stats = self._stats[fp]
        stats.execution_count += 1
        stats.outcomes.append(outcome)
        stats.evidence_classes.update(outcome.evidence_classes)
        stats.total_information_weight += outcome.information_value.numeric_weight
        stats.last_information_value = outcome.information_value

        if outcome.information_value == InformationValue.REDUNDANT:
            stats.consecutive_redundant += 1
        else:
            stats.consecutive_redundant = 0

    def execution_count(self, semantic_fingerprint: str) -> int:
        """Number of times this semantic experiment has been executed."""
        return self._stats.get(semantic_fingerprint, FingerprintStats()).execution_count

    def last_information_value(self, semantic_fingerprint: str) -> InformationValue:
        """Information value of the most recent execution."""
        return self._stats.get(semantic_fingerprint, FingerprintStats()).last_information_value

    def evidence_classes_produced(self, semantic_fingerprint: str) -> set[str]:
        """Evidence classes this experiment has already produced."""
        return set(self._stats.get(semantic_fingerprint, FingerprintStats()).evidence_classes)

    def semantic_redundancy_factor(self, semantic_fingerprint: str) -> float:
        """Compute value multiplier for a semantic experiment.
        
        Returns:
            1.0 = never executed, full value
            <1.0 = has been executed before, proportionally reduced
            >= REDUNDANCY_FLOOR = minimum value (never zero)
        """
        stats = self._stats.get(semantic_fingerprint)
        if stats is None or stats.execution_count == 0:
            return 1.0

        accumulated = stats.total_information_weight
        factor = 1.0 / (1.0 + self.REDUNDANCY_ALPHA * accumulated)

        # Apply extra penalty for consecutive redundant executions
        if stats.consecutive_redundant >= 2:
            factor *= math.pow(0.7, stats.consecutive_redundant - 1)

        return max(self.REDUNDANCY_FLOOR, factor)

    def unresolved_questions_benefit(
        self, semantic_fingerprint: str, unresolved_questions: list[str]
    ) -> float:
        """Compute value bonus if this experiment addresses unresolved questions.
        
        Returns a multiplier >= 1.0 representing the bonus for addressing
        unanswered questions. Returns 1.0 if no benefit.
        """
        if not unresolved_questions:
            return 1.0

        stats = self._stats.get(semantic_fingerprint)
        if stats is None:
            return 1.0 + min(0.3, 0.05 * len(unresolved_questions))

        already_answered = set()
        for outcome in stats.outcomes:
            already_answered.update(outcome.unresolved_questions_answered)

        new_questions = [q for q in unresolved_questions if q not in already_answered]
        if not new_questions:
            return 1.0

        return 1.0 + min(0.3, 0.05 * len(new_questions))

    def snapshot(self) -> dict[str, Any]:
        """Return serializable snapshot for audit."""
        return {
            fp: {
                "execution_count": s.execution_count,
                "evidence_classes": sorted(s.evidence_classes),
                "total_information_weight": round(s.total_information_weight, 4),
                "last_information_value": s.last_information_value.value,
                "consecutive_redundant": s.consecutive_redundant,
                "redundancy_factor": round(self.semantic_redundancy_factor(fp), 4),
            }
            for fp, s in self._stats.items()
        }
