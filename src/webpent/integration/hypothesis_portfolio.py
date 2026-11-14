"""Hypothesis Portfolio / Exploration vs Exploitation (Team-1, V5).

Generic, target-agnostic representation of active research branches. Maintains
only STRUCTURAL state (no target-specific fields). Exploration pressure modifies
candidate VALUE/utility only — it never forces branch switching, never deletes
candidates, never reorders after ranking, never overrides LLM selection.

Branch saturation signals (all structural):
  - repeated low-information outcomes  -> rising exploration_pressure
  - falling novelty / shrinking unresolved questions -> rising exploration_pressure
  - increasing semantic redundancy -> rising exploration_pressure
A strong branch remains exploitable when confidence meaningful, unresolved
questions remain, expected IG high, recent outcomes informative.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class BranchState:
    branch_id: str
    hypothesis_id: str = ""
    confidence: float = 0.0
    evidence_support: int = 0
    evidence_refutations: int = 0
    unresolved_question_count: int = 0
    recent_information_value: str = "UNKNOWN"
    novelty: float = 0.5
    exploration_pressure: float = 0.0
    exploitation_value: float = 0.5
    saturation_state: str = "ACTIVE"  # ACTIVE / SATURATING / SATURATED
    lineage_refs: list[str] = field(default_factory=list)
    _low_outcome_streak: int = 0

    def record_outcome(self, information_value: str, new_question_count: int) -> None:
        self.recent_information_value = information_value
        if information_value in {"LOW", "REDUNDANT"}:
            self._low_outcome_streak += 1
        else:
            self._low_outcome_streak = 0
            self.evidence_support += 1
        self.unresolved_question_count = max(0, int(new_question_count))
        # Exploration pressure rises with saturation; never forces a switch.
        pressure = min(1.0, self._low_outcome_streak * 0.25)
        if self.unresolved_question_count == 0:
            pressure = min(1.0, pressure + 0.3)
        self.exploration_pressure = round(pressure, 3)
        # Exploitation value remains when branch still informative.
        exploit = 0.5 + (0.3 if information_value == "HIGH" else 0.0)
        exploit -= pressure * 0.4
        self.exploitation_value = round(max(0.05, exploit), 3)
        if pressure >= 0.75:
            self.saturation_state = "SATURATED"
        elif pressure >= 0.4:
            self.saturation_state = "SATURATING"
        else:
            self.saturation_state = "ACTIVE"

    def signal(self) -> dict[str, Any]:
        return {
            "branch_id": self.branch_id,
            "hypothesis_id": self.hypothesis_id,
            "confidence": round(self.confidence, 3),
            "unresolved_question_count": self.unresolved_question_count,
            "recent_information_value": self.recent_information_value,
            "exploration_pressure": self.exploration_pressure,
            "exploitation_value": self.exploitation_value,
            "saturation_state": self.saturation_state,
        }


class HypothesisPortfolio:
    """Session-scoped portfolio of competing branches (no second scheduler)."""

    def __init__(self) -> None:
        self._branches: dict[str, BranchState] = {}

    def branch(self, branch_id: str, hypothesis_id: str = "") -> BranchState:
        if branch_id not in self._branches:
            self._branches[branch_id] = BranchState(branch_id=branch_id, hypothesis_id=hypothesis_id)
        return self._branches[branch_id]

    def record_branch_outcome(
        self, branch_id: str, information_value: str, new_question_count: int, hypothesis_id: str = ""
    ) -> None:
        b = self.branch(branch_id, hypothesis_id)
        b.record_outcome(information_value, new_question_count)
        # V6 re-activation: when ANY branch produces HIGH evidence, the global
        # evidence landscape changed -> decay exploration_pressure of OTHER
        # branches so they are re-evaluated and may return to exploitation.
        # Generic, target-agnostic, no hard-coded IDs, no forcing.
        if information_value == "HIGH":
            for other_id, other in self._branches.items():
                if other_id != branch_id and other.exploration_pressure > 0:
                    other.exploration_pressure = round(other.exploration_pressure * 0.7, 3)
                    other.exploitation_value = round(max(0.05, other.exploitation_value + 0.1), 3)
                    if other.exploration_pressure < 0.4:
                        other.saturation_state = "ACTIVE"
                    elif other.exploration_pressure < 0.75:
                        other.saturation_state = "SATURATING"
                    else:
                        other.saturation_state = "SATURATED"

    def branch_signal(self, branch_id: str) -> dict[str, Any]:
        return self.branch(branch_id).signal()

    def all_branches(self) -> list[dict[str, Any]]:
        return [b.signal() for b in self._branches.values()]
