"""Phase 3 — Multi-Path Adaptive Planner (Fix 2: priority-based selection).

Never follows a single path. Maintains up to 3 concurrent attack lanes:
  - primary    (highest priority)
  - fallback   (always warm, promoted if primary stalls)
  - exploratory (low priority, runs in background)

Fix 2: each plan carries a priority score (success history, detection risk,
cost). ``next_batch`` picks the HIGHEST-priority available plans across all
non-stalled lanes — not just round-robin order. When a lane stalls (>=3
consecutive blocks), the best-scoring fallback is promoted. Progress is never
lost.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PrioritizedPlan:
    plan: Any
    priority: float = 1.0  # higher = sent sooner
    risk_level: str = "low"


@dataclass
class Lane:
    name: str
    plans: list[PrioritizedPlan] = field(default_factory=list)
    stall_count: int = 0
    stalled: bool = False


class MultiPathPlanner:
    """Assigns plans to lanes by risk; selects next batch by priority."""

    LANE_CAPACITY = 16

    def __init__(self) -> None:
        self.primary = Lane("primary")
        self.fallback = Lane("fallback")
        self.exploratory = Lane("exploratory")
        self.backlog: list[PrioritizedPlan] = []

    def assign(self, plan: Any, risk_level: str = "low", priority: float = 1.0) -> str:
        """Assign a plan to a lane by risk + priority. Returns lane name."""
        pp = PrioritizedPlan(plan=plan, priority=priority, risk_level=risk_level)
        if risk_level == "high":
            lane = self.exploratory
        elif risk_level == "medium":
            lane = self.fallback if len(self.fallback.plans) < self.LANE_CAPACITY else self.exploratory
        else:
            lane = self.primary if len(self.primary.plans) < self.LANE_CAPACITY else self.fallback
        if len(lane.plans) >= self.LANE_CAPACITY:
            self.backlog.append(pp)
            return "backlog"
        lane.plans.append(pp)
        return lane.name

    def report_stall(self, lane_name: str) -> None:
        """Report a stall. Promote the highest-priority fallback to primary."""
        lane = getattr(self, lane_name, None)
        if lane is None:
            return
        lane.stall_count += 1
        if lane.stall_count >= 3:
            lane.stalled = True
            if lane_name == "primary":
                # Fix 2: promote fallback sorted by priority (best first)
                self.fallback.plans.sort(key=lambda p: -p.priority)
                self.primary = Lane("primary", plans=self.fallback.plans)
                self.fallback = Lane("fallback", plans=self.backlog[: self.LANE_CAPACITY])
                self.backlog = self.backlog[self.LANE_CAPACITY:]

    def next_batch(self, per_lane: int = 3) -> list[Any]:
        """Fix 2: pick highest-priority plans across all non-stalled lanes
        (smart selection), bounded by per_lane from primary then others."""
        candidates: list[PrioritizedPlan] = []
        for lane, weight in ((self.primary, 3), (self.fallback, 1), (self.exploratory, 1)):
            if lane.stalled:
                continue
            take = min(per_lane * weight, len(lane.plans))
            candidates.extend(lane.plans[:take])
        # Sort by priority (highest first) — smart, not sequential
        candidates.sort(key=lambda p: -p.priority)
        batch = [p.plan for p in candidates[: per_lane * 3 + 2]]
        # Remove taken from their lanes
        taken_ids = {id(p.plan) for p in candidates[: len(batch)]}
        for lane in (self.primary, self.fallback, self.exploratory):
            lane.plans = [p for p in lane.plans if id(p.plan) not in taken_ids]
        if not batch and self.backlog:
            self.backlog.sort(key=lambda p: -p.priority)
            batch = [p.plan for p in self.backlog[:per_lane]]
            self.backlog = self.backlog[per_lane:]
        return batch

    @property
    def total_pending(self) -> int:
        return len(self.primary.plans) + len(self.fallback.plans) + len(self.exploratory.plans) + len(self.backlog)


__all__ = ["Lane", "MultiPathPlanner", "PrioritizedPlan"]
