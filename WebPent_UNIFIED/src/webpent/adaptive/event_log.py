"""Fix 3 — Adaptive Event Log.

Central, structured log of every adaptive decision: when a block was
detected, what tactic was chosen, which lane was promoted, which plan was
deferred. Exposed in the node output so the final report tells the operator
exactly how the hunter adapted (and how often it was detected).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AdaptiveEvent:
    phase: str          # "defense_monitor" | "defense_emulator" | "multi_path"
    event: str          # e.g. "block_detected", "plan_deferred", "lane_promoted"
    detail: str = ""
    risk_score: float = 0.0
    action_taken: str = ""


class AdaptiveEventLog:
    def __init__(self) -> None:
        self.events: list[AdaptiveEvent] = []

    def record(self, phase: str, event: str, detail: str = "",
               risk_score: float = 0.0, action_taken: str = "") -> AdaptiveEvent:
        ev = AdaptiveEvent(phase=phase, event=event, detail=detail,
                           risk_score=risk_score, action_taken=action_taken)
        self.events.append(ev)
        return ev

    def summary(self) -> dict[str, Any]:
        blocks = sum(1 for e in self.events if e.event == "block_detected")
        deferred = sum(1 for e in self.events if e.event == "plan_deferred")
        lane_changes = sum(1 for e in self.events if e.event == "lane_promoted")
        return {
            "total_events": len(self.events),
            "blocks_detected": blocks,
            "plans_deferred": deferred,
            "lane_promotions": lane_changes,
            "events": [
                {"phase": e.phase, "event": e.event, "detail": e.detail,
                 "risk_score": e.risk_score, "action": e.action_taken}
                for e in self.events[-50:]  # last 50 to bound output size
            ],
        }


__all__ = ["AdaptiveEvent", "AdaptiveEventLog"]
