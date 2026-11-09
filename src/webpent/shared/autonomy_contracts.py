"""Redaction-safe contracts for bounded autonomous campaign execution.

These contracts describe governance state only. They do not create transports,
select targets, or authorize actions; ActionAuthority and ActionExecutor remain
the only execution gate.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ActionBudgetState:
    """Deterministic, serializable budget for one controller invocation."""

    limit: float = 10.0
    spent: float = 0.0
    iterations_limit: int = 3
    iterations: int = 0
    replans_limit: int = 2
    replans: int = 0
    status: str = "active"
    stop_reason: str = ""

    @classmethod
    def from_state(
        cls,
        raw: Mapping[str, Any] | None,
        *,
        default_iterations: int = 3,
    ) -> ActionBudgetState:
        data = dict(raw) if isinstance(raw, Mapping) else {}

        def number(name: str, default: float, minimum: float = 0.0) -> float:
            try:
                value = float(data.get(name, default))
            except (TypeError, ValueError):
                value = default
            return max(minimum, value)

        def integer(name: str, default: int, minimum: int = 0) -> int:
            try:
                value = int(data.get(name, default))
            except (TypeError, ValueError):
                value = default
            return max(minimum, value)

        limit = min(1000.0, number("limit", number("max_cost", 10.0)))
        spent_default = number(
            "spent_cost", number("used_cost", 0.0)
        )
        spent = min(limit, number("spent", spent_default))
        iterations_default = integer(
            "max_iterations", default_iterations, minimum=1
        )
        iterations_default = integer(
            "max_actions", iterations_default, minimum=1
        )
        iterations_limit = min(
            10,
            integer("iterations_limit", iterations_default, minimum=1),
        )
        replans_limit = min(
            10,
            integer("replans_limit", integer("max_replans", 2), minimum=0),
        )
        status = str(data.get("status") or "active")[:40]
        stop_reason = str(data.get("stop_reason") or "")[:120]
        return cls(
            limit=limit,
            spent=min(limit, number("spent", spent)),
            iterations_limit=iterations_limit,
            iterations=min(
                iterations_limit,
                integer("iterations", integer("used_actions", 0)),
            ),
            replans_limit=replans_limit,
            replans=min(replans_limit, integer("replans", 0)),
            status=status,
            stop_reason=stop_reason,
        )

    def can_start_iteration(self) -> bool:
        if self.status not in {"active", "replanning"}:
            return False
        if self.iterations >= self.iterations_limit:
            self.status = "stopped"
            self.stop_reason = "iteration_budget_exhausted"
            return False
        if self.spent >= self.limit:
            self.status = "stopped"
            self.stop_reason = "action_budget_exhausted"
            return False
        return True

    def start_iteration(self) -> None:
        if not self.can_start_iteration():
            raise RuntimeError(self.stop_reason or "action_budget_unavailable")
        self.iterations += 1

    def reserve(self, amount: float) -> bool:
        try:
            cost = float(amount)
        except (TypeError, ValueError):
            cost = 1.0
        cost = max(0.0, min(100.0, cost))
        if self.spent + cost > self.limit:
            self.status = "stopped"
            self.stop_reason = "action_budget_exhausted"
            return False
        self.spent += cost
        return True

    def record_replan(self) -> bool:
        if self.replans >= self.replans_limit:
            self.status = "stopped"
            self.stop_reason = "replan_budget_exhausted"
            return False
        self.replans += 1
        self.status = "replanning"
        return True

    def stop(self, reason: str) -> None:
        self.status = "stopped"
        self.stop_reason = str(reason or "controller_stopped")[:120]

    def as_dict(self) -> dict[str, Any]:
        # Keep legacy aliases because older nodes/readers still consume them.
        # ``spent`` is reserved before the attempt: blocked, failed, and
        # successful issued attempts all consume their declared cost.
        return {
            "limit": round(self.limit, 6),
            "spent": round(self.spent, 6),
            "remaining": round(max(0.0, self.limit - self.spent), 6),
            "iterations_limit": self.iterations_limit,
            "iterations": self.iterations,
            "replans_limit": self.replans_limit,
            "replans": self.replans,
            "max_actions": self.iterations_limit,
            "used_actions": self.iterations,
            "max_cost": round(self.limit, 6),
            "used_cost": round(self.spent, 6),
            "status": self.status,
            "stop_reason": self.stop_reason,
        }


@dataclass(frozen=True)
class StopDecision:
    """Explicit stop decision emitted by the controller, never inferred by UI."""

    should_stop: bool
    reason: str
    category: str = "normal"
    safe_to_resume: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "should_stop": self.should_stop,
            "reason": self.reason,
            "category": self.category,
            "safe_to_resume": self.safe_to_resume,
        }


@dataclass(frozen=True)
class AutonomousCycle:
    """Redaction-safe lifecycle record for one planning/execution cycle."""

    cycle_id: str
    phase: str
    status: str
    selected_tasks: int = 0
    executed_tasks: int = 0
    evidence_added: bool = False
    knowledge_updated: bool = False
    stop_decision: StopDecision = field(
        default_factory=lambda: StopDecision(False, "")
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "cycle_id": self.cycle_id,
            "phase": self.phase,
            "status": self.status,
            "selected_tasks": self.selected_tasks,
            "executed_tasks": self.executed_tasks,
            "evidence_added": self.evidence_added,
            "knowledge_updated": self.knowledge_updated,
            "stop_decision": self.stop_decision.as_dict(),
        }


__all__ = ["ActionBudgetState", "AutonomousCycle", "StopDecision"]
