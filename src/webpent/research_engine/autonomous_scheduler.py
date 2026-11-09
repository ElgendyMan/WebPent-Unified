"""Deterministic bounded scheduler for AREX research campaigns."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from webpent.research_engine.campaign_state import CampaignState
from webpent.research_engine.execution_router import CapabilityAwareRouter, RouteDecision
from webpent.shared.campaign_executor import CampaignTask, NextBestActionEngine, PlannedAction


class SchedulerDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    status: str = Field(pattern=r"^(selected|blocked|stopped|empty)$")
    task_id: str = ""
    route: str = "none"
    reasons: tuple[str, ...] = ()
    score: float = Field(default=0.0, ge=-1.0, le=2.0)


class AutonomousScheduler:
    """Select at most one bounded task; never executes it."""

    def __init__(
        self,
        state: CampaignState,
        *,
        router: CapabilityAwareRouter | None = None,
        scorer: NextBestActionEngine | None = None,
        max_steps: int = 32,
    ) -> None:
        self.state = state
        self.router = router or CapabilityAwareRouter()
        self.scorer = scorer or NextBestActionEngine()
        self.max_steps = max(0, min(10_000, int(max_steps)))
        self.steps = 0

    def choose(
        self,
        tasks: tuple[CampaignTask, ...] | list[CampaignTask],
        *,
        available_capabilities: set[str] | frozenset[str],
        scope_authorized: bool,
        authority_available: bool,
        observed_evidence: tuple[str, ...] = (),
        observed_preconditions: tuple[str, ...] = (),
        blocked_preconditions: tuple[str, ...] = (),
        attempted_keys: tuple[str, ...] = (),
        covered_classes: tuple[str, ...] = (),
    ) -> tuple[SchedulerDecision, PlannedAction | None, RouteDecision | None]:
        if self.steps >= self.max_steps:
            return (
                SchedulerDecision(status="stopped", reasons=("step_budget_exhausted",)),
                None,
                None,
            )
        if self.state.lineage.sequence >= self.state.research_budget.max_requests:
            return (
                SchedulerDecision(status="stopped", reasons=("research_budget_exhausted",)),
                None,
                None,
            )
        candidates = []
        blocked: list[tuple[CampaignTask, RouteDecision, tuple[str, ...]]] = []
        completed = set(self.state.completed_tasks)
        failed = set(self.state.failed_tasks)
        already_blocked = set(self.state.blocked_tasks)
        for task in tasks:
            if (
                task.task_id in completed
                or task.task_id in failed
                or task.task_id in already_blocked
            ):
                continue
            route = self.router.route(
                task,
                available_capabilities=available_capabilities,
                scope_authorized=scope_authorized,
                authority_available=authority_available,
            )
            if not route.allowed:
                blocked.append((task, route, route.reasons))
                continue
            raw_dependencies = task.metadata.get("dependencies", ())
            if isinstance(raw_dependencies, str):
                raw_dependencies = (raw_dependencies,)
            dependencies = tuple(
                str(item).strip() for item in raw_dependencies if str(item).strip()
            )
            missing_dependencies = tuple(item for item in dependencies if item not in completed)
            if missing_dependencies:
                blocked.append(
                    (
                        task,
                        route,
                        ("dependencies_unmet:" + ",".join(missing_dependencies),),
                    )
                )
                continue
            planned = self.scorer.score(
                task,
                observed_evidence=observed_evidence,
                observed_preconditions=observed_preconditions,
                blocked_preconditions=blocked_preconditions,
                attempted_keys=attempted_keys,
                covered_classes=covered_classes,
            )
            if planned.score >= 0:
                candidates.append((planned, route))
        if not candidates:
            if blocked:
                task, route, reasons = blocked[0]
                return (
                    SchedulerDecision(
                        status="blocked",
                        task_id=task.task_id,
                        reasons=reasons,
                    ),
                    None,
                    route,
                )
            return SchedulerDecision(status="empty", reasons=("no_routable_task",)), None, None
        planned, route = max(candidates, key=lambda item: (item[0].score, item[0].task.task_id))
        self.steps += 1
        return (
            SchedulerDecision(
                status="selected",
                task_id=planned.task.task_id,
                route=route.route,
                reasons=planned.reasons,
                score=planned.score,
            ),
            planned,
            route,
        )

    def record_task_outcome(
        self,
        task_id: str,
        status: str,
        *,
        evidence_summary: dict[str, str] | None = None,
    ) -> CampaignState:
        if status not in {"completed", "failed", "blocked"}:
            raise ValueError("invalid_campaign_task_status")
        updates: dict[str, Any] = {}
        if evidence_summary:
            merged = dict(self.state.evidence_summary)
            merged.update({str(k)[:120]: str(v)[:400] for k, v in evidence_summary.items()})
            updates["evidence_summary"] = merged
        self.state = self.state.mark_task(task_id, status)
        if updates:
            self.state = self.state.evolve(event_id=f"evidence:{task_id}", **updates)
        return self.state


__all__ = ["AutonomousScheduler", "SchedulerDecision"]
