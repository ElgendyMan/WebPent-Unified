"""Deterministic, proposal-only planning for security research hypotheses."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass

from webpent.intelligence.contracts import ResearchHypothesis
from webpent.research_engine.research_state import ResearchTask

_RISK_PENALTY = {"low": 0.0, "medium": 0.08, "high": 0.18, "critical": 0.35}


@dataclass(frozen=True)
class ResearchQueue:
    tasks: tuple[ResearchTask, ...] = ()

    def ordered(self) -> tuple[ResearchTask, ...]:
        return tuple(
            sorted(
                self.tasks,
                key=lambda task: (
                    -task.priority,
                    -task.expected_information_gain,
                    task.cost,
                    task.task_id,
                ),
            )
        )

    def next_task(self) -> ResearchTask | None:
        return self.ordered()[0] if self.tasks else None


@dataclass(frozen=True)
class PlannerDecision:
    status: str
    selected_task_id: str | None
    queue_size: int
    rationale: str
    authoritative: bool = False
    execution_allowed: bool = False


class ResearchPlanner:
    """Select high-value admissible tasks, but never execute or authorize them."""

    def __init__(self, *, max_tasks: int = 256) -> None:
        self.max_tasks = max(1, min(2000, int(max_tasks)))

    def build_queue(
        self,
        hypotheses: Iterable[ResearchHypothesis],
        *,
        engagement_id: str,
        target_id: str,
        available_capabilities: Iterable[str] = (),
        completed_task_ids: Iterable[str] = (),
        attempted_hypothesis_ids: Iterable[str] = (),
    ) -> ResearchQueue:
        capabilities = {str(item).strip() for item in available_capabilities if str(item).strip()}
        completed = {str(item).strip() for item in completed_task_ids if str(item).strip()}
        attempted_hypotheses = {
            str(item).strip() for item in attempted_hypothesis_ids if str(item).strip()
        }
        tasks: list[ResearchTask] = []
        seen_classes: set[str] = set()
        for hypothesis in hypotheses:
            hypothesis_id = str(hypothesis.id)
            task_id = self.task_id(hypothesis, engagement_id=engagement_id, target_id=target_id)
            if (
                task_id in completed
                or hypothesis_id in attempted_hypotheses
                or hypothesis.required_capability not in capabilities
            ):
                continue
            risk = (
                hypothesis.risk.value if hasattr(hypothesis.risk, "value") else str(hypothesis.risk)
            )
            class_name = (
                hypothesis.vuln_class.value
                if hasattr(hypothesis.vuln_class, "value")
                else str(hypothesis.vuln_class)
            )
            evidence_count = min(16, len(hypothesis.evidence_needed))
            plan_count = min(16, len(hypothesis.attack_plan))
            evidence_coverage = min(1.0, evidence_count / 6.0)
            plan_coverage = min(1.0, plan_count / 6.0)
            confidence = max(0.0, min(1.0, float(hypothesis.confidence)))
            gain = min(
                1.0,
                0.18 + (confidence * 0.34) + (evidence_coverage * 0.28) + (plan_coverage * 0.20),
            )
            cost = min(1.0, 0.10 + (plan_count * 0.035) + (evidence_count * 0.018))
            novelty = 0.12 if class_name not in seen_classes else 0.0
            seen_classes.add(class_name)
            risk_penalty = _RISK_PENALTY.get(risk, 0.2)
            priority = max(
                0.0,
                min(
                    1.0,
                    (confidence * 0.42)
                    + (gain * 0.38)
                    + (novelty * 0.20)
                    - (cost * 0.12)
                    - risk_penalty,
                ),
            )
            tasks.append(
                ResearchTask(
                    task_id=task_id,
                    engagement_id=engagement_id,
                    target_id=target_id,
                    objective=f"Validate potential {class_name} hypothesis",
                    reason=(
                        f"{hypothesis.reason} Planning uses evidence coverage, "
                        "information gain, novelty, cost, and risk; "
                        "it does not establish exploitability."
                    ),
                    priority=round(priority, 6),
                    risk=risk,
                    expected_information_gain=round(gain, 6),
                    cost=round(cost, 6),
                    required_capability=hypothesis.required_capability,
                    required_evidence=tuple(hypothesis.evidence_needed),
                    operation="validate",
                )
            )
        return ResearchQueue(ResearchQueue(tuple(tasks)).ordered()[: self.max_tasks])

    def decide(self, queue: ResearchQueue) -> PlannerDecision:
        task = queue.next_task()
        if task is None:
            return PlannerDecision(
                status="no_admissible_task",
                selected_task_id=None,
                queue_size=0,
                rationale="No task satisfies scope, completion, and capability filters.",
            )
        return PlannerDecision(
            status="planned",
            selected_task_id=task.task_id,
            queue_size=len(queue.tasks),
            rationale=(
                f"Selected {task.task_id} by deterministic evidence-gain utility ordering; "
                "execution remains behind the existing scope/authority/evidence gates."
            ),
        )

    @staticmethod
    def task_id(hypothesis: ResearchHypothesis, *, engagement_id: str, target_id: str) -> str:
        raw = f"{engagement_id}|{target_id}|{hypothesis.id}|{hypothesis.required_capability}"
        return "research:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


__all__ = ["PlannerDecision", "ResearchPlanner", "ResearchQueue"]
