"""Bounded planning helpers for coverage and workflow exploration.

These helpers produce advisory plans only.  They never authorize actions or
promote a candidate finding; execution remains behind the existing spine.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from webpent.shared.governed_artifacts import Hypothesis, WorkflowModel


@dataclass(frozen=True)
class CapabilityGap:
    hypothesis_id: str
    vulnerability_class: str
    missing_capabilities: tuple[str, ...]
    reason: str = "capability_not_available"


@dataclass(frozen=True)
class ExplorationPlan:
    hypothesis_id: str
    vulnerability_class: str
    objective: str
    selected_capabilities: tuple[str, ...]
    expected_information_gain: float
    status: str = "ready"

    def as_dict(self) -> dict[str, object]:
        return {
            "hypothesis_id": self.hypothesis_id[:160],
            "vulnerability_class": self.vulnerability_class[:120],
            "objective": self.objective[:500],
            "selected_capabilities": list(self.selected_capabilities[:32]),
            "expected_information_gain": max(0.0, min(1.0, self.expected_information_gain)),
            "status": self.status,
        }


class CapabilityAwarePlanner:
    """Turn hypotheses into plans or explicit capability gaps."""

    def plan(
        self,
        hypotheses: Iterable[Hypothesis],
        *,
        available_capabilities: Iterable[str],
        attempted_by_class: Mapping[str, int] | None = None,
        max_plans: int = 32,
    ) -> tuple[tuple[ExplorationPlan, ...], tuple[CapabilityGap, ...]]:
        available = {str(item).strip() for item in available_capabilities if str(item).strip()}
        attempts = {
            str(key).lower(): max(0, int(value or 0))
            for key, value in (attempted_by_class or {}).items()
        }
        ready: list[ExplorationPlan] = []
        gaps: list[CapabilityGap] = []
        for hypothesis in hypotheses:
            required = tuple(
                dict.fromkeys(
                    str(item).strip()
                    for item in hypothesis.required_capabilities
                    if str(item).strip()
                )
            )
            missing = tuple(item for item in required if item not in available)
            if missing:
                gaps.append(
                    CapabilityGap(hypothesis.hypothesis_id, hypothesis.vulnerability_class, missing)
                )
                continue
            novelty = max(0.0, min(1.0, hypothesis.novelty_score))
            coverage_bonus = (
                0.2 if attempts.get(hypothesis.vulnerability_class.lower(), 0) == 0 else 0.0
            )
            ready.append(
                ExplorationPlan(
                    hypothesis_id=hypothesis.hypothesis_id,
                    vulnerability_class=hypothesis.vulnerability_class,
                    objective=hypothesis.objective,
                    selected_capabilities=required,
                    expected_information_gain=max(
                        0.0,
                        min(1.0, hypothesis.confidence * 0.5 + novelty * 0.3 + coverage_bonus),
                    ),
                )
            )
        ready.sort(
            key=lambda item: (item.expected_information_gain, item.hypothesis_id), reverse=True
        )
        return tuple(ready[: max(1, min(256, int(max_plans)))]), tuple(gaps[:256])


@dataclass
class CoverageMatrix:
    """Engagement-scoped coverage ledger with no cross-target aggregation."""

    engagement_id: str
    target_package_digest: str
    _attempts: dict[str, int] = field(default_factory=dict)
    _confirmed: set[str] = field(default_factory=set)

    def record_attempt(self, vulnerability_class: str, *, confirmed: bool = False) -> None:
        key = str(vulnerability_class).strip().lower()[:120]
        if not key:
            return
        self._attempts[key] = self._attempts.get(key, 0) + 1
        if confirmed:
            self._confirmed.add(key)

    def snapshot(self) -> dict[str, object]:
        return {
            "engagement_id": self.engagement_id[:160],
            "target_package_digest": self.target_package_digest[:160],
            "attempts": dict(sorted(self._attempts.items())),
            "confirmed_classes": sorted(self._confirmed),
        }


@dataclass(frozen=True)
class WorkflowStep:
    workflow_id: str
    from_state: str
    transition: str
    to_state: str
    status: str = "unattempted"

    def as_dict(self) -> dict[str, str]:
        return {
            "workflow_id": self.workflow_id[:160],
            "from_state": self.from_state[:120],
            "transition": self.transition[:160],
            "to_state": self.to_state[:120],
            "status": self.status,
        }


class WorkflowExplorer:
    """Enumerate a bounded set of modeled transitions, never executing them."""

    def explore(self, workflow: WorkflowModel, *, max_steps: int = 64) -> tuple[WorkflowStep, ...]:
        steps: list[WorkflowStep] = []
        seen: set[tuple[str, str, str]] = set()
        for source, transition, destination in workflow.transitions:
            key = (str(source), str(transition), str(destination))
            if key in seen or source not in workflow.states or destination not in workflow.states:
                continue
            seen.add(key)
            steps.append(
                WorkflowStep(
                    workflow_id=workflow.workflow_id,
                    from_state=source,
                    transition=transition,
                    to_state=destination,
                )
            )
            if len(steps) >= max(1, min(256, int(max_steps))):
                break
        return tuple(steps)


__all__ = [
    "CapabilityAwarePlanner",
    "CapabilityGap",
    "CoverageMatrix",
    "ExplorationPlan",
    "WorkflowExplorer",
    "WorkflowStep",
]
