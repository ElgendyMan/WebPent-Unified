"""Adversarial response scenarios for IRTA v3 local validation."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class StressKind(StrEnum):
    SAME_STATUS = "same_status"
    MISLEADING_BODY = "misleading_body"
    PARTIAL_AUTHORIZATION = "partial_authorization"
    TENANT_CONFUSION = "tenant_confusion"
    WORKFLOW_ORDERING = "workflow_ordering"


@dataclass(frozen=True)
class StressScenario:
    scenario_id: str
    kind: StressKind
    baseline_status: int
    candidate_status: int
    control_status: int
    causal_predicate: str


@dataclass(frozen=True)
class StressAssessment:
    scenario_id: str
    outcome: str
    reason: str


def default_stress_scenarios() -> tuple[StressScenario, ...]:
    return (
        StressScenario(
            "same-status-1", StressKind.SAME_STATUS, 200, 200, 200, "body-and-owner-delta"
        ),
        StressScenario(
            "misleading-body-1",
            StressKind.MISLEADING_BODY,
            403,
            200,
            200,
            "authorization-state-delta",

        ),
        StressScenario(
            "partial-auth-1", StressKind.PARTIAL_AUTHORIZATION, 200, 200, 200, "field-level-delta"
        ),
        StressScenario(
            "tenant-confusion-1",
            StressKind.TENANT_CONFUSION,
            403,
            200,
            403,
            "tenant-ownership-delta",

        ),
        StressScenario(
            "workflow-order-1",
            StressKind.WORKFLOW_ORDERING,
            409,
            200,
            409,
            "state-transition-delta",

        ),
    )


def assess_stress(scenario: StressScenario, has_causal_proof: bool) -> StressAssessment:
    if not has_causal_proof:
        return StressAssessment(scenario.scenario_id, "BLOCKED", "causal proof absent")
    if scenario.candidate_status == scenario.control_status:
        return StressAssessment(
            scenario.scenario_id, "BLOCKED", "candidate/control status is indistinguishable"
        )
    return StressAssessment(
        scenario.scenario_id, "READY_FOR_ORACLE", "status distinction requires oracle review"
    )
