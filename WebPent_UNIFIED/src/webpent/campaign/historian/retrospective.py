"""RetrospectiveEngine — U-CAMPAIGN-10.

Compares what was planned (the brief's phases and their budgets) with
what was recorded (the phase results). Every observation cites the
recorded numbers it came from; a phase with no recorded result is
reported as PENDING with zero spend, never invented. The retrospective
describes deltas; it never grades them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webpent.campaign.executor.phase_runner import PhaseResult, PhaseStatus
from webpent.campaign.schemas import CampaignBrief


@dataclass(frozen=True)
class PhaseRetrospective:
    """One phase: what was planned against what was recorded."""

    phase_id: str
    planned_requests: int
    used_requests: int
    status: PhaseStatus


@dataclass(frozen=True)
class Retrospective:
    """The whole comparison, deterministic and fact-citing."""

    campaign_id: str
    per_phase: list[PhaseRetrospective] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)


class RetrospectiveEngine:
    """Builds the retrospective from the brief and the recorded results."""

    def review(
        self,
        brief: CampaignBrief,
        report: Any,
        phase_results: list[PhaseResult],
    ) -> Retrospective:
        by_phase_id = {result.phase_id: result for result in phase_results}
        per_phase: list[PhaseRetrospective] = []
        observations: list[str] = []
        for phase in brief.phases:
            result = by_phase_id.get(phase.phase_id)
            if result is None:
                per_phase.append(PhaseRetrospective(
                    phase_id=phase.phase_id,
                    planned_requests=phase.budget.max_requests,
                    used_requests=0,
                    status=PhaseStatus.PENDING,
                ))
                continue
            planned = phase.budget.max_requests
            used = result.requests_used
            per_phase.append(PhaseRetrospective(
                phase_id=phase.phase_id,
                planned_requests=planned,
                used_requests=used,
                status=result.status,
            ))
            if used > planned:
                observations.append(
                    f"{phase.phase_id} used {used} requests against a "
                    f"planned {planned}"
                )
        return Retrospective(
            campaign_id=brief.campaign_id,
            per_phase=per_phase,
            observations=observations,
        )
