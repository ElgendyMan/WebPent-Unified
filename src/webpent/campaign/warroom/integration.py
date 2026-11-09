"""CampaignIntegration — U-CAMPAIGN-14.

The post-campaign flow as one composition of campaign-package
components only: the report is generated from the recorded results,
recorded into the memory, and turned into a retrospective. It imports
nothing from the webpent core or the production spine — the flow is
the historian and storyteller talking to each other, nothing more.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from webpent.campaign.executor.phase_runner import PhaseResult
from webpent.campaign.historian.campaign_memory import CampaignMemory
from webpent.campaign.historian.retrospective import RetrospectiveEngine
from webpent.campaign.storyteller.report_generator import (
    ExecutionReport,
    ReportGenerator,
)


@dataclass(frozen=True)
class CampaignFlowResult:
    """Everything the post-campaign flow produced."""

    report: ExecutionReport
    memory_id: str
    retrospective: Any


class CampaignIntegration:
    """Runs report → memory → retrospective for one completed campaign."""

    def __init__(self, memory: CampaignMemory):
        self._memory = memory

    def complete_campaign(
        self,
        brief: Any,
        phase_results: list[PhaseResult],
    ) -> CampaignFlowResult:
        if brief is None:
            raise ValueError("no brief to complete: the flow records a "
                             "campaign, and no campaign was given")
        report = ReportGenerator().generate_execution_report(
            brief, phase_results)
        memory_id = self._memory.record(brief, report)
        retrospective = RetrospectiveEngine().review(
            brief, report, phase_results)
        return CampaignFlowResult(
            report=report,
            memory_id=memory_id,
            retrospective=retrospective,
        )
