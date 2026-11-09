"""ReportGenerator — U-CAMPAIGN-8.

The execution report is a deterministic projection of the recorded
phase results: outcome counts per recorded status, findings counted
from the results, budget totals summed from what was actually spent.
It describes what happened; it never grades it (no score, no grade —
enforced by test).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from webpent.campaign.executor.phase_runner import PhaseResult
from webpent.campaign.schemas import CampaignBrief


@dataclass(frozen=True)
class ExecutionReport:
    """What was recorded, summed. Nothing else."""

    campaign_id: str
    outcome: dict[str, int] = field(default_factory=dict)
    findings_total: int = 0
    budget_requests_used: int = 0
    budget_llm_calls_used: int = 0


class ReportGenerator:
    """Builds the execution report from the brief and recorded results."""

    def generate_execution_report(
        self,
        brief: CampaignBrief,
        phase_results: list[PhaseResult],
    ) -> ExecutionReport:
        outcome: dict[str, int] = {}
        findings_total = 0
        requests_used = 0
        llm_calls_used = 0
        for result in phase_results:
            status_name = result.status.value
            outcome[status_name] = outcome.get(status_name, 0) + 1
            findings_total += len(result.findings)
            requests_used += result.requests_used
            llm_calls_used += result.llm_calls_used
        return ExecutionReport(
            campaign_id=brief.campaign_id,
            outcome=outcome,
            findings_total=findings_total,
            budget_requests_used=requests_used,
            budget_llm_calls_used=llm_calls_used,
        )
