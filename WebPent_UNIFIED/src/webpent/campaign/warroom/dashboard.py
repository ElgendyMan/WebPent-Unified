"""CampaignDashboard — U-CAMPAIGN-12.

A deterministic text snapshot of a campaign brief for the operator:
which campaign, how many phases, what the recorded ruling is, and —
when a report is at hand — the recorded spend. Pure rendering; the
dashboard decides nothing.
"""
from __future__ import annotations

from typing import Any

from webpent.campaign.schemas import CampaignBrief


class CampaignDashboard:
    """Renders a brief (optionally with its report) as stable text."""

    def render(self, brief: CampaignBrief, report: Any = None) -> str:
        lines = [
            f"Campaign: {brief.campaign_id}",
            f"Phases: {len(brief.phases)}",
            f"Decision: {brief.decision.value}",
        ]
        if report is not None:
            lines.append(
                f"Requests used: {report.budget_requests_used}"
            )
            lines.append(f"Findings: {report.findings_total}")
        return "\n".join(lines)
