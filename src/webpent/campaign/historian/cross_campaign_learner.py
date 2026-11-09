"""CrossCampaignLearner — U-CAMPAIGN-11.

Aggregates what the memory actually holds across campaigns: how many
campaigns are recorded, how recorded findings distribute over the
families the theses named, which family leads. Every number traces
back to a recorded record; the attribution rule is mechanical — a
record's findings count is attributed to the thesis's TOP recorded
likely family (the builder orders families by weight). The learner
reads the memory and never writes to it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from webpent.campaign.historian.campaign_memory import CampaignMemory
from webpent.campaign.schemas import Family


@dataclass(frozen=True)
class Lessons:
    """Aggregate view over recorded campaigns."""

    campaigns_seen: int = 0
    findings_by_family: dict[Family, int] = field(default_factory=dict)

    def top_family(self) -> Family | None:
        """The family with the most recorded findings; None on no data.

        Ties break deterministically by family name.
        """
        if not self.findings_by_family:
            return None
        best = max(
            sorted(self.findings_by_family, key=lambda fam: fam.name),
            key=lambda fam: self.findings_by_family[fam],
        )
        return best


class CrossCampaignLearner:
    """Reads the memory, reports the aggregate, writes nothing."""

    def learn(self, memory: CampaignMemory) -> Lessons:
        findings_by_family: dict[Family, int] = {}
        campaigns_seen = 0
        for record in memory.list_all():
            campaigns_seen += 1
            families = record.brief.thesis.likely_vuln_families
            if not families:
                continue
            top_family = families[0][0]
            findings_by_family[top_family] = (
                findings_by_family.get(top_family, 0)
                + record.report.findings_total
            )
        return Lessons(
            campaigns_seen=campaigns_seen,
            findings_by_family=findings_by_family,
        )
