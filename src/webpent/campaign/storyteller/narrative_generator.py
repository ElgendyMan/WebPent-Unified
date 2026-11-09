"""NarrativeGenerator — U-CAMPAIGN-7.

The storyteller renders what the machine actually recorded: the thesis
that was built, the phases that were planned. It has NO LLM in any
field and NO invented facts: every sentence is traceable to the thesis
or the phase list it was handed. The narrative describes; it never
grades and never recommends action — ruling stays with the operator
(CAMPAIGN L-2).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from webpent.campaign.schemas import Phase, TargetThesis

AUDIENCES: tuple[str, ...] = ("operator", "executive")


@dataclass(frozen=True)
class NarrativeSection:
    """One rendered section; template_id names the sentence pattern."""

    template_id: str
    text: str


@dataclass(frozen=True)
class CampaignNarrative:
    """The full narrative: opening, sections, closing, audience."""

    opening: str
    sections: list[NarrativeSection] = field(default_factory=list)
    closing: str = ""
    audience: str = "operator"


class NarrativeGenerator:
    """Renders a campaign narrative from the thesis and phase plan."""

    def generate_campaign_narrative(
        self,
        thesis: TargetThesis,
        phases: list[Phase],
        *,
        audience: str = "operator",
    ) -> CampaignNarrative:
        if audience not in AUDIENCES:
            raise ValueError(
                f"unknown audience {audience!r}; expected one of {AUDIENCES}")

        families = ", ".join(f.name for f, _w in thesis.likely_vuln_families)
        if audience == "operator":
            opening = (
                f"Campaign thesis for {thesis.target_id}: "
                f"{thesis.statement} Likely families: {families or 'none recorded'}."
            )
            sections = [
                NarrativeSection(
                    template_id=f"phase_summary_{index}",
                    text=(
                        f"Phase {phase.phase_id} (order {phase.order}) plans "
                        f"'{phase.goal}' with a budget of "
                        f"{phase.budget.max_requests} requests."
                    ),
                )
                for index, phase in enumerate(phases, start=1)
            ]
            if not phases:
                closing = (
                    "No phases were planned; no phases were recorded. "
                    "The operator holds the ruling."
                )
            else:
                closing = (
                    f"{len(phases)} phase(s) planned for this campaign. "
                    "The operator holds the ruling; the machine records "
                    "only what actually ran."
                )
        else:  # executive
            opening = (
                f"Assessment narrative for {thesis.target_id}, prepared for "
                f"an executive audience from recorded campaign facts."
            )
            sections = [
                NarrativeSection(
                    template_id=f"exec_phase_summary_{index}",
                    text=(
                        f"Planned work item {index}: '{phase.goal}' "
                        f"(bounded to {phase.budget.max_requests} requests)."
                    ),
                )
                for index, phase in enumerate(phases, start=1)
            ]
            if not phases:
                closing = (
                    "No phases were planned; there is no execution to "
                    "summarize. The operator holds the ruling."
                )
            else:
                closing = (
                    f"{len(phases)} planned work item(s), each bounded by "
                    "an explicit budget. The operator holds the ruling."
                )

        return CampaignNarrative(
            opening=opening, sections=sections, closing=closing,
            audience=audience,
        )
