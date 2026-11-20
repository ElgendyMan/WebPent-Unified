"""Day 14 — Cross Analysis: rank across targets, freeze the top 5."""

from __future__ import annotations

from verdict_tool.protocol import Check, Day, file_exists, load_state
from verdict_tool.tracking import Workspace

SELECTION_SIZE = 5


class SelectionDay(Day):
    number = 14
    title = "Cross Analysis and Selection"
    phase = "selection"
    objectives = (
        "Cross-analyze all findings from the three targets",
        "Rank confirmed findings by confirmed severity and evidence score",
        f"Freeze exactly {SELECTION_SIZE} finding ids in the selection",
        "Write the cross-analysis rationale to findings/cross_analysis.md",
    )
    output_required = ("findings/cross_analysis.md",
                       f"selection of {SELECTION_SIZE} finding ids in state")
    guidance = (
        "The selection is frozen: what is in, is in. Replacements after "
        "submission day are retro-justification, not judgment."
    )

    def checks(self, ws: Workspace) -> list[Check]:
        state = load_state(ws)
        known = {f.get("finding_id") for f in state.findings}
        confirmed = {
            f.get("finding_id") for f in state.findings
            if f.get("classification") == "confirmed"
        }
        selection = state.selection
        return [
            Check("findings/cross_analysis.md exists",
                  file_exists(ws, "findings", "cross_analysis.md")),
            Check(f"selection holds exactly {SELECTION_SIZE} finding ids",
                  len(selection) == SELECTION_SIZE),
            Check("every selected id exists among the findings",
                  all(fid in known for fid in selection)),
            Check("every selected finding is classified confirmed",
                  all(fid in confirmed for fid in selection)),
        ]
