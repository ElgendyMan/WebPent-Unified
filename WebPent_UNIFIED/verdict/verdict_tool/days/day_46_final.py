"""Day 46 — Final Verdict: analyze everything, decide."""

from __future__ import annotations

from verdict_tool.protocol import Check, Day, file_exists, load_state
from verdict_tool.tracking import Workspace


class FinalVerdictDay(Day):
    number = 46
    title = "Final Verdict"
    phase = "verdict"
    objectives = (
        "Compute the full metrics (verdict verdict final)",
        "Compare outcomes against the day-0 pre-registration predictions",
        "Record the final outcome: GO / GO_CAUTIOUS / IMPROVE / NO-GO",
        "Write verdict/final_verdict.md with the reasoning",
    )
    output_required = ("verdict/metrics_report.md",
                       "verdict/final_verdict.md",
                       "final verdict recorded in state")
    guidance = (
        "The verdict is about the tool and the process, not the operator's "
        "ego: NO-GO with clean data is a better outcome than GO on noise."
    )

    def checks(self, ws: Workspace) -> list[Check]:
        state = load_state(ws)
        return [
            Check("final verdict computed and recorded in state",
                  state.final_verdict is not None),
            Check("verdict/metrics_report.md exists",
                  file_exists(ws, "verdict", "metrics_report.md")),
            Check("verdict/final_verdict.md exists",
                  file_exists(ws, "verdict", "final_verdict.md")),
        ]
