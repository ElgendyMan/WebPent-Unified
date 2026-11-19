"""Day 15 — Submission: five reports, all submitted manually."""

from __future__ import annotations

from verdict_tool.protocol import Check, Day, file_exists, load_state
from verdict_tool.tracking import Workspace


class SubmissionDay(Day):
    number = 15
    title = "Submission"
    phase = "submission"
    objectives = (
        "Generate the report draft for each of the 5 selected findings",
        "Read, edit and approve each report yourself — no auto-submission",
        "Submit each report manually on the platform and record its id",
        "Attach the evidence screenshot path for every submission",
        "Write the preliminary verdict to verdict/preliminary_verdict.md",
    )
    output_required = ("submissions/ (5 reports)",
                       "verdict/preliminary_verdict.md",
                       "5 recorded submissions with platform ids")
    guidance = (
        "The tool prepares and records; a human submits. That boundary is "
        "the point of the pipeline (PRISM-L-2 spirit, applied to reporting)."
    )

    def checks(self, ws: Workspace) -> list[Check]:
        state = load_state(ws)
        subs = state.submissions
        complete = [
            s for s in subs
            if s.get("platform_id") and s.get("screenshot_path")
            and s.get("report_path")
        ]
        reports_on_disk = all(
            (ws.root / str(s.get("report_path", "_missing_"))).is_file()
            for s in subs
        )
        return [
            Check("exactly 5 submissions recorded", len(subs) == 5),
            Check("every submission has platform id, report and screenshot",
                  len(complete) == 5),
            Check("every report file exists on disk", reports_on_disk),
            Check("verdict/preliminary_verdict.md exists",
                  file_exists(ws, "verdict", "preliminary_verdict.md")),
        ]
