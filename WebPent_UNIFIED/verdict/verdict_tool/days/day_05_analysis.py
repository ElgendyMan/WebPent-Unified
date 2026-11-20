"""Analysis days (5, 10, 13) — classify every finding of the run."""

from __future__ import annotations

from verdict_tool.protocol import Check, Day, file_exists, load_state
from verdict_tool.tracking import Workspace


class AnalysisDay(Day):
    phase = "analysis"

    def __init__(self, number: int, target: str) -> None:
        self.number = number
        self.target = target
        name = f"target_{target}"
        self.title = f"{name.replace('_', ' ').title()} Analysis"
        self.objectives = (
            f"Read every finding produced by the {name} run",
            "Re-test each finding manually before classifying it",
            "Classify each finding: confirmed / false_positive / inconclusive",
            "Record the reason (FP) and the confirmed impact (confirmed)",
            f"Write the analysis to findings/analysis_{name}.md",
        )
        self.output_required = (f"findings/analysis_{name}.md",
                                "every run finding classified")
        self.guidance = (
            "An unclassified finding is an unfinished day. Classify honestly: "
            "a false positive recorded today is process improvement, not a loss."
        )

    def checks(self, ws: Workspace) -> list[Check]:
        state = load_state(ws)
        name = f"target_{self.target}"
        findings = [f for f in state.findings if f.get("target") == name]
        unclassified = [f for f in findings if not f.get("classification")]
        return [
            Check(f"at least one finding registered for {name}",
                  bool(findings)),
            Check(f"every {name} finding is classified", not unclassified),
            Check(f"findings/analysis_{name}.md exists",
                  file_exists(ws, "findings", f"analysis_{name}.md")),
        ]
