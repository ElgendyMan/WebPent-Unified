"""The Playbook Generator (U-DRYRUN-2).

Turns the lessons recorded during the dry run into "The Verdict
Playbook": the guide for running the real protocol on real targets.
Built entirely from what the rehearsal actually recorded — no invented
wisdom, no placeholders when lessons exist.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from rehearsal import RehearsalState

TITLE = "# The Verdict Playbook"
SUBTITLE = "## Lessons from the Dry Run"

# (section header, rehearsal days that feed it)
SECTION_DAYS: list[tuple[str, tuple[int, ...]]] = [
    ("### Before you start", (1,)),
    ("### Day 1 — Target selection", (1,)),
    ("### Day 2 — Environment", (2,)),
    ("### Day 3-4 — Run", (3, 4)),
    ("### Day 5 — Analysis", (5,)),
]


class PlaybookGenerator:
    def __init__(self, state: RehearsalState) -> None:
        self.state = state

    def _lines_for(self, kinds: tuple[str, ...],
                   days: tuple[int, ...]) -> list[str]:
        return [f"- {lesson.text}"
                for lesson in self.state.lessons
                if lesson.kind in kinds and lesson.day in days]

    def generate(self) -> str:
        state = self.state
        lines = [TITLE, SUBTITLE, ""]

        # Per-day sections from that day's lessons/issues/adjustments.
        for header, days in SECTION_DAYS:
            lines.append(header)
            lines.append("")
            items = self._lines_for(("lesson", "issue", "adjustment"), days)
            if 4 in days:
                issues = [item for item in state.lessons
                          if item.day in days and item.kind == "issue"]
                fixes = [item for item in state.lessons
                         if item.day in days
                         and item.kind == "adjustment"]
                run_lessons = self._lines_for(("lesson",), days)
                if issues:
                    lines.append("**Common issues:**")
                    lines.append("")
                    for i, issue in enumerate(issues, 1):
                        lines.append(f"{i}. {issue.text}")
                    lines.append("")
                if fixes:
                    lines.append("**Recommended adjustments:**")
                    lines.append("")
                    lines.extend(f"- {item.text}" for item in fixes)
                    lines.append("")
                items = run_lessons
            lines.extend(items or ["- (none recorded yet)"])
            lines.append("")

        # Red / green flags.
        every_day = tuple(sorted({lesson.day for lesson in state.lessons}
                                 or {0}))
        lines.append("### Red flags to watch for")
        lines.append("")
        lines.extend(self._lines_for(("red_flag",), every_day) or
                     ["- (none recorded yet)"])
        lines.append("")
        lines.append("### Green flags")
        lines.append("")
        lines.extend(self._lines_for(("green_flag",), every_day) or
                     ["- (none recorded yet)"])
        lines.append("")

        # If-dry-run-showed-X mappings.
        mappings = [item for item in state.lessons if item.real_implication]
        lines.append("### If the dry run showed X, then in the real run "
                     "expect Y")
        lines.append("")
        if mappings:
            for lesson in mappings:
                lines.append(f"- If the dry run showed {lesson.text}, "
                             f"then in the real run expect "
                             f"{lesson.real_implication}.")
        else:
            lines.append("- (no mappings recorded yet)")
        lines.append("")
        lines.append(f"_Generated {datetime.now(timezone.utc).isoformat()} "
                     f"from {len(state.lessons)} dry-run lessons._")
        return "\n".join(lines) + "\n"

    def write(self, path: Path) -> Path:
        path.write_text(self.generate(), encoding="utf-8")
        return path
