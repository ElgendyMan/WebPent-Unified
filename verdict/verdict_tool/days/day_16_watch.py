"""Watch days (16-45) — track platform responses daily."""

from __future__ import annotations

from verdict_tool.protocol import Check, Day, file_exists, load_state
from verdict_tool.tracking import Workspace


class WatchOpenDay(Day):
    """Day 16 — the watch period opens."""

    phase = "watch"

    def __init__(self, number: int = 16) -> None:
        self.number = number
        self.title = "Watch — Period Opens"
        self.objectives = (
            "Open the watch period (verdict watch start)",
            "Create watch/tracker.md and record every submission's status",
            "Check each platform response and update it the same day",
        )
        self.output_required = ("watch/tracker.md", "watch opened in state")
        self.guidance = (
            "No new testing during watch. The protocol watches; it does "
            "not chase or nudge platforms."
        )

    def checks(self, ws: Workspace) -> list[Check]:
        state = load_state(ws)
        return [
            Check("watch period opened in state (watch start)",
                  state.watch_opened_at is not None),
            Check("watch/tracker.md exists",
                  file_exists(ws, "watch", "tracker.md")),
        ]


class WatchDay(Day):
    """Days 17-45 — daily response tracking."""

    phase = "watch"

    def __init__(self, number: int) -> None:
        self.number = number
        self.title = f"Watch — Track Responses (day {number})"
        self.objectives = (
            "Check every submission for platform responses",
            "Update each status with verdict watch update (accepted, "
            "rejected, duplicate, informational, under_review, reported_spam)",
            "Keep watch/tracker.md current",
        )
        self.output_required = ("watch/tracker.md",)
        self.guidance = (
            "A duplicate is data, not an insult: it calibrates timing "
            "and target choice for the next campaign."
        )

    def checks(self, ws: Workspace) -> list[Check]:
        state = load_state(ws)
        return [
            Check("watch period opened in state",
                  state.watch_opened_at is not None),
            Check("watch/tracker.md exists",
                  file_exists(ws, "watch", "tracker.md")),
        ]
