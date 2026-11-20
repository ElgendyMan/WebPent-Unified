"""The Verdict Protocol — day model and shared helpers (U-VERDICT-1/2).

The protocol spans 47 entries: 15 protocol days (0-15), the 30-day
watch window (16-45) and the final verdict (day 46). Every day carries
objectives, an operator-facing checklist and required outputs. Checks
are filesystem/state predicates only: the tool never opens a network
connection and never runs commands on the operator's behalf — it is a
structured notebook that verifies the operator's own work.
"""

from __future__ import annotations

from dataclasses import dataclass

from verdict_tool.tracking import VerdictState, Workspace

TOTAL_DAYS = 47


def load_state(ws: Workspace) -> VerdictState:
    """Load the workspace state, or a fresh empty state if uninitialized."""
    if ws.exists():
        return ws.load()
    return VerdictState(created_at="")


@dataclass(frozen=True)
class Check:
    """One checklist line and whether it currently passes."""

    name: str
    passed: bool


def file_exists(ws: Workspace, *parts: str) -> bool:
    return (ws.root.joinpath(*parts)).is_file()


def dir_exists(ws: Workspace, *parts: str) -> bool:
    return (ws.root.joinpath(*parts)).is_dir()


class Day:
    """Base class for one protocol day."""

    number: int = -1
    title: str = ""
    phase: str = ""
    objectives: tuple[str, ...] = ()
    output_required: tuple[str, ...] = ()
    guidance: str = ""

    def checks(self, ws: Workspace) -> list[Check]:
        raise NotImplementedError

    # -- rendering -------------------------------------------------------

    def render(self, ws: Workspace) -> str:
        lines = [
            f"Day {self.number} — {self.title}",
            f"phase: {self.phase}",
            "",
            "Objectives:",
        ]
        lines += [f"  {i+1}. {o}" for i, o in enumerate(self.objectives)]
        lines += ["", "Checklist:"]
        for check in self.checks(ws):
            mark = "[x]" if check.passed else "[ ]"
            lines.append(f"  {mark} {check.name}")
        lines += ["", "Required outputs:"]
        lines += [f"  - {o}" for o in self.output_required]
        if self.guidance:
            lines += ["", f"Note: {self.guidance}"]
        status = "complete" if self.is_complete(ws) else "open"
        lines += ["", f"Run 'verdict day {self.number} --complete' "
                      f"when every item passes (current: {status})."]
        return "\n".join(lines)

    def is_complete(self, ws: Workspace) -> bool:
        return all(check.passed for check in self.checks(ws))

    def missing(self, ws: Workspace) -> list[str]:
        return [c.name for c in self.checks(ws) if not c.passed]


def protocol_days() -> dict[int, Day]:
    """The full 47-day registry (imported lazily from the days package)."""
    from verdict_tool.days import REGISTRY

    return REGISTRY


def get_day(day: int) -> Day:
    registry = protocol_days()
    if day not in registry:
        raise ValueError(
            f"unknown protocol day {day}; valid days are 0..{TOTAL_DAYS - 1}"
        )
    return registry[day]


__all__ = ["Check", "Day", "TOTAL_DAYS", "dir_exists", "file_exists",
           "get_day", "protocol_days"]
