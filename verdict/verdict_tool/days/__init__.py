"""The Verdict Protocol days — full 47-entry registry (U-VERDICT-2)."""

from __future__ import annotations

from verdict_tool.days.day_00_setup import Day0
from verdict_tool.days.day_01_targets import Day1
from verdict_tool.days.day_02_environment import Day2
from verdict_tool.days.day_03_run import RunDay
from verdict_tool.days.day_05_analysis import AnalysisDay
from verdict_tool.days.day_06_buffer import DAY6, DAY7
from verdict_tool.days.day_14_selection import SelectionDay
from verdict_tool.days.day_15_submission import SubmissionDay
from verdict_tool.days.day_16_watch import WatchDay, WatchOpenDay
from verdict_tool.days.day_46_final import FinalVerdictDay
from verdict_tool.protocol import Day

REGISTRY: dict[int, Day] = {}


def _add(day: Day) -> None:
    if day.number in REGISTRY:
        raise ValueError(f"duplicate protocol day {day.number}")
    REGISTRY[day.number] = day


_add(Day0())
_add(Day1())
_add(Day2())
_add(RunDay(3, "a", "Target A Run", first=True))
_add(RunDay(4, "a", "Target A Run", first=False))
_add(AnalysisDay(5, "a"))
_add(DAY6)
_add(DAY7)
_add(RunDay(8, "b", "Target B Run", first=True))
_add(RunDay(9, "b", "Target B Run", first=False))
_add(AnalysisDay(10, "b"))
_add(RunDay(11, "c", "Target C Run", first=True))
_add(RunDay(12, "c", "Target C Run", first=False))
_add(AnalysisDay(13, "c"))
_add(SelectionDay())
_add(SubmissionDay())
for _n in range(16, 46):
    _add(WatchOpenDay(16) if _n == 16 else WatchDay(_n))
_add(FinalVerdictDay())

assert len(REGISTRY) == 47, f"expected 47 protocol days, got {len(REGISTRY)}"

__all__ = ["REGISTRY"]
