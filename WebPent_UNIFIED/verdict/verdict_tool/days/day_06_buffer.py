"""Buffer days (6-7) — issue handling and refinement for the next target."""

from __future__ import annotations

from verdict_tool.protocol import Check, Day, dir_exists, file_exists
from verdict_tool.tracking import Workspace


class BufferDay(Day):
    phase = "buffer"

    def __init__(self, number: int, title: str,
                 requirements: tuple[tuple[str, str, bool], ...]) -> None:
        self.number = number
        self.title = title
        # requirements: (kind, relative path, required) — kind: file|dir
        self._requirements = requirements
        paths = ", ".join(rel for _, rel, _ in requirements)
        self.objectives = (
            "Handle any issue raised by the previous run",
            "Record the lessons and the adjustments to apply next",
            f"Prepare what the next phase needs ({paths})",
        )
        self.output_required = tuple(rel for _, rel, _ in requirements)
        self.guidance = (
            "Buffer days exist to absorb reality. An issue silently skipped "
            "here resurfaces on a real target with higher stakes."
        )

    def checks(self, ws: Workspace) -> list[Check]:
        checks: list[Check] = []
        for kind, rel, _required in self._requirements:
            parts = rel.split("/")
            exists = (file_exists(ws, *parts) if kind == "file"
                      else dir_exists(ws, *parts))
            checks.append(Check(f"{rel} exists", exists))
        return checks


DAY6 = BufferDay(6, "Buffer — Retro and Target B Prep", (
    ("file", "findings/retro_target_a.md", True),
    ("file", "targets/target_b.yaml", True),
))

DAY7 = BufferDay(7, "Refinement", (
    ("file", "environment/adjustments.md", True),
    ("dir", "runs/target_b", True),
))
