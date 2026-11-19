"""Day 2 — Environment: clean install, configs, benign test."""

from __future__ import annotations

from verdict_tool.protocol import Check, Day, file_exists
from verdict_tool.tracking import Workspace


class Day2(Day):
    number = 2
    title = "Environment"
    phase = "preparation"
    objectives = (
        "Clean install of webpent and the verdict tool from a known state",
        "Review and pin every config file; record the versions",
        "Run a benign smoke test against the local lab only — never "
        "against a real target before day 3",
    )
    output_required = ("environment/environment_setup.md",
                       "environment/baseline.md",
                       "environment/benign_test.log")

    def checks(self, ws: Workspace) -> list[Check]:
        return [
            Check("environment/environment_setup.md exists",
                  file_exists(ws, "environment", "environment_setup.md")),
            Check("environment/baseline.md exists",
                  file_exists(ws, "environment", "baseline.md")),
            Check("environment/benign_test.log exists",
                  file_exists(ws, "environment", "benign_test.log")),
        ]
