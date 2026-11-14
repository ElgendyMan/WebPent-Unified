"""Day 0 — Setup: freeze, workspace, pre-registration."""

from __future__ import annotations

from verdict_tool.protocol import Check, Day, dir_exists, file_exists, load_state
from verdict_tool.tracking import Workspace


class Day0(Day):
    number = 0
    title = "Setup"
    phase = "preparation"
    objectives = (
        "Create the Verdict workspace and freeze the working environment",
        "Write the pre-registration: predicted findings range, predicted "
        "acceptance range, scope rules — committed before any testing",
        "Verify the workspace directories and state exist",
    )
    output_required = (".verdict/state.json", "pre_registration.md")
    guidance = (
        "The pre-registration is the honesty anchor of the whole protocol: "
        "once it is written, no metric may be reinterpreted to flatter it."
    )

    def checks(self, ws: Workspace) -> list[Check]:
        state = load_state(ws)
        return [
            Check("workspace state exists (.verdict/state.json)", ws.exists()),
            Check(
                "standard directories created",
                all(dir_exists(ws, d) for d in Workspace.DIRS),
            ),
            Check("pre_registration.md exists", file_exists(ws, "pre_registration.md")),
            Check("pre-registration marked done in state", state.pre_registered),
        ]
