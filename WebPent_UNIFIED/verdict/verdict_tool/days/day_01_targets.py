"""Day 1 — Target Selection: 3 configs, legal clearance, dry run."""

from __future__ import annotations

from verdict_tool.protocol import Check, Day, dir_exists, file_exists, load_state
from verdict_tool.targets import TargetManager
from verdict_tool.tracking import Workspace


class Day1(Day):
    number = 1
    title = "Target Selection"
    phase = "preparation"
    objectives = (
        "Pick three targets that meet the selection criteria",
        "Complete the legal review for every target and record it",
        "Create and validate one config per target",
        "Dry-run accessibility (config-level; the live HEAD check is "
        "run explicitly with 'verdict targets check')",
    )
    output_required = ("targets/target_a.yaml, target_b.yaml, target_c.yaml",
                       "legal_clearance.md")
    guidance = (
        "No target without documented authorization. A target whose legal "
        "review is incomplete is not a candidate; it is a liability."
    )

    def checks(self, ws: Workspace) -> list[Check]:
        state = load_state(ws)
        configs = (
            sorted((ws.root / "targets").glob("*.yaml"))
            if dir_exists(ws, "targets") else []
        )
        errors: list[str] = []
        if state.targets:
            manager = TargetManager(ws.root / "targets")
            for target in manager.list():
                errors.extend(manager.validate(target))
        return [
            Check("three target configs exist in targets/", len(configs) >= 3),
            Check("legal_clearance.md exists", file_exists(ws, "legal_clearance.md")),
            Check("three targets registered in state", len(state.targets) >= 3),
            Check("every registered target validates clean", not errors),
        ]
