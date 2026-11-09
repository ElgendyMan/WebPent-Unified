"""Run days (3-4, 8-9, 11-12) — launch, check-ins, stop, backup.

One :class:`RunDay` instance per calendar day; the first day of a pair
covers the launch, the second covers the clean stop and evidence backup.
The tool records the run; the operator performs it.
"""

from __future__ import annotations

from verdict_tool.protocol import Check, Day, dir_exists, file_exists, load_state
from verdict_tool.tracking import Workspace


def _latest_run(state, target: str) -> dict | None:
    runs = [r for r in state.runs if r.get("target") == target]
    return runs[-1] if runs else None


class RunDay(Day):
    phase = "run"

    def __init__(self, number: int, target: str, label: str,
                 first: bool) -> None:
        self.number = number
        self.target = target
        self.label = label
        self.first = first
        name = f"target_{target}"
        if first:
            self.title = f"{label} — Launch"
            self.objectives = (
                f"Configure the launch for {name}: rate-limited, supervised, "
                "inside the recorded scope only",
                f"Start the run and record the launch parameters in "
                f"runs/{name}/launch.txt",
                "First check-in: confirm the tool behaves within policy",
            )
            self.output_required = (f"runs/{name}/", f"runs/{name}/launch.txt")
            self.guidance = (
                "Automation stays within the target policy: max_rate_rps is "
                "a ceiling, not a target. Out-of-scope endpoints are never probed."
            )
        else:
            self.title = f"{label} — Stop and Backup"
            self.objectives = (
                f"Stop the run for {name} cleanly at the planned time",
                "Back up all evidence (logs, screenshots, JSONL) into "
                f"runs/{name}/backup/",
                "Record the check-ins and any anomalies seen during the run",
            )
            self.output_required = (f"runs/{name}/stop.txt",
                                    f"runs/{name}/backup/",
                                    f"runs/{name}/checkins.txt")
            self.guidance = (
                "Evidence that is not backed up on stop day tends to "
                "disappear; the backup is part of the protocol, not a courtesy."
            )

    # -- checks ----------------------------------------------------------

    def checks(self, ws: Workspace) -> list[Check]:
        state = load_state(ws)
        name = f"target_{self.target}"
        run = _latest_run(state, name)
        checks = [
            Check(f"runs/{name}/ directory exists", dir_exists(ws, "runs", name)),
        ]
        if self.first:
            checks += [
                Check(f"{name} registered in state with a started run",
                      run is not None and run.get("started_at")),
                Check(f"runs/{name}/launch.txt exists",
                      file_exists(ws, "runs", name, "launch.txt")),
            ]
        else:
            checks += [
                Check(f"{name} run stopped (stopped_at recorded)",
                      run is not None and run.get("stopped_at")),
                Check(f"runs/{name}/stop.txt exists",
                      file_exists(ws, "runs", name, "stop.txt")),
                Check(f"runs/{name}/backup/ exists",
                      dir_exists(ws, "runs", name, "backup")),
                Check(f"runs/{name}/checkins.txt exists",
                      file_exists(ws, "runs", name, "checkins.txt")),
            ]
        return checks
