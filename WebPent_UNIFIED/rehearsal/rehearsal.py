"""The Verdict Dry Run — a compressed rehearsal of the Verdict Protocol
(U-DRYRUN-1).

The rehearsal runs the full workflow in 5 days against the emulator
range only: no real targets, no submissions, no network. Like the
Verdict tool itself, this is a structured notebook: it records what
the operator did and produces the report and playbook; it never runs
tools or touches targets itself.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

STATE_FILE = "rehearsal_state.json"
REHEARSAL_DAYS = (1, 2, 3, 4, 5)

DAY_TITLES = {
    1: "Setup + freeze + pre-registration",
    2: "Three mini-runs (8h each)",
    3: "Analysis + classification",
    4: "Refinement + retry",
    5: "Final analysis + playbook",
}

PHASE_BY_DAY = {
    1: "before you start",
    2: "day 2 — environment",
    3: "day 3 — analysis",
    4: "day 3-4 — run",
    5: "day 5 — analysis",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EmulatorRange(Protocol):
    """Anything that can name the local range the rehearsal runs against."""

    def targets(self) -> list[dict[str, str]]: ...


@dataclass
class DayResult:
    day: int
    title: str
    objectives: list[str]
    outputs: list[str] = field(default_factory=list)
    notes: str = ""
    completed_at: str | None = None


@dataclass
class Lesson:
    day: int
    kind: str  # lesson | issue | adjustment | red_flag | green_flag
    text: str
    real_implication: str = ""  # "if dry run showed X, expect Y on real"


@dataclass
class RehearsalState:
    started_at: str = ""
    finished_at: str | None = None
    frozen_targets: list[dict[str, str]] = field(default_factory=list)
    predictions: dict[str, Any] = field(default_factory=dict)
    runs: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    days: dict[int, DayResult] = field(default_factory=dict)
    lessons: list[Lesson] = field(default_factory=list)

    def day(self, number: int) -> DayResult:
        if number not in REHEARSAL_DAYS:
            raise ValueError(f"rehearsal days are {REHEARSAL_DAYS}")
        if number not in self.days:
            self.days[number] = DayResult(number, DAY_TITLES[number],
                                          objectives_for(number))
        return self.days[number]


def objectives_for(day: int) -> list[str]:
    return {
        1: ["Freeze the emulator targets", "Write pre-registration "
            "predictions"],
        2: ["Run 3 mini-runs, one per target, 8h each"],
        3: ["Analyze findings and classify each one"],
        4: ["Record what was refined and retry at least one run"],
        5: ["Write the final analysis", "Generate the playbook"],
    }[day]


class RehearsalProtocol:
    def __init__(self, workspace: Path) -> None:
        self.workspace = Path(workspace)
        self.state_path = self.workspace / STATE_FILE
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.state = self._load()

    # -- persistence -----------------------------------------------------

    def _load(self) -> RehearsalState:
        if not self.state_path.is_file():
            return RehearsalState()
        data = json.loads(self.state_path.read_text(encoding="utf-8"))
        days = {int(k): DayResult(**v) for k, v in data.pop("days", {}).items()}
        lessons = [Lesson(**item) for item in data.pop("lessons", [])]
        return RehearsalState(days=days, lessons=lessons, **data)

    def save(self) -> None:
        data = asdict(self.state)
        data["days"] = {str(k): asdict(v) for k, v in self.state.days.items()}
        data["lessons"] = [asdict(lesson) for lesson in self.state.lessons]
        self.state_path.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")

    # -- flow --------------------------------------------------------------

    def start(self, emulator: EmulatorRange) -> RehearsalState:
        if self.state.started_at:
            raise RuntimeError("rehearsal already started")
        self.state.started_at = utc_now()
        self.state.frozen_targets = emulator.targets()
        self.state.day(1)
        self.save()
        return self.state

    def set_predictions(self, predicted_findings: list[int],
                        predicted_acceptance: list[float]) -> None:
        self.state.predictions = {
            "findings": predicted_findings,
            "acceptance": predicted_acceptance,
            "written_at": utc_now(),
        }
        self.save()

    def record_run(self, target: str, hours: float,
                   note: str = "") -> None:
        self.state.runs.append({
            "target": target, "hours": hours, "note": note,
            "recorded_at": utc_now(),
        })
        self.save()

    def register_finding(self, finding_id: str, target: str,
                         family: str) -> None:
        self.state.findings.append({
            "finding_id": finding_id, "target": target, "family": family,
            "classification": None, "registered_at": utc_now(),
        })
        self.save()

    def classify_finding(self, finding_id: str, classification: str,
                         note: str = "") -> None:
        for finding in self.state.findings:
            if finding["finding_id"] == finding_id:
                if finding["classification"] is not None:
                    raise ValueError(
                        f"{finding_id} is already classified (immutable)")
                finding["classification"] = classification
                finding["note"] = note
                finding["classified_at"] = utc_now()
                self.save()
                return
        raise ValueError(f"unknown finding {finding_id}")

    def add_lesson(self, day: int, kind: str, text: str,
                   real_implication: str = "") -> None:
        if kind not in ("lesson", "issue", "adjustment", "red_flag",
                        "green_flag"):
            raise ValueError(f"unknown lesson kind {kind}")
        self.state.lessons.append(Lesson(day, kind, text, real_implication))
        self.save()

    # -- day gating --------------------------------------------------------

    def _check_requirements(self, number: int) -> None:
        state = self.state
        if number == 1 and not state.predictions:
            raise RuntimeError("day 1 needs pre-registration predictions")
        if number == 2:
            targets = {t["name"] for t in state.frozen_targets}
            run_targets = {r["target"] for r in state.runs}
            if run_targets != targets:
                raise RuntimeError(
                    "day 2 needs one run per frozen target "
                    f"({sorted(targets)}), has {sorted(run_targets)}")
        if number == 3:
            unclassified = [f for f in state.findings
                            if f["classification"] is None]
            if unclassified:
                raise RuntimeError(
                    f"day 3 needs every finding classified, "
                    f"{len(unclassified)} pending")
        if number == 4 and not state.lessons:
            raise RuntimeError(
                "day 4 needs refinement lessons recorded")

    def run_day(self, number: int) -> DayResult:
        day = self.state.day(number)
        if not self.state.started_at:
            raise RuntimeError("call start() before run_day()")
        if number > 1:
            previous = self.state.days.get(number - 1)
            if previous is not None:
                # opening day N validates what day N-1 produced
                self._check_requirements(number - 1)
            if previous is None or previous.completed_at is None:
                raise RuntimeError(f"day {number - 1} is not complete yet")
        self.save()
        return day

    def complete_day(self, number: int, outputs: list[str],
                     notes: str = "") -> DayResult:
        day = self.state.day(number)
        day.outputs = outputs
        day.notes = notes
        day.completed_at = utc_now()
        self.save()
        return day

    # -- closing -------------------------------------------------------------

    def finish(self) -> RehearsalReport:
        pending = [n for n in REHEARSAL_DAYS
                   if self.state.days.get(n, DayResult(n, "", [])).completed_at
                   is None]
        if pending:
            raise RuntimeError(f"cannot finish: days {pending} incomplete")
        self.state.finished_at = utc_now()
        self.save()
        return RehearsalReport(self.state)

    def generate_playbook(self) -> str:
        from playbook import PlaybookGenerator
        return PlaybookGenerator(self.state).generate()


class RehearsalReport:
    def __init__(self, state: RehearsalState) -> None:
        self.state = state

    def to_markdown(self) -> str:
        state = self.state
        lines = ["# Verdict Dry Run Report", ""]
        lines.append(f"Started: {state.started_at}")
        lines.append(f"Finished: {state.finished_at}")
        lines.append(f"Targets (emulator only): "
                     f"{', '.join(t['name'] for t in state.frozen_targets)}")
        lines.append(f"Runs: {len(state.runs)}   "
                     f"Findings: {len(state.findings)}   "
                     f"Lessons: {len(state.lessons)}")
        lines.append("")
        lines.append("## Days")
        for number in REHEARSAL_DAYS:
            day = state.days[number]
            lines.append(f"- Day {number}: {day.title} — done, "
                         f"outputs: {', '.join(day.outputs) or 'none'}")
        by_kind: dict[str, int] = {}
        for lesson in state.lessons:
            by_kind[lesson.kind] = by_kind.get(lesson.kind, 0) + 1
        lines.append("")
        lines.append("## Lessons by kind")
        for kind, count in sorted(by_kind.items()):
            lines.append(f"- {kind}: {count}")
        lines.append("")
        lines.append("## Predictions")
        lines.append(f"- findings: {state.predictions.get('findings')}")
        lines.append(f"- acceptance: {state.predictions.get('acceptance')}")
        return "\n".join(lines) + "\n"
