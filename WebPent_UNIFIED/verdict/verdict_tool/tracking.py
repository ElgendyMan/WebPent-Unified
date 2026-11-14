"""The Verdict Protocol — workspace state (U-VERDICT-1).

All state lives in one JSON file (``.verdict/state.json``) inside the
workspace. Every write is a full rewrite (read → merge → write) so the
file never contains partial state, and every timestamp is UTC ISO-8601.
No network, no shell: the tool is a structured notebook, not an agent
(the operator runs webpent; this tool records what happened).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATE_DIR = ".verdict"
STATE_FILE = "state.json"
INTEGRITY_FILE = "state.sha256"


class StateTamperError(RuntimeError):
    """Raised when state.json does not match its recorded integrity hash.

    The hash is a plain SHA-256 recorded beside the file: it catches
    accidental edits and naive tampering (the Round-3 war games' forged
    GO verdict, silent FP deletion, post-freeze rewrites), but it is
    NOT a defense against a determined local attacker, who can rewrite
    both files. Full chain of custody comes from the operator's own
    VCS: commit the workspace, and git history is the second seal.
    """

CLASSIFICATIONS = ("confirmed", "false_positive", "inconclusive")
WATCH_STATUSES = ("under_review", "accepted", "rejected", "duplicate",
                  "informational", "reported_spam")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TargetRecord:
    name: str
    platform: str
    config_path: str
    added_at: str
    legal_review: bool = False


@dataclass
class RunRecord:
    target: str
    started_at: str
    stopped_at: str | None = None
    launch_path: str = ""
    stop_path: str = ""


@dataclass
class FindingRecord:
    finding_id: str
    target: str
    family: str
    original_severity: str
    original_evidence_score: float
    classification: str | None = None
    re_test_evidence: list[str] = field(default_factory=list)
    reason: str = ""
    severity_confirmed: str | None = None
    impact_confirmed: str | None = None
    classified_at: str | None = None
    classified_by: str | None = None


@dataclass
class SubmissionRecord:
    finding_id: str
    platform_id: str
    platform: str
    submitted_at: str
    screenshot_path: str
    report_path: str
    status: str = "submitted"


@dataclass
class WatchEntry:
    finding_id: str
    status: str
    updated_at: str
    note: str = ""


@dataclass
class VerdictState:
    version: int = 1
    created_at: str = ""
    pre_registered: bool = False
    days: dict[str, dict[str, str]] = field(default_factory=dict)
    targets: list[dict[str, Any]] = field(default_factory=list)
    runs: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    submissions: list[dict[str, Any]] = field(default_factory=list)
    watch: list[dict[str, Any]] = field(default_factory=list)
    selection: list[str] = field(default_factory=list)
    watch_opened_at: str | None = None
    final_verdict: dict[str, Any] | None = None
    # pre-registration predictions (written on day 0, checked on day 46)
    predicted_findings_range: list[int] | None = None
    predicted_acceptance_range: list[float] | None = None
    # SHA-256 of pre_registration.md at the moment of the freeze (F-3)
    pre_registration_sha256: str | None = None

    # -- day transitions -------------------------------------------------

    def day_status(self, day: int) -> str:
        entry = self.days.get(str(day))
        return entry["status"] if entry else "not_started"

    def open_day(self, day: int) -> None:
        key = str(day)
        if self.days.get(key, {}).get("status") == "complete":
            raise ValueError(f"day {day} is already complete")
        entry = self.days.setdefault(key, {})
        entry.setdefault("status", "open")
        entry.setdefault("opened_at", utc_now())

    def complete_day(self, day: int) -> None:
        key = str(day)
        entry = self.days.setdefault(key, {})
        if entry.get("status") == "complete":
            raise ValueError(f"day {day} is already complete")
        entry["status"] = "complete"
        entry["completed_at"] = utc_now()

    # -- lookups -----------------------------------------------------------

    def finding(self, finding_id: str) -> FindingRecord | None:
        for raw in self.findings:
            if raw.get("finding_id") == finding_id:
                return FindingRecord(**{
                    k: v for k, v in raw.items() if k in
                    FindingRecord.__dataclass_fields__  # noqa: SLF001
                })
        return None

    def target_names(self) -> list[str]:
        return [t["name"] for t in self.targets]

    def summary(self) -> str:
        complete = sum(
            1 for d in self.days.values() if d.get("status") == "complete"
        )
        classified = sum(
            1 for f in self.findings if f.get("classification")
        )
        lines = [
            f"created: {self.created_at or '(not initialized)'}",
            f"days complete: {complete}/47",
            f"targets: {len(self.targets)}",
            f"runs: {len(self.runs)}",
            f"findings: {len(self.findings)} "
            f"({classified} classified)",
            f"submissions: {len(self.submissions)}",
            f"watch: {'open' if self.watch_opened_at else 'not started'}",
        ]
        if self.final_verdict:
            lines.append(f"verdict: {self.final_verdict.get('outcome')}")
        return "\n".join(lines)


class Workspace:
    """A Verdict workspace directory holding ``.verdict/state.json``."""

    def __init__(self, path: Path | str) -> None:
        self.root = Path(path).resolve()

    @property
    def state_path(self) -> Path:
        return self.root / STATE_DIR / STATE_FILE

    def exists(self) -> bool:
        return self.state_path.is_file()

    def load(self) -> VerdictState:
        if not self.exists():
            raise FileNotFoundError(
                f"no Verdict workspace at {self.root}; run 'verdict init'"
            )
        data = self.state_path.read_bytes()
        integrity_path = self.state_path.parent / INTEGRITY_FILE
        if not integrity_path.is_file():
            raise StateTamperError(
                f"state.json has no integrity record ({INTEGRITY_FILE}); "
                "it was edited outside the tool or written by a version "
                "older than the Round-3 fixes"
            )
        recorded = integrity_path.read_text(encoding="utf-8").strip()
        actual = hashlib.sha256(data).hexdigest()
        if recorded != actual:
            raise StateTamperError(
                "state.json was modified outside the tool: recorded hash "
                f"{recorded[:16]}… but the file hashes to {actual[:16]}… "
                "(restore from VCS or restart the workspace)"
            )
        return VerdictState(**json.loads(data))

    def save(self, state: VerdictState) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        data = (
            json.dumps(asdict(state), indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        self.state_path.write_bytes(data)
        (self.state_path.parent / INTEGRITY_FILE).write_text(
            hashlib.sha256(data).hexdigest() + "\n", encoding="utf-8",
        )

    # standard subdirectories ---------------------------------------------

    DIRS = ("targets", "runs", "findings", "submissions", "watch",
            "verdict", "export", "environment")

    def ensure_dirs(self) -> None:
        for name in self.DIRS:
            (self.root / name).mkdir(parents=True, exist_ok=True)
        (self.root / STATE_DIR).mkdir(parents=True, exist_ok=True)

    def subdir(self, name: str) -> Path:
        path = self.root / name
        path.mkdir(parents=True, exist_ok=True)
        return path


def new_state() -> VerdictState:
    return VerdictState(created_at=utc_now())
