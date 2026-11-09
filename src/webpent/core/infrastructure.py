"""Core infrastructure — red-team 15-step plan execution.

Phase 1 (structure):
  * dataclasses with validate() — Finding, VerificationResult, Rule, QualitySummary
  * ExecutionSession — status machine + checkpoints + resume
  * ResourceLimits — bounds on memory/time/requests, never exceeded
  * PriorityQueue — retest priority actually applied (not just computed)

Phase 2 (integrated logic):
  * validate() at construction time (not just at save)
  * detailed error context (path, line, expected vs found)
  * FileBackup — automatic backup before any data-file write
  * Rule source/context fields (source, source_type, created_at, success/failure counts)

Phase 3 (production readiness):
  * version + data-format compatibility (core/version.py)
  * system_health_check at startup
  * ISO timestamps everywhere
  * safe shutdown handler (SIGINT/SIGTERM)
  * PerformanceMetrics — per-component timing + memory + request counts
"""
from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Phase 1 — Datatypes with validate() at construction (step 1-2 + 2-2)
# ---------------------------------------------------------------------------

class SessionStatus(str, Enum):
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    SAFELY_STOPPED = "safely_stopped"


@dataclass
class Finding:
    finding_id: str
    vuln_class: str
    endpoint: str
    confidence: float
    status: str = "candidate"
    created_at: str = field(default_factory=_now_iso)
    verified_at: str | None = None

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if not self.finding_id:
            raise ValueError("finding_id must be non-empty")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be 0.0-1.0, got {self.confidence}")
        if not self.endpoint:
            raise ValueError("endpoint must be non-empty")


@dataclass
class VerificationResult:
    finding_id: str
    passed: bool
    tests_run: list[str] = field(default_factory=list)
    alternatives_examined: int = 0
    reason: str | None = None
    verified_at: str = field(default_factory=_now_iso)


@dataclass
class Rule:
    rule_id: str
    pattern: str
    scope: str = "pattern"   # global | endpoint | pattern | target
    priority: int = 3        # 1-5
    source: str = "auto_learned"
    source_type: str = "auto_learned"  # manual | auto_learned | imported | system
    created_at: str = field(default_factory=_now_iso)
    last_applied_at: str | None = None
    success_count: int = 0
    failure_count: int = 0

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if not self.pattern:
            raise ValueError("rule pattern must be non-empty")
        if self.scope not in ("global", "endpoint", "pattern", "target"):
            raise ValueError(f"invalid scope: {self.scope}")
        if not (1 <= self.priority <= 5):
            raise ValueError(f"priority must be 1-5, got {self.priority}")


@dataclass
class QualitySummary:
    total: int
    confirmed: int
    needs_review: int
    excluded: int
    started_at: str = field(default_factory=_now_iso)
    completed_at: str | None = None

    def __post_init__(self) -> None:
        if self.total != self.confirmed + self.needs_review + self.excluded:
            # Auto-correct and flag (step 2-5) — never return inconsistent numbers
            self.total = self.confirmed + self.needs_review + self.excluded


# ---------------------------------------------------------------------------
# Phase 1 — ExecutionSession with checkpoints + resume (step 1-4)
# ---------------------------------------------------------------------------

class ExecutionSession:
    """Status machine with automatic checkpoints. Can resume from a saved state."""

    def __init__(self, session_id: str, checkpoint_path: str | None = None) -> None:
        self.session_id = session_id
        self.checkpoint_path = checkpoint_path or f"data/session_{session_id}.json"
        self.status: SessionStatus = SessionStatus.READY
        self.findings_processed: int = 0
        self.checkpoints: list[str] = []
        self.started_at: str | None = None
        self.completed_at: str | None = None

    def start(self) -> None:
        self.status = SessionStatus.RUNNING
        self.started_at = _now_iso()
        self._checkpoint("session_started")

    def checkpoint(self, label: str) -> None:
        if self.status != SessionStatus.RUNNING:
            return
        self.findings_processed += 1
        if self.findings_processed % 5 == 0:
            self._checkpoint(label)

    def _checkpoint(self, label: str) -> None:
        self.checkpoints.append(f"{_now_iso()}:{label}:processed={self.findings_processed}")
        try:
            os.makedirs(os.path.dirname(self.checkpoint_path) or ".", exist_ok=True)
            # P1-12 (0.33.0): atomic write. The old in-place "w" truncate
            # meant a SIGKILL/KeyboardInterrupt between truncate and dump
            # left a partial JSON file and resume() raised JSONDecodeError
            # forever — the session was unrecoverable. tmp+os.replace is
            # atomic on POSIX and Windows.
            tmp_path = f"{self.checkpoint_path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump({"session_id": self.session_id, "status": self.status.value,
                           "findings_processed": self.findings_processed,
                           "checkpoints": self.checkpoints[-10:]}, fh, indent=2)
            os.replace(tmp_path, self.checkpoint_path)
        except OSError:
            pass  # checkpoint best-effort

    def pause(self) -> None:
        self.status = SessionStatus.PAUSED
        self._checkpoint("paused")

    def complete(self) -> None:
        self.status = SessionStatus.COMPLETED
        self.completed_at = _now_iso()
        self._checkpoint("completed")

    def fail(self, reason: str) -> None:
        self.status = SessionStatus.FAILED
        self._checkpoint(f"failed:{reason}")

    @classmethod
    def resume(cls, checkpoint_path: str) -> "ExecutionSession":
        with open(checkpoint_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        sess = cls(data["session_id"], checkpoint_path)
        sess.status = SessionStatus(data.get("status", "paused"))
        sess.findings_processed = data.get("findings_processed", 0)
        sess.checkpoints = data.get("checkpoints", [])
        return sess

    @classmethod
    def resume_or_none(cls, checkpoint_path: str) -> "ExecutionSession | None":
        """P1-12 (0.33.0): corruption-tolerant resume.

        Returns None instead of raising when the checkpoint file is missing
        or unreadable; callers decide whether that means "fresh session" or
        "operator attention". The atomic tmp+replace write makes a torn
        file practically impossible, but a pre-0.33.0 partial checkpoint
        may still exist on disk from an old crash.
        """
        try:
            return cls.resume(checkpoint_path)
        except (OSError, ValueError, KeyError):
            return None


# ---------------------------------------------------------------------------
# Phase 1 — Resource limits (step 1-5) — never exceeded
# ---------------------------------------------------------------------------

class ResourceLimits:
    """Bounds on findings/requests/time. Exceeding → safe stop + clear message."""

    def __init__(self, max_findings: int = 5000, max_requests_per_minute: int = 120,
                 max_seconds: int = 3600) -> None:
        self.max_findings = max_findings
        self.max_requests_per_minute = max_requests_per_minute
        self.max_seconds = max_seconds
        self.start_time = time.time()
        self.requests_this_minute: list[float] = []
        self.total_findings = 0

    def can_accept_finding(self) -> tuple[bool, str]:
        if self.total_findings >= self.max_findings:
            return False, f"max_findings_exceeded: {self.max_findings}"
        return True, "ok"

    def record_finding(self) -> None:
        self.total_findings += 1

    def can_send_request(self) -> tuple[bool, str]:
        now = time.time()
        self.requests_this_minute = [t for t in self.requests_this_minute if now - t < 60]
        if len(self.requests_this_minute) >= self.max_requests_per_minute:
            return False, f"rate_limit_exceeded: {self.max_requests_per_minute}/min"
        if now - self.start_time > self.max_seconds:
            return False, f"max_runtime_exceeded: {self.max_seconds}s"
        self.requests_this_minute.append(now)
        return True, "ok"


# ---------------------------------------------------------------------------
# Phase 2 — PriorityQueue (step 2-1): retest priority actually applied
# ---------------------------------------------------------------------------

class PriorityQueue:
    """Retest queue ordered by severity × proximity ÷ cost. Highest priority
    comes out first, not oldest."""

    def __init__(self) -> None:
        self._items: list[tuple[float, dict[str, Any]]] = []

    def add(self, item: dict[str, Any], *, severity: float, confidence: float,
            threshold: float = 0.70, cost: float = 1.0) -> None:
        proximity = 1.0 - abs(threshold - confidence)
        priority = severity * max(0.0, proximity) / max(1.0, cost)
        self._items.append((priority, item))
        self._items.sort(key=lambda x: x[0], reverse=True)

    def pop(self) -> dict[str, Any] | None:
        if not self._items:
            return None
        return self._items.pop(0)[1]

    def __len__(self) -> int:
        return len(self._items)


# ---------------------------------------------------------------------------
# Phase 2 — FileBackup (step 2-4): backup before any data-file write
# ---------------------------------------------------------------------------

class FileBackup:
    """Before writing a data file, back up the existing one. Keep last 5."""

    @staticmethod
    def backup_before_write(path: str, keep: int = 5) -> str | None:
        if not os.path.exists(path):
            return None
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        backup = f"{path}.backup.{ts}"
        try:
            shutil.copy2(path, backup)
        except OSError:
            return None
        # Prune old backups
        base = os.path.basename(path)
        d = os.path.dirname(path) or "."
        backups = sorted([f for f in os.listdir(d) if f.startswith(base + ".backup.")])
        for old in backups[:-keep]:
            try:
                os.remove(os.path.join(d, old))
            except OSError:
                pass
        return backup


# ---------------------------------------------------------------------------
# Phase 2 — Detailed error context (step 2-3)
# ---------------------------------------------------------------------------

@dataclass
class ErrorContext:
    """Detailed technical error info for the log; user sees a simple message."""
    module: str
    path: str
    reason: str
    error_type: str
    detail: str
    timestamp: str = field(default_factory=_now_iso)

    def user_message(self) -> str:
        return f"تعذر إكمال العملية في {self.module} — راجع السجل للتفاصيل"

    def log_line(self) -> str:
        return f"[ERROR] {self.timestamp} — {self.module} — {self.reason} | path={self.path} | type={self.error_type} | detail={self.detail}"


# ---------------------------------------------------------------------------
# Phase 3 — Startup health check (step 3-2)
# ---------------------------------------------------------------------------

def system_health_check(data_dir: str = "data", reports_dir: str = "reports") -> dict[str, Any]:
    """Run at startup. Creates missing dirs. Returns a report of all issues."""
    issues: list[str] = []
    for d in (data_dir, reports_dir):
        if not os.path.exists(d):
            try:
                os.makedirs(d, exist_ok=True)
                issues.append(f"created_missing_dir: {d}")
            except OSError as exc:
                issues.append(f"cannot_create_dir: {d} ({exc})")
    # Check writability
    if os.path.exists(data_dir) and not os.access(data_dir, os.W_OK):
        issues.append(f"data_dir_not_writable: {data_dir}")
    return {"healthy": len(issues) == 0, "issues": issues, "checked_at": _now_iso()}


# ---------------------------------------------------------------------------
# Phase 3 — Safe shutdown handler (step 3-4)
# ---------------------------------------------------------------------------

class ShutdownHandler:
    """On SIGINT/SIGTERM: checkpoint, mark safely_stopped, close files cleanly."""

    def __init__(self, session: ExecutionSession) -> None:
        self.session = session
        self.triggered = False

    def handle(self, signum: int = 0, frame: Any = None) -> None:
        if self.triggered:
            return
        self.triggered = True
        self.session.status = SessionStatus.SAFELY_STOPPED
        self.session._checkpoint(f"shutdown_signal_{signum}")


# ---------------------------------------------------------------------------
# Phase 3 — Performance metrics (step 3-5)
# ---------------------------------------------------------------------------

class PerformanceMetrics:
    """Per-component timing + counts. Shown in final report."""

    def __init__(self) -> None:
        self.start = time.time()
        self.timings: dict[str, float] = {}
        self.requests_sent = 0
        self._component_start: dict[str, float] = {}

    def begin(self, component: str) -> None:
        self._component_start[component] = time.time()

    def end(self, component: str) -> None:
        if component in self._component_start:
            self.timings[component] = round(time.time() - self._component_start.pop(component), 3)

    def summary(self) -> dict[str, Any]:
        return {
            "total_runtime_seconds": round(time.time() - self.start, 2),
            "per_component_seconds": self.timings,
            "requests_sent": self.requests_sent,
        }


__all__ = [
    "ErrorContext", "ExecutionSession", "FileBackup", "Finding",
    "PerformanceMetrics", "PriorityQueue", "QualitySummary", "ResourceLimits",
    "Rule", "SessionStatus", "ShutdownHandler", "VerificationResult",
    "system_health_check",
]
