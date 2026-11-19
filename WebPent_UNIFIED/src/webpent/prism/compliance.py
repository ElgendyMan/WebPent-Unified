"""THE PRISM — U-PRISM-15, the Silent Failure Detector (v89).

"Every finding without an EvidenceProfile is a breach. Every score
without a log is a breach." Six audit rules, each with a deterministic
violation id, a severity and an action. Zero silent failures means the
detector itself never silently drops a violation: every finding of the
audit is logged and counted (PRISM-L-4).
"""

from __future__ import annotations

import os
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from webpent.oracle.models import sha256_text
from webpent.prism.errors import PrismLawError

MIN_SAMPLES = 5


def _atomic_write_lines(target: Path, lines: list[str]) -> None:
    """Crash-safe rewrite: temp file in the same dir + os.replace.

    R2-prism-03: the compliance log promises zero silent failures; a
    plain truncate-then-write (Path.write_text) destroys the whole audit
    trail when a crash lands between truncate and write, and lets two
    concurrent writers lose each other's lines.
    """
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + ("\n" if lines else ""))
        os.replace(tmp_name, target)
    finally:
        with suppress(OSError):
            os.unlink(tmp_name)

# rule_id, description, action
AUDIT_RULES = (
    ("unscored_finding", "finding without evidence_profile", "block"),
    ("unlogged_score", "evidence without score", "flag"),
    ("missing_justification", "score without reason", "block"),
    ("unpatterned_adjustment", "adjustment without pattern_id", "block"),
    ("undersampled_pattern", "pattern with samples < 5", "block"),
    ("unlogged_decision", "decision without log", "block"),
)


@dataclass(frozen=True)
class AuditedFinding:
    finding_id: str
    has_evidence_profile: bool
    has_score: bool
    score_has_reason: bool
    has_decision: bool = True
    decision_logged: bool = True


@dataclass(frozen=True)
class AuditedAdjustment:
    adjustment_id: str
    has_pattern_id: bool


@dataclass(frozen=True)
class AuditedPattern:
    pattern_id: str
    samples: int


@dataclass(frozen=True)
class AuditFlow:
    findings: tuple[AuditedFinding, ...] = ()
    adjustments: tuple[AuditedAdjustment, ...] = ()
    patterns: tuple[AuditedPattern, ...] = ()


@dataclass(frozen=True)
class ComplianceViolation:
    violation_id: str
    type: str
    severity: str            # "critical" | "high" | "medium"
    details: dict[str, Any]
    auto_action: str         # "block" | "flag" | "log"
    mode: str = "compliance (PRISM-L-4)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "violation_id": self.violation_id,
            "type": self.type,
            "severity": self.severity,
            "details": self.details,
            "auto_action": self.auto_action,
            "mode": self.mode,
        }


_SEVERITY = {
    "unscored_finding": "critical",
    "unlogged_score": "high",
    "missing_justification": "critical",
    "unpatterned_adjustment": "high",
    "undersampled_pattern": "medium",
    "unlogged_decision": "high",
}


class SilentFailureDetector:
    """Six-rule audit with zero silent drops (U-PRISM-15)."""

    def __init__(self, log_path: Path | str | None = None) -> None:
        self._log: list[dict[str, Any]] = []
        self._log_path = Path(log_path) if log_path else None

    # -- audit ---------------------------------------------------------------------

    def audit(self, flow: AuditFlow) -> list[ComplianceViolation]:
        violations: list[ComplianceViolation] = []

        def add(kind: str, subject_id: str,
                details: dict[str, Any]) -> None:
            actions = {rule[0]: rule[2] for rule in AUDIT_RULES}
            action = actions.get(kind, "log")
            violations.append(ComplianceViolation(
                violation_id=sha256_text(f"{kind}|{subject_id}")[:16],
                type=kind,
                severity=_SEVERITY[kind],
                details={"subject": subject_id, **details},
                auto_action=action,
            ))

        for finding in flow.findings:
            if not finding.has_evidence_profile:
                add("unscored_finding", finding.finding_id, {
                    "rule": "finding without evidence_profile",
                })
                continue  # an unscored finding cannot fail deeper rules
            if not finding.has_score:
                add("unlogged_score", finding.finding_id, {
                    "rule": "evidence without score",
                })
            if finding.has_score and not finding.score_has_reason:
                add("missing_justification", finding.finding_id, {
                    "rule": "score without reason",
                })
            if finding.has_decision and not finding.decision_logged:
                add("unlogged_decision", finding.finding_id, {
                    "rule": "decision without log",
                })
        for adjustment in flow.adjustments:
            if not adjustment.has_pattern_id:
                add("unpatterned_adjustment", adjustment.adjustment_id, {
                    "rule": "adjustment without pattern_id",
                })
        for pattern in flow.patterns:
            if pattern.samples < MIN_SAMPLES:
                add("undersampled_pattern", pattern.pattern_id, {
                    "rule": f"pattern with samples < {MIN_SAMPLES}",
                    "samples": pattern.samples,
                })
        violations.sort(key=lambda v: (v.type, v.violation_id))
        return violations

    # -- enforcement ------------------------------------------------------------------

    # the on-disk audit log keeps the most recent lines only; the full
    # history lives in the ledger and the per-round JSONL reports
    MAX_LOG_LINES = 5000

    def enforce(self, violation: ComplianceViolation,
                log_path: Path | str | None = None) -> None:
        """Record the violation; the in-memory log never drops entries."""
        entry = violation.to_dict()
        self._log.append(entry)
        target = Path(log_path) if log_path else self._log_path
        if target is not None:
            target.parent.mkdir(parents=True, exist_ok=True)
            existing: list[str] = []
            if target.exists():
                existing = target.read_text(
                    encoding="utf-8", errors="replace",
                ).splitlines()
            existing.append(
                f"{violation.violation_id}|{violation.type}|"
                f"{violation.severity}|{violation.auto_action}"
            )
            if len(existing) > self.MAX_LOG_LINES:
                existing = existing[-self.MAX_LOG_LINES:]
            _atomic_write_lines(target, existing)

    def enforce_all(self, violations: list[ComplianceViolation],
                    log_path: Path | str | None = None) -> None:
        """Record every violation; the on-disk log is rewritten once, not
        once per violation (batched: read → append all → truncate → write)."""
        for violation in violations:
            self._log.append(violation.to_dict())
        target = Path(log_path) if log_path else self._log_path
        if target is None or not violations:
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        existing: list[str] = []
        if target.exists():
            existing = target.read_text(
                encoding="utf-8", errors="replace",
            ).splitlines()
        existing.extend(
            f"{v.violation_id}|{v.type}|{v.severity}|{v.auto_action}"
            for v in violations
        )
        if len(existing) > self.MAX_LOG_LINES:
            existing = existing[-self.MAX_LOG_LINES:]
        _atomic_write_lines(target, existing)

    def get_violation_stats(self) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_action: dict[str, int] = {}
        for entry in self._log:
            by_type[entry["type"]] = by_type.get(entry["type"], 0) + 1
            by_severity[entry["severity"]] = \
                by_severity.get(entry["severity"], 0) + 1
            by_action[entry["auto_action"]] = \
                by_action.get(entry["auto_action"], 0) + 1
        return {
            "total": len(self._log),
            "by_type": dict(sorted(by_type.items())),
            "by_severity": dict(sorted(by_severity.items())),
            "by_action": dict(sorted(by_action.items())),
        }

    def audit_or_raise(self, flow: AuditFlow) -> list[ComplianceViolation]:
        """Audit and refuse the flow when a BLOCK-class violation exists."""
        violations = self.audit(flow)
        blocking = [v for v in violations if v.auto_action == "block"]
        if blocking:
            first_subject = blocking[0].details.get("subject")
            raise PrismLawError(
                f"{len(blocking)} blocking compliance violations "
                f"(first: {blocking[0].type} on {first_subject}); "
                f"no silent failures pass (PRISM-L-4)",
                law="PRISM-L-4",
            )
        return violations


__all__ = [
    "AUDIT_RULES", "MIN_SAMPLES", "AuditFlow", "AuditedAdjustment",
    "AuditedFinding", "AuditedPattern", "ComplianceViolation",
    "SilentFailureDetector",
]
