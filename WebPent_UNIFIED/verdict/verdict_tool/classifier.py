"""U-VERDICT-4 — the Finding Classifier.

After each run the operator re-tests every finding by hand and records
one of three classifications: confirmed, false_positive or
inconclusive. The rules are strict because the FP rate is the number
the whole Verdict turns on: an FP needs a reason, a confirmation needs
re-test evidence and an impact statement, and classifications are
immutable once written.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from verdict_tool.targets import SEVERITIES
from verdict_tool.tracking import (
    CLASSIFICATIONS,
    FindingRecord,
    VerdictState,
    Workspace,
    utc_now,
)

DEFAULT_OPERATOR = "operator"


class ClassificationError(ValueError):
    """Raised for invalid or illegal classifications."""


@dataclass
class ClassifiedFinding:
    finding_id: str
    target: str
    family: str
    original_severity: str
    original_evidence_score: float

    classification: str
    re_test_evidence: list[str] = field(default_factory=list)
    reason: str = ""
    severity_confirmed: str | None = None
    impact_confirmed: str | None = None

    classified_at: str = ""
    classified_by: str = DEFAULT_OPERATOR

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _record_to_classified(raw: dict[str, Any]) -> ClassifiedFinding:
    return ClassifiedFinding(**{
        k: v for k, v in raw.items()
        if k in ClassifiedFinding.__dataclass_fields__
    })


class FindingClassifier:
    """Classifies findings inside a Verdict workspace (U-VERDICT-4)."""

    def __init__(self, state: VerdictState, ws: Workspace) -> None:
        self.state = state
        self.ws = ws

    # -- registration ------------------------------------------------------

    def register(self, finding_id: str, target: str, family: str,
                 original_severity: str,
                 original_evidence_score: float) -> FindingRecord:
        if self.state.finding(finding_id) is not None:
            raise ClassificationError(
                f"finding {finding_id} is already registered"
            )
        if original_severity not in SEVERITIES:
            raise ClassificationError(
                f"original_severity must be one of {SEVERITIES}, "
                f"got {original_severity!r}"
            )
        if not 0.0 <= original_evidence_score <= 1.0:
            raise ClassificationError(
                "original_evidence_score must be in [0, 1], "
                f"got {original_evidence_score!r}"
            )
        record = FindingRecord(
            finding_id=finding_id,
            target=target,
            family=family,
            original_severity=original_severity,
            original_evidence_score=float(original_evidence_score),
        )
        self.state.findings.append({
            **asdict(record),
            "registered_at": utc_now(),
        })
        self.ws.save(self.state)
        return record

    # -- classification ------------------------------------------------------

    def classify(self, finding_id: str, classification: str,
                 re_test_evidence: list[str] | None = None,
                 reason: str = "", severity_confirmed: str | None = None,
                 impact_confirmed: str | None = None,
                 classified_by: str = DEFAULT_OPERATOR,
                 ) -> ClassifiedFinding:
        record = self.state.finding(finding_id)
        if record is None:
            raise ClassificationError(f"unknown finding {finding_id!r}")
        if record.classification is not None:
            raise ClassificationError(
                f"finding {finding_id} is already classified as "
                f"{record.classification}; classifications are immutable"
            )
        if classification not in CLASSIFICATIONS:
            raise ClassificationError(
                f"classification must be one of {CLASSIFICATIONS}, "
                f"got {classification!r}"
            )
        evidence = list(re_test_evidence or [])
        if classification in ("confirmed", "false_positive") \
                and not evidence:
            raise ClassificationError(
                f"a {classification} finding requires re-test evidence "
                "(paths to screenshots or logs)"
            )
        missing = [p for p in evidence
                   if not self._evidence_exists(p)]
        if missing:
            raise ClassificationError(
                "evidence paths do not exist in the workspace: "
                f"{missing}; attach the real re-test evidence before "
                "classifying (Round-3 finding F-4)"
            )
        if classification == "false_positive" and not reason.strip():
            raise ClassificationError(
                "a false_positive classification requires a reason"
            )
        if classification == "inconclusive" and not reason.strip():
            raise ClassificationError(
                "an inconclusive classification requires a reason "
                "(what could not be established?)"
            )
        if classification == "confirmed" and not impact_confirmed:
            raise ClassificationError(
                "a confirmed finding requires impact_confirmed"
            )
        if severity_confirmed is not None \
                and severity_confirmed not in SEVERITIES:
            raise ClassificationError(
                f"severity_confirmed must be one of {SEVERITIES}, "
                f"got {severity_confirmed!r}"
            )

        record.classification = classification
        record.re_test_evidence = evidence
        record.reason = reason
        record.severity_confirmed = severity_confirmed
        record.impact_confirmed = impact_confirmed
        record.classified_at = utc_now()
        record.classified_by = classified_by
        for raw in self.state.findings:
            if raw.get("finding_id") == finding_id:
                raw.update(asdict(record))
        self.ws.save(self.state)
        return record

    def _evidence_exists(self, path: str) -> bool:
        """True when an evidence path resolves to a file in the workspace."""
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.ws.root / path
        return candidate.is_file()

    # -- summaries ------------------------------------------------------------

    def all_classified(self) -> list[ClassifiedFinding]:
        return [
            _record_to_classified(raw)
            for raw in self.state.findings
            if raw.get("classification") is not None
        ]

    def batch_summary(self) -> dict[str, Any]:
        findings = self.state.findings
        classified = [f for f in findings if f.get("classification")]
        by_class: dict[str, int] = dict.fromkeys(CLASSIFICATIONS, 0)
        for f in classified:
            by_class[f["classification"]] = by_class.get(
                f["classification"], 0
            ) + 1
        by_target: dict[str, dict[str, int]] = {}
        for f in findings:
            slot = by_target.setdefault(f.get("target", "?"), {
                "total": 0, "classified": 0,
            })
            slot["total"] += 1
            if f.get("classification"):
                slot["classified"] += 1
        total = len(classified)
        return {
            "total_findings": len(findings),
            "classified": total,
            "unclassified": len(findings) - total,
            "confirmed": by_class["confirmed"],
            "false_positive": by_class["false_positive"],
            "inconclusive": by_class["inconclusive"],
            "fp_rate": round(self.compute_fp_rate(), 6),
            "by_target": dict(sorted(by_target.items())),
        }

    def compute_fp_rate(self) -> float:
        classified = [
            f for f in self.state.findings if f.get("classification")
        ]
        if not classified:
            return 0.0
        fps = sum(
            1 for f in classified
            if f["classification"] == "false_positive"
        )
        return fps / len(classified)

    # -- export -----------------------------------------------------------------

    def export(self, path: Path | str) -> Path:
        out = Path(path)
        payload = {
            "exported_at": utc_now(),
            "summary": self.batch_summary(),
            "findings": [f.to_dict() for f in self.all_classified()],
        }
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return out


__all__ = ["CLASSIFICATIONS", "ClassifiedFinding", "ClassificationError",
           "FindingClassifier"]
