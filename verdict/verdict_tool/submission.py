"""U-VERDICT-5 — the Submission Pipeline.

The pipeline generates report drafts and records what a human actually
submitted. It never submits anything itself: there is no network code
in this module by design, and every submission requires the operator's
own report file and a screenshot path recorded by hand.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from verdict_tool.classifier import ClassifiedFinding
from verdict_tool.tracking import (
    SubmissionRecord,
    VerdictState,
    Workspace,
    utc_now,
)

REPORT_TEMPLATE = """# {title}

## Summary
{summary}

## Severity
{severity}

## Steps to Reproduce
{steps}

## Evidence
{evidence}

## Impact
{impact}

## Remediation
{remediation}

## Scope & Method
Tested within {program} scope. Rate-limited to {rate} req/s.
Automated-but-supervised testing.
"""

SECTIONS = ("Summary", "Severity", "Steps to Reproduce", "Evidence",
            "Impact", "Remediation", "Scope & Method")


class SubmissionError(ValueError):
    """Raised when a submission step is attempted out of order."""


class SubmissionPipeline:
    """Prepares and records manual submissions (U-VERDICT-5)."""

    def __init__(self, state: VerdictState, ws: Workspace) -> None:
        self.state = state
        self.ws = ws

    # -- report generation -------------------------------------------------

    def _finding(self, finding_id: str) -> ClassifiedFinding:
        record = self.state.finding(finding_id)
        if record is None:
            raise SubmissionError(f"unknown finding {finding_id!r}")
        return ClassifiedFinding(
            finding_id=record.finding_id,
            target=record.target,
            family=record.family,
            original_severity=record.original_severity,
            original_evidence_score=record.original_evidence_score,
            classification=record.classification or "",
            re_test_evidence=list(record.re_test_evidence),
            reason=record.reason,
            severity_confirmed=record.severity_confirmed,
            impact_confirmed=record.impact_confirmed,
            classified_at=record.classified_at or "",
        )

    def generate_report(self, finding_id: str, title: str = "",
                        summary: str = "", steps: str = "",
                        remediation: str = "", program: str = "",
                        rate: str = "5") -> str:
        """Render the report draft for one classified finding."""
        finding = self._finding(finding_id)
        if finding.classification != "confirmed":
            raise SubmissionError(
                f"finding {finding_id} is "
                f"{finding.classification or 'unclassified'}: "
                "only confirmed findings are submitted"
            )
        severity = finding.severity_confirmed or finding.original_severity
        evidence = "\n".join(f"- {path}" for path in finding.re_test_evidence)
        return REPORT_TEMPLATE.format(
            title=title or f"{finding.family} on {finding.target}",
            summary=summary or finding.impact_confirmed or "<fill in>",
            severity=severity,
            steps=steps or "<numbered reproduction steps>",
            evidence=evidence or "<screenshots and logs>",
            impact=finding.impact_confirmed or "<business impact>",
            remediation=remediation or "<how to fix>",
            program=program or finding.target,
            rate=rate,
        )

    def write_report(self, finding_id: str, **context: Any) -> Path:
        report = self.generate_report(finding_id, **context)
        out = self.ws.subdir("submissions") / f"{finding_id}.md"
        out.write_text(report, encoding="utf-8")
        return out

    @staticmethod
    def preview(report: str) -> str:
        """Return the report text (the CLI prints it); verifies sections."""
        missing = [s for s in SECTIONS if f"## {s}" not in report]
        if missing:
            raise SubmissionError(f"report is missing sections: {missing}")
        return report

    # -- recording ------------------------------------------------------------

    def record_submission(self, finding_id: str, platform_id: str,
                          screenshot_path: str,
                          platform: str = "hackerone") -> SubmissionRecord:
        """Record a MANUAL submission performed by the operator."""
        finding = self._finding(finding_id)
        if finding.classification != "confirmed":
            raise SubmissionError(
                f"finding {finding_id} is not confirmed; refusing to record"
            )
        if finding_id in self.state.selection:
            pass  # selected findings are the expected case
        if not platform_id.strip():
            raise SubmissionError("platform_id is required")
        if not screenshot_path.strip():
            raise SubmissionError(
                "a screenshot path is required for every submission"
            )
        if not (self.ws.root / screenshot_path).is_file():
            raise SubmissionError(
                f"screenshot {screenshot_path!r} does not exist in the "
                "workspace; attach real evidence"
            )
        report_rel = Path("submissions") / f"{finding_id}.md"
        if not (self.ws.root / report_rel).is_file():
            raise SubmissionError(
                f"no report at {report_rel}; run report generation first "
                "and review it before submitting"
            )
        record = SubmissionRecord(
            finding_id=finding_id,
            platform_id=platform_id,
            platform=platform,
            submitted_at=utc_now(),
            screenshot_path=screenshot_path,
            report_path=str(report_rel),
        )
        self.state.submissions.append(dict(record.__dict__))
        self.ws.save(self.state)
        return record

    def get_tracker(self) -> list[dict[str, Any]]:
        return list(self.state.submissions)


__all__ = ["REPORT_TEMPLATE", "SECTIONS", "SubmissionError",
           "SubmissionPipeline"]
