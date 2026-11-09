# src/webpent/remediation/executive_summary.py
"""webpent.remediation.executive_summary

Executive summary over findings that already exist.

ADVISORY-ONLY and machine-derived: counts come from the findings list,
the exposure statement is worded from those counts, and the top actions
are the first three rows of the urgent tier of the action plan. Nothing
here executes or claims any new result about the target.

Findings without a usable class or severity are counted as skipped, so
the summary never overstates its coverage.
"""

from __future__ import annotations

from typing import Any

from webpent.models.findings import Severity
from webpent.remediation._fields import as_severity, as_vuln_class
from webpent.remediation.action_plan import build_action_plan

_SEVERITY_ORDER = (
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
    Severity.INFO,
)


def _exposure_statement(by_severity: dict[str, int]) -> str:
    critical = by_severity[Severity.CRITICAL.value]
    high = by_severity[Severity.HIGH.value]
    total = sum(by_severity.values())
    if total == 0:
        return "No classified findings to summarize."
    if critical:
        return (
            f"{critical} critical finding(s) require immediate remediation; "
            f"{high} high-severity finding(s) follow."
        )
    if high:
        return (
            f"No critical findings; {high} high-severity finding(s) "
            "should be scheduled now."
        )
    if by_severity[Severity.MEDIUM.value]:
        return "No critical or high findings; medium-severity work is queued."
    return "Only low-severity findings remain."


def build_executive_summary(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Counts by severity and class, exposure statement, top actions."""
    by_severity = {sev.value: 0 for sev in _SEVERITY_ORDER}
    by_class: dict[str, int] = {}
    skipped = 0
    for finding in findings:
        severity = as_severity(finding.get("severity"))
        vuln_class = as_vuln_class(finding.get("vuln_class"))
        # UNKNOWN or a missing/unparseable class is an honest absence:
        # counted as skipped, never rendered as a class of its own.
        if severity is None or vuln_class is None:
            skipped += 1
            continue
        by_severity[severity.value] += 1
        by_class[vuln_class.value] = by_class.get(vuln_class.value, 0) + 1
    plan = build_action_plan(findings)
    top_actions = [
        {
            "finding_id": item["finding_id"],
            "vuln_class": item["vuln_class"],
            "effort": item["effort"],
        }
        for item in plan["urgent"][:3]
    ]
    return {
        "counts_by_severity": by_severity,
        "counts_by_class": dict(sorted(by_class.items())),
        "total_findings": len(findings),
        "skipped_unclassified": skipped,
        "top_actions": top_actions,
        "exposure": _exposure_statement(by_severity),
        "non_claim": (
            "machine-derived summary of existing findings; not a "
            "guarantee of completeness"
        ),
    }
