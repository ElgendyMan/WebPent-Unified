# src/webpent/remediation/action_plan.py
"""webpent.remediation.action_plan

A three-tier remediation plan over findings that already exist.

ADVISORY-ONLY: this module reads a findings list and organizes it into
urgent / proactive / preventive work, with an effort estimate and a
derived priority per item. It never executes, re-tests, promotes, or
demotes anything, and every count it reports is computed from the list it
was given.

Honesty rules: findings without a usable ``vuln_class`` are counted in
``skipped_unclassified`` and never guessed into a tier; priorities are
derived only from the finding's own severity and the class's effort
estimate, never invented.
"""

from __future__ import annotations

from typing import Any

from webpent.models.findings import Severity, VulnClass
from webpent.remediation._fields import EFFORT, SEVERITY_WEIGHT, as_severity, as_vuln_class
from webpent.remediation.fix_templates import fix_template
from webpent.remediation.root_cause_mapper import classify

_URGENT_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}
_EFFORT_PENALTY: dict[str, float] = {"S": 0.0, "M": 0.1, "L": 0.2}


def _item(finding: dict[str, Any]) -> dict[str, Any] | None:
    vuln_class = as_vuln_class(finding.get("vuln_class"))
    severity = as_severity(finding.get("severity"))
    if vuln_class is None or severity is None:
        return None
    effort = EFFORT[vuln_class]
    priority = round(
        max(0.0, SEVERITY_WEIGHT[severity] - _EFFORT_PENALTY[effort]), 2
    )
    return {
        "finding_id": str(finding.get("finding_id") or ""),
        "vuln_class": vuln_class.value,
        "severity": severity.value,
        "effort": effort,
        "priority": priority,
    }


def build_action_plan(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Three-tier plan over a findings list, machine-derived throughout."""
    urgent: list[dict[str, Any]] = []
    proactive: list[dict[str, Any]] = []
    skipped = 0
    seen_classes: set[VulnClass] = set()
    class_ids: dict[VulnClass, list[str]] = {}
    for finding in findings:
        item = _item(finding)
        if item is None:
            skipped += 1
            continue
        vuln_class = VulnClass(item["vuln_class"])
        seen_classes.add(vuln_class)
        class_ids.setdefault(vuln_class, []).append(item["finding_id"])
        if Severity(item["severity"]) in _URGENT_SEVERITIES:
            urgent.append(item)
        else:
            proactive.append(item)
    preventive: list[dict[str, Any]] = []
    for vuln_class in sorted(seen_classes, key=lambda c: c.value):
        cause = classify(vuln_class)
        template = fix_template(vuln_class)
        preventive.append({
            "vuln_class": vuln_class.value,
            "root_cause": cause.value if cause else None,
            "fix_concept": template.concept if template else None,
            "effort": EFFORT[vuln_class],
            # Only findings that actually classified (valid severity and
            # class) appear here; skipped findings are never relisted.
            "finding_ids": class_ids.get(vuln_class, []),
        })
    return {
        "urgent": sorted(urgent, key=lambda i: -i["priority"]),
        "proactive": sorted(proactive, key=lambda i: -i["priority"]),
        "preventive": preventive,
        "counts": {
            "urgent": len(urgent),
            "proactive": len(proactive),
            "preventive": len(preventive),
            "total": len(findings),
        },
        "skipped_unclassified": skipped,
    }
