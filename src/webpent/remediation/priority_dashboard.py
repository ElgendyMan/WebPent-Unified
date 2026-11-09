# src/webpent/remediation/priority_dashboard.py
"""webpent.remediation.priority_dashboard

Priority dashboard: rank existing findings by derived priority.

ADVISORY-ONLY: the priority score is a planning aid over findings that
already exist, computed as

    priority = severity_weight x exploitability x spread / fix_effort

Every weight is a named constant below, the score is clamped to [0, 100],
and nothing about a finding is asserted that the finding does not carry.
The dashboard never executes, re-tests, or promotes; it orders text for a
human's todo list.

Findings without a usable ``vuln_class`` or ``severity`` are skipped and
counted, never guessed.
"""

from __future__ import annotations

from typing import Any

from webpent.models.findings import VulnClass
from webpent.remediation._fields import EFFORT, SEVERITY_WEIGHT, as_severity, as_vuln_class
from webpent.remediation.context_guide import context_guidance

# Exploitability: how directly the class converts to attacker value.
# Derived from the class's dangerous-context tier: a class whose guidance
# carries more dangerous contexts is more directly exploitable. The tier
# entries are semantic contexts, not prose, so the derived score tracks
# meaning, not text length. Clamped to [0.2, 1.0].

# Spread weight: how many findings of this class exist, relative to the
# list. One finding of a class scores 1.0; each further finding adds a
# diminishing increment up to _SPREAD_CAP.
_SPREAD_MAX_INCREMENT = 0.05
_SPREAD_CAP = 1.5

# Effort divisor: the S/M/L effort estimate becomes 1.0 / 1.5 / 2.0 so a
# quick fix outranks a slow one at equal severity.
_EFFORT_DIVISOR: dict[str, float] = {"S": 1.0, "M": 1.5, "L": 2.0}

_SCORE_SCALE = 100.0


def _exploitability(vuln_class: VulnClass) -> float:
    guidance = context_guidance(vuln_class)
    if not guidance["known"]:
        return 0.2
    dangerous = len(guidance["dangerous"])
    warning = len(guidance["warning"])
    score = 0.4 + 0.2 * min(dangerous, 3) + 0.05 * min(warning, 2)
    return max(0.2, min(1.0, score))


def build_priority_dashboard(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Ranked rows plus the skipped count; all derived from the input."""
    class_counts: dict[str, int] = {}
    for finding in findings:
        vuln_class = as_vuln_class(finding.get("vuln_class"))
        if vuln_class is not None:
            class_counts[vuln_class.value] = class_counts.get(vuln_class.value, 0) + 1

    rows: list[dict[str, Any]] = []
    skipped = 0
    for finding in findings:
        severity = as_severity(finding.get("severity"))
        vuln_class = as_vuln_class(finding.get("vuln_class"))
        if severity is None or vuln_class is None:
            skipped += 1
            continue
        effort = EFFORT[vuln_class]
        severity_weight = SEVERITY_WEIGHT[severity]
        exploitability = _exploitability(vuln_class)
        count = class_counts[vuln_class.value]
        spread = min(
            _SPREAD_CAP, 1.0 + (count - 1) * _SPREAD_MAX_INCREMENT
        )
        raw = (
            severity_weight * exploitability * spread
            / _EFFORT_DIVISOR[effort]
        )
        rows.append({
            "finding_id": str(finding.get("finding_id") or ""),
            "vuln_class": vuln_class.value,
            "severity": severity.value,
            "severity_weight": severity_weight,
            "exploitability": round(exploitability, 2),
            "spread": round(spread, 2),
            "effort": effort,
            "priority": round(min(_SCORE_SCALE, raw * _SCORE_SCALE), 1),
        })
    rows.sort(key=lambda r: (-r["priority"], r["finding_id"]))
    return {"rows": rows, "skipped_unclassified": skipped}
