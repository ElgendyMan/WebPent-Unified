# src/webpent/remediation/__init__.py
"""Smart remediation editor + security patterns guide (v77, suggestion 2).

ADVISORY-ONLY, end to end. Every module in this package is a pure function
over findings that already exist. Nothing here executes, contacts a target,
re-tests, promotes, or demotes anything; the verification checklists are
instructions for a human and are never run by the framework. Findings
without a usable ``VulnClass`` are skipped and counted, never guessed.
"""

from __future__ import annotations

from webpent.remediation.action_plan import build_action_plan
from webpent.remediation.context_guide import context_guidance
from webpent.remediation.developer_report import build_developer_report
from webpent.remediation.executive_summary import build_executive_summary
from webpent.remediation.exploit_scenario import scenario_steps
from webpent.remediation.fix_templates import FixTemplate, fix_template
from webpent.remediation.impact_explainer import business_impact
from webpent.remediation.locator import locate
from webpent.remediation.patterns_db import (
    PATTERNS,
    SecurityPattern,
    coverage,
    get_pattern,
    pattern_for_finding,
)
from webpent.remediation.priority_dashboard import build_priority_dashboard
from webpent.remediation.root_cause_mapper import (
    RootCause,
    causes,
    classes_for_cause,
    classify,
    explain,
)
from webpent.remediation.verification_steps import checklist

__all__ = [
    "PATTERNS",
    "FixTemplate",
    "RootCause",
    "SecurityPattern",
    "build_action_plan",
    "build_developer_report",
    "build_executive_summary",
    "build_priority_dashboard",
    "business_impact",
    "causes",
    "checklist",
    "classes_for_cause",
    "classify",
    "context_guidance",
    "coverage",
    "explain",
    "fix_template",
    "get_pattern",
    "locate",
    "pattern_for_finding",
    "scenario_steps",
]
