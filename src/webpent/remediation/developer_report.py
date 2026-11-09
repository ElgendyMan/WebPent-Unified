# src/webpent/remediation/developer_report.py
"""webpent.remediation.developer_report

Developer-facing remediation report: one Jira-ready card per finding.

ADVISORY-ONLY. This module composes the guidance layers (pattern, root
cause, context, locator, exploit scenario, impact, fix template,
verification checklist) into a card for each finding that already exists.
The card is text for a human; the framework never executes any of it,
never re-tests the target from here, and never promotes or demotes a
finding based on this report. All counts are derived from the findings
list, and findings without a usable class are counted, never guessed.

Every card carries a stable ``non_claim`` line stating exactly that, so a
reader cannot mistake guidance for a re-run result.
"""

from __future__ import annotations

from typing import Any

from webpent.remediation._fields import as_vuln_class
from webpent.remediation.action_plan import build_action_plan
from webpent.remediation.context_guide import context_guidance
from webpent.remediation.exploit_scenario import scenario_steps
from webpent.remediation.fix_templates import fix_template
from webpent.remediation.impact_explainer import business_impact
from webpent.remediation.locator import locate
from webpent.remediation.patterns_db import pattern_for_finding
from webpent.remediation.root_cause_mapper import RootCause, explain
from webpent.remediation.verification_steps import checklist

_NON_CLAIM = (
    "advisory guidance attached to an existing finding; not a re-run, "
    "not a re-test, and not a confirmation"
)


def _card(finding: dict[str, Any]) -> dict[str, Any]:
    pattern = pattern_for_finding(finding)
    cause: RootCause | None = None
    if pattern is not None:
        cause = pattern.root_causes[0] if pattern.root_causes else None
    # One normalized class string for every guidance lookup, so a finding
    # carrying a VulnClass instance resolves like a string-carried one.
    parsed = as_vuln_class(finding.get("vuln_class"))
    class_value = parsed.value if parsed else "unknown"
    scenario = scenario_steps(class_value)
    impact = business_impact(class_value)
    template = fix_template(class_value)
    return {
        "finding_id": str(finding.get("finding_id") or ""),
        "title": str(finding.get("title") or "Untitled finding"),
        "vuln_class": str(finding.get("vuln_class") or "unknown"),
        "severity": str(finding.get("severity") or "unknown"),
        "locator": locate(finding),
        "cwe": {
            "id": pattern.cwe_id if pattern else None,
            "name": pattern.cwe_name if pattern else None,
        },
        "simplified_name": pattern.simplified_name if pattern else None,
        "root_cause": cause.value if cause else None,
        "root_cause_explanation": explain(cause) if cause else None,
        "context": context_guidance(class_value),
        "exploit_scenario": scenario["steps"],
        "business_impact": impact["impact"],
        "interim_mitigations": impact["interim_mitigations"],
        "fix": {
            "concept": template.concept if template else None,
            "bad_example": template.bad_code if template else None,
            "good_example": template.good_code if template else None,
            "framework_variants": (
                {k: list(v) for k, v in template.framework_variants.items()}
                if template else {}
            ),
        },
        "verification_checklist": checklist(class_value),
        "non_claim": _NON_CLAIM,
    }


def build_developer_report(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Per-finding cards plus machine-derived counts and skips."""
    cards: list[dict[str, Any]] = []
    skipped = 0
    for finding in findings:
        if pattern_for_finding(finding) is None:
            skipped += 1
            continue
        cards.append(_card(finding))
    plan = build_action_plan(findings)
    return {
        "cards": cards,
        "counts": {
            "cards": len(cards),
            "total_findings": len(findings),
            "urgent": plan["counts"]["urgent"],
            "proactive": plan["counts"]["proactive"],
            "preventive": plan["counts"]["preventive"],
        },
        "skipped_unclassified": skipped,
        "non_claim": _NON_CLAIM,
    }
