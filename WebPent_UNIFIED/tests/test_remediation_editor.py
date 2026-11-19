"""Tests for the smart remediation editor (suggestion 2, v77).

The editor is advisory-only: every module is a pure function over
findings that already exist. These tests pin what makes that safe:

* the pattern database covers the VulnClass vocabulary honestly (no
  invented CWE for UNKNOWN, coverage reported, not implied),
* root causes are total over the vocabulary and None only for unknown,
* context tiers exist for every mapped class and degrade honestly,
* locators keep names and drop values (redaction),
* report builders derive every count from the findings list.
"""

from __future__ import annotations

import json
from typing import Any

from webpent.autonomous import AutonomousHuntState
from webpent.models.findings import Severity, VulnClass
from webpent.remediation.action_plan import build_action_plan
from webpent.remediation.context_guide import context_guidance
from webpent.remediation.developer_report import build_developer_report
from webpent.remediation.executive_summary import build_executive_summary
from webpent.remediation.exploit_scenario import scenario_steps
from webpent.remediation.fix_templates import fix_template
from webpent.remediation.impact_explainer import business_impact
from webpent.remediation.locator import locate
from webpent.remediation.patterns_db import (
    PATTERNS,
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

# ---------------------------------------------------------------------------
# Task 1: pattern database
# ---------------------------------------------------------------------------


def test_every_non_unknown_class_resolves() -> None:
    unmapped = [
        member for member in VulnClass
        if member is not VulnClass.UNKNOWN and get_pattern(member) is None
    ]
    assert unmapped == []


def test_unknown_resolves_to_none() -> None:
    assert get_pattern(VulnClass.UNKNOWN) is None
    assert get_pattern("no_such_class") is None


def test_pattern_entries_are_complete() -> None:
    for cls in PATTERNS:
        pattern = PATTERNS[cls]
        assert pattern.simplified_name
        assert pattern.description
        assert pattern.cwe_name
        if cls is not VulnClass.UNKNOWN:
            assert pattern.cwe_id and pattern.cwe_id.startswith("CWE-")
            assert pattern.bad_example
            assert pattern.good_example
            assert pattern.bad_example != pattern.good_example
            assert pattern.references


def test_pattern_root_causes_derive_from_mapper() -> None:
    for cls in PATTERNS:
        if cls is VulnClass.UNKNOWN:
            assert PATTERNS[cls].root_causes == ()
        else:
            assert PATTERNS[cls].root_causes


def test_pattern_for_finding_reads_vuln_class() -> None:
    pattern = pattern_for_finding({"vuln_class": "sqli"})
    assert pattern is not None and pattern.cwe_id == "CWE-89"
    assert pattern_for_finding({}) is None
    assert pattern_for_finding({"vuln_class": "unknown"}) is None


def test_coverage_reports_mapped_and_unmapped() -> None:
    report = coverage()
    assert report["mapped"] >= 30
    assert report["mapped"] + report["unmapped"] == report["vocabulary_size"]


# ---------------------------------------------------------------------------
# Task 2: root-cause mapper
# ---------------------------------------------------------------------------


def test_classify_is_total_over_vocabulary_except_unknown() -> None:
    for member in VulnClass:
        if member is VulnClass.UNKNOWN:
            assert classify(member) is None
        else:
            assert classify(member) is not None


def test_classify_accepts_strings_and_rejects_garbage() -> None:
    assert classify("sqli") is RootCause.INPUT_TRUST
    assert classify("not-a-class") is None


def test_causes_match_primary_classification() -> None:
    for member in VulnClass:
        all_causes = causes(member)
        if all_causes is None:
            assert classify(member) is None
        else:
            assert classify(member) is all_causes[0]


def test_explain_covers_every_cause() -> None:
    for cause in RootCause:
        text = explain(cause)
        assert text and len(text) > 40


def test_classes_for_cause_partition_the_vocabulary() -> None:
    seen: set[VulnClass] = set()
    for cause in RootCause:
        members = classes_for_cause(cause)
        assert members, "every cause owns at least one class"
        seen.update(members)
    assert seen == {m for m in VulnClass if m is not VulnClass.UNKNOWN}


# ---------------------------------------------------------------------------
# Task 3: context guide
# ---------------------------------------------------------------------------


def test_context_tiers_exist_for_every_mapped_class() -> None:
    for member in VulnClass:
        guidance = context_guidance(member)
        assert set(guidance) == {
            "acceptable", "warning", "dangerous", "note", "known",
        }
        if member is VulnClass.UNKNOWN:
            assert guidance["known"] is False
            assert guidance["dangerous"] == []
        else:
            assert guidance["known"] is True
            assert guidance["dangerous"], f"{member} needs a dangerous tier"


def test_context_guidance_for_garbage_string_is_honest() -> None:
    guidance = context_guidance("not-a-class")
    assert guidance["known"] is False
    assert guidance["note"]


def test_xss_dangerous_tier_covers_stored_cross_user() -> None:
    guidance = context_guidance(VulnClass.XSS)
    assert any("stored" in item for item in guidance["dangerous"])


# ---------------------------------------------------------------------------
# Shared finding fixtures for Tasks 4-12
# ---------------------------------------------------------------------------


def _finding(**overrides: Any) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "finding_id": "f-1",
        "vuln_class": "sqli",
        "severity": "critical",
        "confidence": "confirmed",
        "url": "http://lab.example/search?q=blood+pressure&page=2",
        "request_method": "GET",
        "target_param": "q",
        "title": "SQL injection in search",
    }
    finding.update(overrides)
    return finding


# ---------------------------------------------------------------------------
# Task 4: locator (redaction contract)
# ---------------------------------------------------------------------------


def test_locator_keeps_names_and_drops_values() -> None:
    loc = locate(_finding())
    assert loc["origin"] == "http://lab.example"
    assert loc["path"] == "/search"
    assert loc["method"] == "GET"
    assert loc["param"] == "q"
    assert "page" in loc["params"]
    assert "blood" not in str(loc)  # value never survives


def test_locator_missing_fields_stay_none() -> None:
    loc = locate({"finding_id": "f-2"})
    assert loc["origin"] is None
    assert loc["path"] is None
    assert loc["method"] is None
    assert loc["param"] is None


def test_locator_handles_path_only_urls() -> None:
    loc = locate({"url": "http://lab.example/api/items/177"})
    assert loc["path"] == "/api/items/177"
    assert loc["params"] == []


# ---------------------------------------------------------------------------
# Task 5: exploit scenario
# ---------------------------------------------------------------------------


def test_scenario_steps_exist_for_mapped_classes() -> None:
    for member in VulnClass:
        result = scenario_steps(member)
        if member is VulnClass.UNKNOWN:
            assert result["steps"] == [] and result["known"] is False
        else:
            assert result["steps"], f"{member} needs scenario steps"
            assert result["known"] is True


def test_scenario_rejects_garbage_class() -> None:
    result = scenario_steps("nope")
    assert result["steps"] == [] and result["reason"]


# ---------------------------------------------------------------------------
# Task 6: impact explainer
# ---------------------------------------------------------------------------


def test_impact_and_mitigations_for_mapped_classes() -> None:
    for member in VulnClass:
        impact = business_impact(member)
        if member is VulnClass.UNKNOWN:
            assert impact["known"] is False
            assert impact["interim_mitigations"] == []
        else:
            assert impact["impact"]
            assert impact["interim_mitigations"], (
                f"{member} needs at least one interim mitigation"
            )


def test_impact_honest_for_unknown_string() -> None:
    impact = business_impact("mystery")
    assert impact["known"] is False
    assert impact["impact"]  # generic honest text, not a guess


# ---------------------------------------------------------------------------
# Task 7: fix templates
# ---------------------------------------------------------------------------


def test_fix_template_exists_for_mapped_classes() -> None:
    for member in VulnClass:
        template = fix_template(member)
        if member is VulnClass.UNKNOWN:
            assert template is None
        else:
            assert template is not None
            assert template.concept
            assert template.bad_code != template.good_code


def test_fix_template_framework_variants_are_paired() -> None:
    template = fix_template("sqli")
    assert template is not None and template.framework_variants
    for key, (bad, good) in template.framework_variants.items():
        assert key and bad and good and bad != good


# ---------------------------------------------------------------------------
# Task 8: action plan
# ---------------------------------------------------------------------------


def test_action_plan_tiers_by_severity() -> None:
    plan = build_action_plan([
        _finding(finding_id="f-1", severity="critical"),
        _finding(finding_id="f-2", severity="medium", vuln_class="xss"),
        _finding(finding_id="f-3", severity="low", vuln_class="csp"),
    ])
    assert plan["counts"]["urgent"] == 1
    assert plan["counts"]["proactive"] == 2
    assert [i["finding_id"] for i in plan["urgent"]] == ["f-1"]
    assert plan["counts"]["total"] == 3


def test_action_plan_skips_unclassified_honestly() -> None:
    plan = build_action_plan([
        {"finding_id": "f-9", "severity": "high"},  # no vuln_class
        _finding(finding_id="f-1"),
    ])
    assert plan["skipped_unclassified"] == 1
    assert plan["counts"]["urgent"] == 1


def test_action_plan_preventive_dedupes_by_class() -> None:
    plan = build_action_plan([
        _finding(finding_id="f-1"),
        _finding(finding_id="f-2", url="http://lab.example/x?id=1"),
    ])
    assert plan["counts"]["preventive"] == 1
    entry = plan["preventive"][0]
    assert entry["vuln_class"] == "sqli"
    assert sorted(entry["finding_ids"]) == ["f-1", "f-2"]
    assert entry["fix_concept"]


# ---------------------------------------------------------------------------
# Task 9: verification steps
# ---------------------------------------------------------------------------


def test_checklist_covers_mapped_classes_with_three_parts() -> None:
    for member in VulnClass:
        steps = checklist(member)
        if member is VulnClass.UNKNOWN:
            assert steps == []
        else:
            assert len(steps) >= 3, f"{member} needs a full checklist"
            assert any(step.startswith("retest:") for step in steps)
            assert any(step.startswith("negative control:") for step in steps)
            assert any(step.startswith("regression:") for step in steps)


def test_checklist_empty_for_garbage() -> None:
    assert checklist("nope") == []


# ---------------------------------------------------------------------------
# Task 10: developer report
# ---------------------------------------------------------------------------


def test_developer_report_card_is_complete() -> None:
    report = build_developer_report([_finding()])
    card = report["cards"][0]
    assert card["cwe"]["id"] == "CWE-89"
    assert card["root_cause"] == "input_trust"
    assert card["root_cause_explanation"]
    assert card["exploit_scenario"]
    assert card["business_impact"]
    assert card["interim_mitigations"]
    assert card["fix"]["concept"]
    assert card["fix"]["good_example"]
    assert card["verification_checklist"]
    assert "not a re-run" in card["non_claim"]


def test_developer_report_counts_and_skips() -> None:
    report = build_developer_report([
        _finding(finding_id="f-1"),
        {"finding_id": "f-9", "vuln_class": "unknown", "severity": "high"},
    ])
    assert report["counts"]["cards"] == 1
    assert report["counts"]["total_findings"] == 2
    assert report["skipped_unclassified"] == 1


# ---------------------------------------------------------------------------
# Task 11: executive summary
# ---------------------------------------------------------------------------


def test_executive_summary_counts_match_input() -> None:
    summary = build_executive_summary([
        _finding(finding_id="f-1", severity="critical"),
        _finding(finding_id="f-2", severity="critical"),
        _finding(finding_id="f-3", severity="medium", vuln_class="xss"),
        {"finding_id": "f-9"},
    ])
    assert summary["counts_by_severity"]["critical"] == 2
    assert summary["counts_by_severity"]["medium"] == 1
    assert summary["counts_by_class"] == {"sqli": 2, "xss": 1}
    assert summary["total_findings"] == 4
    assert summary["skipped_unclassified"] == 1
    assert len(summary["top_actions"]) == 2
    assert summary["top_actions"][0]["vuln_class"] == "sqli"


def test_exposure_wording_tracks_counts() -> None:
    critical = build_executive_summary(
        [_finding(severity="critical")]
    )["exposure"]
    assert "critical" in critical
    medium_only = build_executive_summary(
        [_finding(severity="medium", vuln_class="xss")]
    )["exposure"]
    assert "medium" in medium_only
    empty = build_executive_summary([])["exposure"]
    assert "No classified findings" in empty


# ---------------------------------------------------------------------------
# Task 12: priority dashboard
# ---------------------------------------------------------------------------


def test_dashboard_orders_and_derives_scores() -> None:
    dashboard = build_priority_dashboard([
        _finding(finding_id="f-1"),
        _finding(finding_id="f-2", severity="low", vuln_class="csp",
                 url="http://lab.example/"),
        {"finding_id": "f-9"},
    ])
    assert dashboard["skipped_unclassified"] == 1
    rows = dashboard["rows"]
    assert [r["finding_id"] for r in rows] == ["f-1", "f-2"]
    top = rows[0]
    expected = round(
        min(100.0, 1.0 * top["exploitability"] * 1.0 / 1.5 * 100.0), 1
    )
    assert top["priority"] == expected
    assert 0 <= top["priority"] <= 100


def test_dashboard_spread_raises_repeated_class() -> None:
    single = build_priority_dashboard([_finding(finding_id="f-1")])
    doubled = build_priority_dashboard([
        _finding(finding_id="f-1"),
        _finding(finding_id="f-2", url="http://lab.example/x?id=2"),
    ])
    assert doubled["rows"][0]["spread"] > single["rows"][0]["spread"]


# ---------------------------------------------------------------------------
# Task 13: report wiring in hunt_state
# ---------------------------------------------------------------------------


def test_report_carries_remediation_when_findings_classified() -> None:
    state = AutonomousHuntState(
        engagement_id="e1", target_url="http://lab.example/"
    )
    state.findings = [_finding()]
    report = state.to_report_json()
    section = report["remediation"]
    assert section["executive_summary"]["counts_by_class"] == {"sqli": 1}
    assert section["priority_dashboard"]["rows"][0]["finding_id"] == "f-1"
    assert "non_claim" in section


def test_report_omits_remediation_without_classified_findings() -> None:
    state = AutonomousHuntState(
        engagement_id="e1", target_url="http://lab.example/"
    )
    # Minimal proof-bundle-linked finding: no vuln_class, no severity.
    state.findings = [{"finding_id": "f-9", "proof_digest": "x"}]
    report = state.to_report_json()
    assert "remediation" not in report
    empty = AutonomousHuntState(
        engagement_id="e1", target_url="http://lab.example/"
    )
    assert "remediation" not in empty.to_report_json()


# --- Red-team v77.1: regressions for the five proven bugs ----------------


def test_dashboard_skips_unknown_class_without_crash() -> None:
    # RT1: UNKNOWN resolved fine but _EFFORT had no entry -> KeyError.
    dashboard = build_priority_dashboard(
        [{"finding_id": "f-1", "severity": "high", "vuln_class": "unknown"}]
    )
    assert dashboard["rows"] == []
    assert dashboard["skipped_unclassified"] == 1


def test_locator_strips_credentials_from_origin() -> None:
    # RT2: userinfo in the netloc leaked into origin.
    located = locate(
        {
            "finding_id": "f-1",
            "url": "http://admin:hunter2@site.test/x?a=1",
            "method": "GET",
        }
    )
    assert located["origin"] == "http://site.test"
    assert "hunter2" not in json.dumps(located)


def test_summary_never_invents_a_none_class() -> None:
    # RT3: a missing class used to be counted under the literal "None".
    summary = build_executive_summary([{"finding_id": "f-1", "severity": "high"}])
    assert summary["counts_by_class"] == {}
    assert summary["skipped_unclassified"] == 1
    assert summary["counts_by_severity"]["high"] == 0


def test_summary_treats_unknown_class_as_skipped() -> None:
    summary = build_executive_summary(
        [{"finding_id": "f-1", "severity": "high", "vuln_class": "unknown"}]
    )
    assert summary["counts_by_class"] == {}
    assert summary["skipped_unclassified"] == 1


def test_enum_carried_findings_resolve_everywhere() -> None:
    # RT4: str(VulnClass.SQLI) == "VulnClass.SQLI" corrupted every lookup.
    enum_finding = {
        "finding_id": "f-1",
        "severity": Severity.HIGH,
        "vuln_class": VulnClass.SQLI,
    }
    plan = build_action_plan([enum_finding])
    assert plan["skipped_unclassified"] == 0
    assert plan["counts"]["urgent"] == 1
    summary = build_executive_summary([enum_finding])
    assert summary["counts_by_class"] == {"sqli": 1}
    dashboard = build_priority_dashboard([enum_finding])
    assert dashboard["rows"][0]["vuln_class"] == "sqli"
    report = build_developer_report([enum_finding])
    assert report["counts"]["cards"] == 1
    card = report["cards"][0]
    assert card["cwe"]["id"] is not None
    assert card["fix"]["concept"] is not None
    assert card["business_impact"] is not None


def test_preventive_ids_exclude_skipped_findings() -> None:
    # RT5: a finding skipped for a bad severity was relisted in ids.
    plan = build_action_plan(
        [
            {"finding_id": "g-1", "severity": "nonsense", "vuln_class": "xss"},
            {"finding_id": "g-2", "severity": "low", "vuln_class": "xss"},
        ]
    )
    assert plan["preventive"][0]["finding_ids"] == ["g-2"]


def test_report_with_single_unknown_finding_is_honest() -> None:
    # Wiring: one unknown-class finding is an honest absence, so no
    # classified severity exists and the remediation section stays out
    # entirely (the report must not imply guidance over nothing).
    state = AutonomousHuntState(
        engagement_id="e1", target_url="http://lab.example/"
    )
    state.findings = [
        {"finding_id": "f-1", "severity": "high", "vuln_class": "unknown"}
    ]
    report = state.to_report_json()
    assert "remediation" not in report
