"""Tests for the engagement report renderer (v78, Task 3)."""

from __future__ import annotations

import json
from typing import Any

from webpent.autonomous import AutonomousHuntState
from webpent.reporting import build_engagement_report


def _payload_with_findings() -> dict[str, Any]:
    state = AutonomousHuntState(engagement_id="e-1", target_url="http://lab.example/")
    state.findings = [
        {
            "finding_id": "f-1",
            "title": "Reflected XSS",
            "severity": "high",
            "vuln_class": "xss",
        },
        {
            "finding_id": "f-2",
            "title": "Unclassified anomaly",
            "severity": "low",
            "vuln_class": "unknown",
        },
    ]
    return state.to_report_json()


def test_markdown_renders_core_sections() -> None:
    payload = _payload_with_findings()
    report = build_engagement_report(payload, fmt="markdown")
    content = report["content"]
    assert report["fmt"] == "markdown"
    assert "# WebPent engagement report" in content
    assert "| ID | Title | Severity | Class |" in content
    assert "f-1" in content and "Reflected XSS" in content
    assert report["non_claim"] in content


def test_html_is_self_contained_and_escaped() -> None:
    payload = _payload_with_findings()
    payload["findings"][0]["title"] = "<script>alert(1)</script>"
    report = build_engagement_report(payload, fmt="html")
    content = report["content"]
    assert report["fmt"] == "html"
    # No external resources: no script/link tags pointing at URLs.
    assert "<script src=" not in content
    assert "<link" not in content
    assert "src=" not in content
    assert "<iframe" not in content
    # The injected markup is escaped, never executed.
    assert "<script>alert(1)" not in content
    assert "&lt;script&gt;" in content
    assert "&lt;!DOCTYPE" not in content  # document is valid, not double-escaped


def test_absent_sections_are_skipped_not_invented() -> None:
    state = AutonomousHuntState(engagement_id="e-2", target_url="http://lab.example/")
    payload = state.to_report_json()
    report = build_engagement_report(payload, fmt="markdown")
    content = report["content"]
    assert "## Findings" not in content
    assert "## Remediation guidance" not in content
    assert "## Executive summary" not in content


def test_query_values_from_findings_never_appear() -> None:
    payload = _payload_with_findings()
    payload["findings"][0]["url"] = "http://lab.example/x?secret=value123"
    report = build_engagement_report(payload, fmt="markdown")
    assert "value123" not in report["content"]
    report = build_engagement_report(payload, fmt="html")
    assert "value123" not in report["content"]


def test_remediation_non_claim_carried_through() -> None:
    payload = _payload_with_findings()
    report = build_engagement_report(payload, fmt="html")
    assert "nothing re-ran" in report["content"]


def test_unsupported_format_refuses() -> None:
    try:
        build_engagement_report({}, fmt="pdf")
    except ValueError as exc:
        assert "unsupported report format" in str(exc)
    else:
        raise AssertionError("expected ValueError for unsupported format")


def test_payload_round_trips_through_json() -> None:
    payload = json.loads(json.dumps(_payload_with_findings(), default=str))
    report = build_engagement_report(payload, fmt="markdown")
    assert "e-1" in report["content"]


def test_markdown_priority_is_cell_escaped() -> None:
    payload = _payload_with_findings()
    payload["remediation"] = {
        "priority_dashboard": {
            "rows": [
                {
                    "finding_id": "f-1",
                    "vuln_class": "xss",
                    "severity": "high",
                    "effort": "S",
                    "priority": "1 | INJECTED |",
                }
            ]
        }
    }
    content = build_engagement_report(payload, fmt="markdown")["content"]
    row = next(line for line in content.splitlines() if "INJECTED" in line)
    # The injected pipe stays escaped inside its own cell; the row keeps 5 columns.
    assert "\\| INJECTED \\|" in row
    assert row.count("|") - row.count("\\|") == 6


def test_markdown_counts_keys_and_header_are_injection_safe() -> None:
    payload: dict[str, Any] = {
        "engagement_id": "e-9\n## INJECTED",
        "counts": {"findings\n## INJECTED": 3},
        "iteration": "1\nINJECTED",
        "max_iterations": 5,
    }
    content = build_engagement_report(payload, fmt="markdown")["content"]
    # Newlines in payload values must never start a new line in the document:
    # no injected line may begin with a heading marker.
    assert not any(line.startswith("## INJECTED") for line in content.splitlines())


def test_empty_payload_does_not_render_none_placeholders() -> None:
    content = build_engagement_report({}, fmt="markdown")["content"]
    assert "None of None" not in content
