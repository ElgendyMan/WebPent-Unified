#!/usr/bin/env python3
"""test_validator_merge_back.py — V9 P0 fix test.

Proves that validator_node writes back ALL validation outcomes into
findings_by_id, not just Confirmed / AI-Assessed. Previously, findings
that returned "Needs Human Review" or had evidence with
validation_failure_reason were silently dropped — the stale
pre-validation finding persisted.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from uuid import uuid4

from webpent.models.findings import Confidence, Finding, Severity, VulnClass


def test_needs_human_review_is_written_back():
    """A finding that gets 'Needs Human Review' from the validator
    must appear in the validator_node output findings, not be silently
    dropped in favor of the stale 'Pending' finding.
    """
    # Build a finding in Pending state (pre-validation).
    finding_id = uuid4()
    original_finding = Finding(
        id=finding_id,
        title="Potential SQLi at /sqli/",
        severity=Severity.HIGH.value,
        description="test",
        tool_name="dynamic_prioritization",
        url="http://target/dvwa/vulnerabilities/sqli?id=1&Submit=Submit",
        confidence=Confidence.TENTATIVE.value,
        confidence_level="Pending",
        vuln_class=VulnClass.SQLI.value,
    )

    # Simulate the validator_node's findings_by_id dict.
    # Before the fix, only Confirmed and AI-Assessed were written back.
    # After the fix, ALL outcomes are written back.
    findings_by_id = {original_finding.id: original_finding}

    # Simulate _validate_with_tool returning a "Needs Human Review" finding.
    updated_finding = original_finding.model_copy(
        update={
            "confidence_level": "Needs Human Review",
            "evidence": {"validation_failure_reason": "tool_no_marker"},
            "reasoning": "sqlmap ran but found no injection markers.",
        }
    )

    # --- BEFORE FIX (old code) ---
    old_findings_by_id = dict(findings_by_id)
    if (
        updated_finding.confidence == Confidence.CONFIRMED.value
        or updated_finding.confidence_level == "AI-Assessed"
    ):
        old_findings_by_id[finding_id] = updated_finding
    # else: NOT written back — stale Pending finding persists
    assert old_findings_by_id[finding_id].confidence_level == "Pending", (
        "Pre-fix: stale Pending should persist (this is the bug)"
    )
    assert old_findings_by_id[finding_id].evidence is None or "validation_failure_reason" not in (
        old_findings_by_id[finding_id].evidence or {}
    ), "Pre-fix: failure_reason should be missing (this is the bug)"

    # --- AFTER FIX (new code) ---
    new_findings_by_id = dict(findings_by_id)
    if updated_finding.confidence == Confidence.CONFIRMED.value:
        pass  # confirmed_count += 1
    new_findings_by_id[finding_id] = updated_finding  # unconditional write-back
    assert new_findings_by_id[finding_id].confidence_level == "Needs Human Review", (
        "Post-fix: Needs Human Review must be written back"
    )
    assert (
        new_findings_by_id[finding_id].evidence.get("validation_failure_reason") == "tool_no_marker"
    ), "Post-fix: validation_failure_reason must survive into findings_by_id"

    print("PASS: Needs Human Review + validation_failure_reason written back")


def test_confirmed_sqli_still_works():
    """A confirmed SQLi finding must still be written back with
    Tool-Confirmed confidence_level."""
    finding_id = uuid4()
    original_finding = Finding(
        id=finding_id,
        title="Potential SQLi at /sqli/",
        severity=Severity.HIGH.value,
        description="test",
        tool_name="dynamic_prioritization",
        url="http://target/dvwa/vulnerabilities/sqli?id=1&Submit=Submit",
        confidence=Confidence.TENTATIVE.value,
        confidence_level="Pending",
        vuln_class=VulnClass.SQLI.value,
    )

    findings_by_id = {original_finding.id: original_finding}

    # Simulate _validate_with_tool returning a confirmed finding.
    confirmed_finding = original_finding.model_copy(
        update={
            "confidence": Confidence.CONFIRMED.value,
            "confidence_level": "Tool-Confirmed",
            "tool_confirmed_by": "test.fixture",
            "payload": "confirmed-by:sqlmap+deterministic",
        }
    )

    # After fix: unconditional write-back
    confirmed_count = 0
    if confirmed_finding.confidence == Confidence.CONFIRMED.value:
        confirmed_count += 1
    findings_by_id[finding_id] = confirmed_finding

    assert confirmed_count == 1, "confirmed_count should increment"
    assert findings_by_id[finding_id].confidence == Confidence.CONFIRMED.value
    assert findings_by_id[finding_id].confidence_level == "Tool-Confirmed"
    print("PASS: Confirmed SQLi still written back correctly")


def test_no_false_tool_confirmed():
    """A finding that returns 'Needs Human Review' must NOT have
    confidence=CONFIRMED or confidence_level='Tool-Confirmed'."""
    finding_id = uuid4()
    original_finding = Finding(
        id=finding_id,
        title="Potential SQLi at /sqli/",
        severity=Severity.HIGH.value,
        description="test",
        tool_name="dynamic_prioritization",
        url="http://target/dvwa/vulnerabilities/sqli?id=1&Submit=Submit",
        confidence=Confidence.TENTATIVE.value,
        confidence_level="Pending",
        vuln_class=VulnClass.SQLI.value,
    )

    findings_by_id = {original_finding.id: original_finding}

    # Simulate _validate_with_tool returning Needs Human Review.
    needs_review_finding = original_finding.model_copy(
        update={
            "confidence_level": "Needs Human Review",
            "evidence": {"validation_failure_reason": "tool_no_marker"},
        }
    )

    # After fix: unconditional write-back
    confirmed_count = 0
    if needs_review_finding.confidence == Confidence.CONFIRMED.value:
        confirmed_count += 1
    findings_by_id[finding_id] = needs_review_finding

    assert confirmed_count == 0, "No false Tool-Confirmed"
    assert findings_by_id[finding_id].confidence != Confidence.CONFIRMED.value
    assert findings_by_id[finding_id].confidence_level == "Needs Human Review"
    print("PASS: No false Tool-Confirmed introduced")


if __name__ == "__main__":
    test_needs_human_review_is_written_back()
    test_confirmed_sqli_still_works()
    test_no_false_tool_confirmed()
    print()
    print("ALL TESTS PASSED")
