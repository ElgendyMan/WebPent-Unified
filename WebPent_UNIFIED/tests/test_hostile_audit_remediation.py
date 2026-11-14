"""Regression tests for hostile-audit remediation (TEAM-RED D1/D2/D3).

Read-only assertions on source + model contract. No network, no target contact.
Run: uv run pytest -q tests/test_hostile_audit_remediation.py
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_PY = REPO_ROOT / "src/webpent/agents/validator/agent.py"
BUILDER_PY = REPO_ROOT / "src/webpent/graph/builder.py"


def test_sqli_auto_confirm_bypass_removed():
    """D1/P1: the sqli special-case that auto-persisted Tool-Confirmed findings
    without verify_replay_evidence must be gone."""
    src = AGENT_PY.read_text()
    assert "sqli_tool_native_confirmation_no_differential_applicable" not in src, (
        "SQLi auto-confirm bypass string still present"
    )
    assert (
        "sqli_tool_native_evidence_preserved_but_auto_promotion_removed_fail_closed" in src
    ), "SQLi fail-closed replacement missing"
    # The removed block called _persist_finding_incrementally inside the sqli branch.
    # Source-level: the fail-closed replacement must NOT call persist.
    block_start = src.find("if vuln_class == \"sqli\" and differential_observation is None:")
    assert block_start != -1, "sqli guard clause missing entirely"
    block_end = src.find("return updated_finding", block_start)
    block = src[block_start:block_end]
    assert "_persist_finding_incrementally" not in block, (
        "sqli fail-closed branch still persists findings"
    )


def test_open_redirect_verifier_no_hardcoded_true():
    """D3/P2: open_redirect must not rubber-stamp the verifier with hardcoded True."""
    src = AGENT_PY.read_text()
    # The open_redirect call site previously had causal_signal=True, negative_control_complete=True.
    # After fix, no hardcoded True pair remains at any verify_replay_evidence call.
    assert "causal_signal=True,\n            negative_control_complete=True" not in src, (
        "hardcoded True verifier rubber-stamp still present"
    )
    assert "negative_control=evidence[\"baseline\"]" not in src, (
        "negative_control reused from baseline still present"
    )


def test_avi_promoted_findings_merge_present():
    """D2/P1: _research_campaign_node must merge AVI promoted findings into state findings."""
    src = BUILDER_PY.read_text()
    assert "avi_promoted_merged" in src, "AVI merge flag missing from builder"
    assert "out[\"findings\"] = [*list(state.get(\"findings\") or []), *_avi_promoted]" in src, (
        "AVI promoted findings not appended to state findings"
    )
    assert "avi_promoted_merge_failed" in src, "fail-visible merge-failure counter missing"


def test_finding_construction_for_avi_merge():
    """The Finding shape used by the merge must construct successfully."""
    from webpent.models.findings import Finding

    f = Finding(
        title="[AVI-promoted] IDOR finding test",
        severity="high",
        description="autonomously validated",
        tool_name="autonomous_validation_intelligence_v1",
        url="https://lab.example.com",
        vuln_class="idor",
        confidence="confirmed",
        confidence_level="Tool-Confirmed",
        reasoning="AVI PromotionPipeline decision: all_anti_fake_gates_passed",
        evidence={"avi_promoted": True, "avi_identity_bound": True},
        references=[],
    )
    assert f.confidence_level == "Tool-Confirmed"
    assert f.evidence["avi_promoted"] is True


def test_builder_imports_and_node_present():
    """The patched builder must import and expose the research_campaign node."""
    from webpent.graph import builder as b

    assert callable(b.build_graph)
    assert b.NODE_RESEARCH_CAMPAIGN == "research_campaign"
