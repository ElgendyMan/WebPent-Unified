"""SCENARIO CONTRACT locks — reporter surfaces scope source + coverage matrix.

Operator workflow under audit: "URL + Credentials (+ Scope sometimes)".
Phase-11 requirement: the final report MUST declare where the boundaries
came from (scope_file vs inferred_from_url), the authentication outcome
(incl. principals + session liveness, redaction-safe), and a coverage
matrix across AuthZ / Input / Misconfig / Logic derived deterministically
from state — never from LLM narrative.
"""

from __future__ import annotations

from uuid import uuid4

from webpent.agents.reporter.agent import (
    _compose_markdown,
    _compose_scenario_sections,
    _scenario_auth_row,
    _scenario_scope_source_row,
)
from webpent.models.findings import Finding, Severity


def _finding(confidence_level: str = "Tool-Confirmed", tool: str = "sqlmap") -> Finding:
    return Finding(
        title="SQL injection in login",
        severity=Severity.HIGH,
        description="Synthetic scenario-contract finding.",
        tool_name=tool,
        url="https://app.example.test/login",
        confidence_level=confidence_level,
        id=uuid4(),
        # M1-B (E-1): model-level proof requirement.
        evidence={"tool_confirmed_by": "test.fixture"},
    )


def _state(**overrides):
    base = {
        "scope_source": "inferred_from_url",
        "scope_declaration": {"source": "inferred_from_url", "fingerprint": ""},
        "authentication_status": "authenticated",
        "identity_records": {"primary": {"validated": True}},
        "session_liveness": {
            "status": "healthy", "reauth_attempts": 1,
            "max_reauth_attempts": 2, "downgrade_requested": False,
        },
        "auth_surface_diff": {"counts": {"both": 4, "auth_only": 3, "anonymous_only": 1}},
        "bac_coverage_gaps": [],
        "hypotheses": ["h1", "h2"],
        "engagement_limitations": [{"reason": "single_account"}],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Scope source resolution
# ---------------------------------------------------------------------------

def test_scope_source_inferred_is_labelled_and_explained() -> None:
    source, detail = _scenario_scope_source_row(_state())
    assert source == "inferred_from_url"
    assert "ESTIMATES" in detail
    assert "same exact host" in detail


def test_scope_source_file_publishes_fingerprint() -> None:
    state = _state(
        scope_source="scope_file",
        scope_declaration={
            "source": "scope_file",
            "fingerprint": "sha256:deadbeef",
            "allow_entries": ["https://app.example.test"],
        },
    )
    source, detail = _scenario_scope_source_row(state)
    assert source == "scope_file"
    assert "contractual" in detail
    assert "sha256:deadbeef" in detail


# ---------------------------------------------------------------------------
# Authentication row (redaction-safe)
# ---------------------------------------------------------------------------

def test_auth_row_reports_status_principals_liveness_without_secrets() -> None:
    row = _scenario_auth_row(_state())
    assert "authenticated" in row
    assert "1 principal record(s)" in row
    assert "liveness=healthy" in row
    assert "reauth=1/2" in row
    # Secret-shaped material must never appear in the row.
    assert "cookie=" not in row and "password" not in row


def test_auth_row_declares_dead_session_downgrade() -> None:
    row = _scenario_auth_row(_state(session_liveness={
        "status": "dead", "reauth_attempts": 2,
        "max_reauth_attempts": 2, "downgrade_requested": True,
    }))
    assert "downgrade requested" in row


# ---------------------------------------------------------------------------
# Scenario sections composition
# ---------------------------------------------------------------------------

def test_sections_include_inferred_caveat_and_coverage_matrix() -> None:
    lines = _compose_scenario_sections(_state(), [_finding()])
    text = "\n".join(lines)
    assert "## Scope & Session Declaration" in text
    assert "inferred_from_url" in text
    assert "Inferred-scope caveat" in text
    assert "## Coverage Matrix" in text
    assert "Access control (BAC/IDOR)" in text
    assert "Input validation (SQLi/XSS/...)" in text
    assert "Misconfiguration & exposure" in text
    assert "Business logic" in text
    # Honest counters from state.
    assert "auth_only: 3" in text
    assert "Hypotheses recorded: 2" in text


def test_sections_surface_tool_backed_evidence_only() -> None:
    findings = [_finding("Tool-Confirmed", tool="sqlmap"),
                _finding("AI-Assessed", tool="hallucinatrix")]
    lines = _compose_scenario_sections(_state(), findings)
    text = "\n".join(lines)
    assert "sqlmap" in text
    # LLM-only tool claims must NOT be presented as tool-backed evidence.
    assert "hallucinatrix" not in text


def test_file_scope_produces_no_inferred_caveat() -> None:
    state = _state(
        scope_source="scope_file",
        scope_declaration={
            "source": "scope_file", "fingerprint": "sha256:aa",
            "allow_entries": ["https://app.example.test"],
            "exclude_paths": ["/admin"],
        },
    )
    text = "\n".join(_compose_scenario_sections(state, []))
    assert "Inferred-scope caveat" not in text
    assert "sha256:aa" in text


# ---------------------------------------------------------------------------
# Markdown integration (report carries the sections in the right slots)
# ---------------------------------------------------------------------------

def test_markdown_carries_declaration_up_top_and_matrix_in_appendix() -> None:
    sections = _compose_scenario_sections(_state(), [_finding()])
    md = _compose_markdown(
        "https://app.example.test", [_finding()], "Summary",
        scenario_sections=sections,
    )
    decl = md.index("## Scope & Session Declaration")
    summary = md.index("## Executive Summary")
    findings_idx = md.index("## Findings")
    matrix = md.index("## Coverage Matrix")
    assert decl < summary, "declaration must be surfaced directly under the header"
    assert findings_idx < matrix, "coverage matrix belongs to the appendix"


def test_markdown_without_sections_is_unchanged() -> None:
    md = _compose_markdown("https://app.example.test", [_finding()], "Summary")
    assert "## Scope & Session Declaration" not in md
    assert "## Coverage Matrix" not in md
    assert md.startswith("# WebPent Engagement Report")
