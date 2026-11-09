"""Regression tests for the IMPLEMENTATION-team residual fixes (R-04/R-06/R-07).

Each test maps 1:1 to a defect ID from the TEAM-2 verification report so a
future auditor can trace closure evidence directly.
"""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

from webpent.agents.reporter.agent import (
    _compose_markdown,
    _compute_stats,
    _render_findings_table,
)
from webpent.config.settings import get_settings
from webpent.models.findings import Finding, Severity
from webpent.reporter.export import build_report_data


def _finding(confidence_level: str = "Tool-Confirmed", title: str = "SSRF via callback") -> Finding:
    return Finding(
        title=title,
        severity=Severity.HIGH,
        description="Synthetic residual-regression finding.",
        tool_name="test",
        url="https://example.test/endpoint",
        confidence_level=confidence_level,
        id=uuid4(),
        # M1-B (E-1): model-level proof requirement.
        evidence={"tool_confirmed_by": "test.fixture"},
    )


# ---------------------------------------------------------------------------
# R-04 — DATABASE_URL alias precedence
# ---------------------------------------------------------------------------

def test_r04_namespaced_database_url_wins_over_ambient(monkeypatch) -> None:
    """WEBPENT_DATABASE_URL must beat a generic ambient DATABASE_URL."""
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./ambient-foreign.db")
    monkeypatch.setenv("WEBPENT_DATABASE_URL", "sqlite:///./namespaced-authority.db")
    get_settings.cache_clear()
    try:
        settings = get_settings()
        assert settings.database_url == "sqlite:///./namespaced-authority.db"
    finally:
        get_settings.cache_clear()


def test_r04_generic_alias_still_supported_for_legacy_deployments(monkeypatch) -> None:
    """Backward compatibility: deployments with only DATABASE_URL keep working."""
    monkeypatch.delenv("WEBPENT_DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./legacy-only.db")
    get_settings.cache_clear()
    try:
        settings = get_settings()
        assert settings.database_url == "sqlite:///./legacy-only.db"
    finally:
        get_settings.cache_clear()


def test_r04_suite_is_hermetic_against_ambient_database_url() -> None:
    """The conftest autouse fixture must have stripped ambient DB env vars.

    Under an operator shell exporting DATABASE_URL=junk, every test still
    starts from a clean env state — this assertion runs AFTER the fixture.
    """
    assert os.environ.get("DATABASE_URL") is None
    assert os.environ.get("WEBPENT_DATABASE_URL") is None


# ---------------------------------------------------------------------------
# R-06 — doctor knowledge_ready parity (reuses preflight check verbatim)
# ---------------------------------------------------------------------------

def test_r06_preflight_knowledge_check_finds_the_pack() -> None:
    """The pack root must resolve to the project root, not src/.

    Root cause fixed here: parents[2] anchored knowledge_pack lookup inside
    src/, so knowledge_ready was permanently a false "manifest missing".
    """
    from webpent.shared.preflight import _check_knowledge_ready

    report = _check_knowledge_ready()
    assert isinstance(report, dict)
    status = str(report.get("status") or "")
    assert "manifest.yaml missing" not in status, (
        "preflight must locate knowledge_pack/manifest.yaml from the src layout"
    )
    assert "knowledge_ready" in report


def test_r06_doctor_reuses_preflight_knowledge_check() -> None:
    """doctor._knowledge_readiness must delegate to preflight (no drift)."""
    import scripts.doctor as doctor
    from webpent.shared.preflight import _check_knowledge_ready

    knowledge = doctor._knowledge_readiness()
    direct = _check_knowledge_ready()
    assert knowledge is not None
    assert set(direct.keys()) == set(knowledge.keys()), (
        "doctor must surface the exact preflight knowledge fields"
    )


# ---------------------------------------------------------------------------
# R-07 — Refuted visibility in reports
# ---------------------------------------------------------------------------

def test_r07_report_data_counts_and_lists_refuted() -> None:
    # A Tool-Confirmed finding that SURVIVES the report-boundary evidence gate
    # needs a sealed proof bundle; reuse the canonical v26 fixture (dict-based,
    # which build_report_data accepts) so confirmed_count reflects a real
    # evidence-backed claim rather than an unsupported one (unsupported
    # Tool-Confirmed claims are demoted to Needs Human Review by design).
    from tests.test_v26_report_quality import _finding as _sealed_confirmed_finding

    findings: list = [
        _sealed_confirmed_finding(),
        _finding("Refuted"),
        _finding("AI-Assessed"),
    ]
    data = build_report_data("https://example.test", findings, "Summary", "Low")
    assert data["refuted_count"] == 1
    assert len(data["refuted_findings"]) == 1
    assert data["refuted_findings"][0]["confidence_level"] == "Refuted"
    # Stats honesty is unchanged: only evidence-backed Tool-Confirmed counts.
    assert data["confirmed_count"] == 1


def test_r07_markdown_has_refuted_section_with_strikethrough() -> None:
    findings = [_finding("Tool-Confirmed"), _finding("Refuted")]
    md = _compose_markdown("https://example.test", findings, "Summary")
    assert "## Refuted Findings (1)" in md
    assert "~~SSRF via callback~~" in md
    # The findings table strikes the refuted title too.
    assert "~~" in _render_findings_table(findings)


def test_r07_markdown_omits_refuted_section_when_none() -> None:
    findings = [_finding("Tool-Confirmed")]
    md = _compose_markdown("https://example.test", findings, "Summary")
    assert "## Refuted Findings" not in md


def test_r07_stats_include_refuted_count() -> None:
    findings = [_finding("Refuted"), _finding("Refuted"), _finding("Pending")]
    stats = _compute_stats(findings)
    assert stats["refuted_count"] == 2
    assert stats["confirmed_count"] == 0


def test_r07_html_template_renders_refuted_section(tmp_path: Path) -> None:
    from webpent.reporter.export import export_to_html

    findings = [_finding("Tool-Confirmed"), _finding("Refuted")]
    out = export_to_html(
        "https://example.test",
        findings,
        tmp_path,
        executive_summary="Summary",
        risk_score="Medium",
    )
    html = Path(out).read_text(encoding="utf-8")
    assert "Refuted Findings (1)" in html
    assert "refuted-title" in html
    assert "conf-refuted" in html
    assert "terminal" in html.lower()
