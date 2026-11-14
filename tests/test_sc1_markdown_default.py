"""DEFECT SC-1 lock — default engagements must write the Markdown report.

Discovered by the scenario campaign (2026-09-15): initial_state normalizes
an absent ``report_formats`` into an EMPTY list, and reporter_node's
``selected_formats is None`` gate therefore never fired for default
engagements — the legacy Markdown report was silently skipped while
JSON/HTML/PDF still exported (export_all_formats defaults its own param).
An empty selection must mean "operator default" everywhere.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from webpent.agents.reporter import agent as reporter_agent
from webpent.models.targets import Target


def _base_state(report_formats):
    return {
        "target": Target(url="http://127.0.0.1:9/lab"),
        "findings": [],
        "hypotheses": [],
        "executive_summary": "Pre-computed summary.",
        "risk_score": "Low",
        "decision_log": [],
        "report_formats": report_formats,
        "scope_source": "inferred_from_url",
        "scope_declaration": {"source": "inferred_from_url"},
        "authentication_status": "authenticated",
        "identity_records": {"primary": {"validated": True}},
    }


@pytest.mark.parametrize("report_formats", [None, []])
def test_default_and_empty_formats_request_markdown(report_formats, tmp_path):
    """None AND the normalized [] must both produce a Markdown report."""
    saved: dict = {}

    def _fake_save(content, output_dir: Path, filename: str) -> Path:
        path = output_dir / filename
        path.write_text(content, encoding="utf-8")
        saved["content"] = content
        return path

    settings = MagicMock()
    settings.ensure_output_dir.return_value = tmp_path
    settings.enable_report_quality_gate = False
    with patch.object(
        reporter_agent, "get_settings", return_value=settings
    ), patch.object(
        reporter_agent, "_save_report", side_effect=_fake_save
    ), patch(
        "webpent.reporter.export.export_all_formats",
        return_value={"json": tmp_path / "r.json", "html": tmp_path / "r.html",
                      "pdf": None},
    ) as mock_export:
        result = reporter_agent.reporter_node(_base_state(report_formats))

    # The node must not degrade to export-only: markdown path ran and the
    # scenario declaration sections are present in the composed report.
    assert not result.get("markdown_failed", False)
    assert "content" in saved, "markdown report was not composed"
    assert "## Scope & Session Declaration" in saved["content"]
    assert "## Coverage Matrix" in saved["content"]
    mock_export.assert_called_once()


def test_explicit_md_selection_still_writes_markdown(tmp_path):
    """'md' remains an explicit opt-in with identical behavior."""
    saved: dict = {}

    def _fake_save(content, output_dir: Path, filename: str) -> Path:
        path = output_dir / filename
        path.write_text(content, encoding="utf-8")
        saved["content"] = content
        return path

    settings = MagicMock()
    settings.ensure_output_dir.return_value = tmp_path
    settings.enable_report_quality_gate = False
    with patch.object(
        reporter_agent, "get_settings", return_value=settings
    ), patch.object(
        reporter_agent, "_save_report", side_effect=_fake_save
    ), patch(
        "webpent.reporter.export.export_all_formats",
        return_value={"json": tmp_path / "r.json", "html": None, "pdf": None},
    ):
        reporter_agent.reporter_node(_base_state(["md"]))

    assert "content" in saved
    assert "# WebPent Engagement Report" in saved["content"]
