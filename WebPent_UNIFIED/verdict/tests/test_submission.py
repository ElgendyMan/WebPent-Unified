"""U-VERDICT-5 — Submission Pipeline tests (6 tests)."""

from __future__ import annotations

import inspect

import pytest
from verdict_tool.classifier import FindingClassifier
from verdict_tool.submission import SECTIONS, SubmissionError, SubmissionPipeline
from verdict_tool.tracking import Workspace


@pytest.fixture
def pipeline(ws: Workspace) -> SubmissionPipeline:
    state = ws.load()
    FindingClassifier(state, ws).register("f-1", "target_a", "sqli",
                                          "high", 0.9)
    return SubmissionPipeline(state, ws)


def _confirm(pipeline: SubmissionPipeline) -> None:
    FindingClassifier(pipeline.state, pipeline.ws).classify(
        "f-1", "confirmed", re_test_evidence=["shots/f1.png"],
        impact_confirmed="data exposure")


def test_report_contains_all_sections(pipeline: SubmissionPipeline) -> None:
    _confirm(pipeline)
    report = pipeline.generate_report("f-1", title="Union SQLi",
                                      program="example")
    for section in SECTIONS:
        assert f"## {section}" in report
    assert "Union SQLi" in report
    assert "- shots/f1.png" in report


def test_report_only_for_confirmed(pipeline: SubmissionPipeline) -> None:
    with pytest.raises(SubmissionError, match="unclassified"):
        pipeline.generate_report("f-1")
    FindingClassifier(pipeline.state, pipeline.ws).classify(
        "f-1", "false_positive", re_test_evidence=["e.png"],
        reason="waf interference")
    with pytest.raises(SubmissionError, match="confirmed"):
        pipeline.generate_report("f-1")


def test_screenshot_required(ws: Workspace, pipeline: SubmissionPipeline
                             ) -> None:
    _confirm(pipeline)
    pipeline.write_report("f-1")
    with pytest.raises(SubmissionError, match="screenshot"):
        pipeline.record_submission("f-1", "H1-123", "")
    with pytest.raises(SubmissionError, match="does not exist"):
        pipeline.record_submission("f-1", "H1-123", "shots/missing.png")


def test_record_requires_report_on_disk(ws: Workspace,
                                        pipeline: SubmissionPipeline
                                        ) -> None:
    _confirm(pipeline)
    (ws.root / "shots").mkdir(exist_ok=True)
    (ws.root / "shots" / "f1.png").write_bytes(b"png")
    with pytest.raises(SubmissionError, match="report generation first"):
        pipeline.record_submission("f-1", "H1-123", "shots/f1.png")
    pipeline.write_report("f-1")
    record = pipeline.record_submission("f-1", "H1-123", "shots/f1.png")
    assert record.platform_id == "H1-123"
    assert record.report_path == "submissions/f-1.md"
    assert len(pipeline.get_tracker()) == 1
    assert ws.load().submissions[0]["finding_id"] == "f-1"


def test_no_auto_submission() -> None:
    """The pipeline must never submit anything itself."""
    import verdict_tool.submission as mod

    source = inspect.getsource(mod)
    for banned in ("urllib", "requests", "httpx", "socket", "urlopen",
                   "POST ", "api.hackerone"):
        assert banned not in source, f"network code found: {banned}"
    pipeline_methods = dir(SubmissionPipeline)
    for banned in ("submit", "send", "post", "upload", "auto_submit"):
        assert not any(
            name == banned or name.startswith(f"auto_{banned}")
            for name in pipeline_methods
        ), f"suspect method: {banned}"


def test_tracker_updates_state(ws: Workspace, pipeline: SubmissionPipeline
                               ) -> None:
    _confirm(pipeline)
    (ws.root / "shots").mkdir(exist_ok=True)
    (ws.root / "shots" / "f1.png").write_bytes(b"png")
    pipeline.write_report("f-1")
    pipeline.record_submission("f-1", "H1-123", "shots/f1.png")
    state = ws.load()
    assert state.submissions[0]["platform"] == "hackerone"
    assert state.submissions[0]["status"] == "submitted"
