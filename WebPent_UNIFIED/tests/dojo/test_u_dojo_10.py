"""U-DOJO-10: the case study writer (plan Task 10)."""

from __future__ import annotations

import pytest

from webpent.dojo.case_study import CaseStudyWriter
from webpent.dojo.scenario_library import ScenarioLibrary
from webpent.dojo.sparring import RoundLog, SparringMatchResult

CONFIG_DIR = "config/dojo/scenarios"


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


@pytest.fixture(scope="module")
def scenario(library: ScenarioLibrary):
    return library.get("sqli-01")


def _match(lessons=("advisory: defense add_input_filter was bypassed",)) -> SparringMatchResult:
    return SparringMatchResult(
        scenario_id="sqli-01",
        red_score=92.5,
        blue_score=0.0,
        winner="red",
        rounds_log=(
            RoundLog(round_no=1, pattern="none", red_success=True,
                     red_score=92.5, blue_score=0.0),
            RoundLog(round_no=2, pattern="rate_limit_lockout", red_success=True,
                     red_score=80.0, blue_score=0.0),
        ),
        lessons=lessons,
    )


def test_case_study_from_match_renders_markdown(scenario):
    text = CaseStudyWriter.from_match(_match(), scenario)
    assert text.startswith("# ")
    assert "sqli-01" in text
    assert "| 1 |" in text and "| 2 |" in text
    assert "rate_limit_lockout" in text
    assert "red" in text and "92.5" in text


def test_export_sanitized(scenario):
    """No token/cookie/secret-shaped string survives the export (redaction)."""
    leaky = _match(
        lessons=(
            "advisory: captured Authorization: Bearer live-secret-token-99 "
            "and Cookie: session=abc123 and token=hunter2",
        )
    )
    text = CaseStudyWriter.from_match(leaky, scenario)
    assert "live-secret-token-99" not in text
    assert "abc123" not in text
    assert "hunter2" not in text
    assert "[REDACTED" in text


def test_case_study_deterministic(scenario):
    first = CaseStudyWriter.from_match(_match(), scenario)
    second = CaseStudyWriter.from_match(_match(), scenario)
    assert first == second


def test_includes_ground_truth_and_lessons(scenario):
    match = _match()
    text = CaseStudyWriter.from_match(match, scenario)
    assert scenario.vuln_class in text
    assert scenario.location in text
    assert scenario.signature in text
    for lesson in match.lessons:
        assert lesson in text


def test_case_study_is_advisory_marked(scenario):
    text = CaseStudyWriter.from_match(_match(), scenario)
    assert "advisory" in text
