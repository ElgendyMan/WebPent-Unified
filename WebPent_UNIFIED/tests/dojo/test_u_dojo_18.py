"""U-DOJO-10 edge cases: sanitization is ordered, bounded, and complete (L-10)."""

from __future__ import annotations

from webpent.dojo.case_study import _MAX_TEXT, CaseStudyWriter, _redact
from webpent.dojo.scenario_library import Scenario
from webpent.dojo.sparring import RoundLog, SparringMatchResult


def _scenario() -> Scenario:
    return Scenario(
        scenario_id="s-1", family="sqli", title="t", description="d", difficulty=1,
        template_id="flask_sqli_login", seed=1,
        ground_truth={"vuln_class": "sqli", "location": "/login",
                      "signature": "' OR 1=1"},
        hints=("h1", "h2"), lesson_tags=("tag",), skill_families=("sqli",),
        request_budget=10,
    )


def _match(lessons: tuple[str, ...] = (), winner: str = "red") -> SparringMatchResult:
    return SparringMatchResult(
        scenario_id="s-1", red_score=80.0, blue_score=20.0, winner=winner,
        rounds_log=(
            RoundLog(1, "add_input_filter", True, 80.0, 0.0),
            RoundLog(2, "elevate_auth_requirement", False, 40.0, 100.0),
        ),
        lessons=lessons,
    )


def test_bearer_value_is_redacted_first():
    leaked = "lesson with Bearer live-secret-token-99 in transit"
    redacted = _redact(leaked)
    assert "live-secret-token-99" not in redacted
    assert "[REDACTED_BEARER]" in redacted


def test_bare_authorization_header_is_redacted():
    redacted = _redact("use Authorization: Basic dXNlcjpwYXNz here")
    assert "dXNlcjpwYXNz" not in redacted
    assert "[REDACTED_AUTH]" in redacted


def test_cookie_is_redacted():
    redacted = _redact("Cookie: session=abc123 was stolen")
    assert "abc123" not in redacted
    assert "[REDACTED_COOKIE]" in redacted


def test_generic_secrets_are_redacted():
    for shape in ("api_key: xyz", "apikey = xyz", "token: hunter2",
                  "password=hunter2", "secret: top", "session: abc"):
        redacted = _redact(f"leak {shape} end")
        assert "xyz" not in redacted and "hunter2" not in redacted
        assert "[REDACTED_SECRET]" in redacted


def test_redaction_is_case_insensitive():
    assert "SECRET" not in _redact("BEARER abcdef123456")
    assert "abcdef123456" not in _redact("BeArEr abcdef123456")


def test_redaction_is_bounded_to_max_text():
    redacted = _redact("a" * (_MAX_TEXT * 3))
    assert len(redacted) == _MAX_TEXT


def test_benign_text_passes_through():
    benign = "the agent probed /login and the defense held"
    assert _redact(benign) == benign


def test_lessons_are_redacted_in_the_export():
    study = CaseStudyWriter.from_match(
        _match(lessons=("advisory: captured Cookie: session=super-secret-42",)),
        _scenario(),
    )
    assert "super-secret-42" not in study
    assert "[REDACTED_COOKIE]" in study


def test_advisory_banner_and_notice_present():
    study = CaseStudyWriter.from_match(_match(), _scenario())
    assert study.startswith("# Dojo Case Study: s-1")
    assert "advisory" in study
    assert "Simulated target only" in study
    assert "Sanitization notice" in study


def test_match_record_table_lists_every_round():
    study = CaseStudyWriter.from_match(_match(), _scenario())
    assert "| 1 | add_input_filter | True | 80.0 | 0.0 |" in study
    assert "| 2 | elevate_auth_requirement | False | 40.0 | 100.0 |" in study


def test_scenario_block_carries_ground_truth_and_family():
    study = CaseStudyWriter.from_match(_match(), _scenario())
    assert "family: sqli" in study
    assert "ground truth: class=sqli location=/login" in study


def test_empty_lessons_leave_an_empty_section():
    study = CaseStudyWriter.from_match(_match(), _scenario())
    assert "## Lessons" in study
    assert study.index("## Lessons") < study.index("## Sanitization notice")
