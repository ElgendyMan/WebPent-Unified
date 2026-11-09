"""U-DOJO-8 edge cases: every detector threshold is exact (L-5/L-6)."""

from __future__ import annotations

from webpent.dojo.practice_runner import PracticeResult
from webpent.dojo.scenario_library import Scenario
from webpent.dojo.sparring import SparringMatchResult
from webpent.dojo.weakness_identifier import (
    CONSISTENCY_GAP_STDDEV_LINE,
    MIN_SAMPLES_FOR_WEAKNESS,
    SKILL_GAP_SUCCESS_LINE,
    SPEED_GAP_TIME_LINE,
    WeaknessIdentifier,
)


def _scenario(sid: str, difficulty: int = 1, families=("sqli",)) -> Scenario:
    return Scenario(
        scenario_id=sid, family="sqli", title="t", description="d",
        difficulty=difficulty, template_id="flask_sqli_login", seed=1,
        ground_truth={"vuln_class": "sqli", "location": "/login",
                      "signature": "' OR 1=1"},
        hints=("h1", "h2"), lesson_tags=("tag",), skill_families=tuple(families),
        request_budget=10,
    )


def _result(sid: str = "s-1", score: float = 80.0, success: bool = True,
            fp: int = 0, time_steps: int = 1) -> PracticeResult:
    return PracticeResult(
        scenario_id=sid, success=success, score=score, requests_used=1,
        false_positives=fp, time_steps=time_steps, budget=10,
    )


def test_constants_are_the_spec_values():
    assert SKILL_GAP_SUCCESS_LINE == 0.5
    assert SPEED_GAP_TIME_LINE == 0.8
    assert CONSISTENCY_GAP_STDDEV_LINE == 25.0
    assert MIN_SAMPLES_FOR_WEAKNESS == 5


def test_skill_gap_at_exactly_the_line_is_not_declared():
    results = [_result(success=True), _result(success=False, fp=1)]
    assert sum(r.success for r in results) / 2 == 0.5
    identifier = WeaknessIdentifier()
    found = identifier._skill_gap("sqli", results)
    assert found is None


def test_skill_gap_just_below_the_line_is_declared():
    results = [_result(success=True)] + [
        _result(success=False, fp=1) for _ in range(2)
    ]
    assert sum(r.success for r in results) / 3 < 0.5
    weakness = WeaknessIdentifier()._skill_gap("sqli", results)
    assert weakness is not None and weakness.kind == "skill_gap"


def test_skill_gap_without_false_positives_is_declared():
    # RT-05 corrected rule: pure honest failure (0% success, no FP claims)
    # is the clearest skill gap; only a PASSING family is never flagged
    results = [_result(success=False, fp=0) for _ in range(5)]
    weakness = WeaknessIdentifier()._skill_gap("sqli", results)
    assert weakness is not None and weakness.kind == "skill_gap"


def test_speed_gap_at_exactly_the_line_is_declared():
    results = [_result(time_steps=8) for _ in range(5)]  # 8/10 == 0.8
    weakness = WeaknessIdentifier()._speed_gap("sqli", results)
    assert weakness is not None and weakness.kind == "speed_gap"


def test_speed_gap_below_the_line_is_not_declared():
    results = [_result(time_steps=7) for _ in range(5)]  # 0.7 < 0.8
    assert WeaknessIdentifier()._speed_gap("sqli", results) is None


def test_speed_gap_is_not_declared_for_failing_agents():
    results = [_result(success=False, time_steps=9) for _ in range(5)]
    assert WeaknessIdentifier()._speed_gap("sqli", results) is None


def test_speed_gap_time_ratio_is_capped():
    results = [_result(time_steps=99) for _ in range(5)]
    weakness = WeaknessIdentifier()._speed_gap("sqli", results)
    assert weakness is not None
    assert weakness.severity == 1.0


def test_consistency_gap_at_exactly_the_line_is_declared():
    # scores 0 and 50: stddev = 25.0, exactly the line
    results = [_result(score=0.0), _result(score=50.0)]
    weakness = WeaknessIdentifier(min_samples=2)._consistency_gap("sqli", results)
    assert weakness is not None and weakness.kind == "consistency_gap"


def test_consistency_gap_below_the_line_is_not_declared():
    results = [_result(score=20.0), _result(score=40.0)]  # stddev = 10
    assert WeaknessIdentifier(min_samples=2)._consistency_gap("sqli", results) is None


def test_consistency_gap_needs_min_samples():
    results = [_result(score=0.0), _result(score=100.0)]
    assert WeaknessIdentifier()._consistency_gap("sqli", results) is None


def test_context_gap_ignores_middle_difficulty():
    identifier = WeaknessIdentifier()
    scenarios = [_scenario("easy", 2), _scenario("mid", 3), _scenario("hard", 4)]
    results = (
        [_result("easy", success=True) for _ in range(3)]
        + [_result("mid", success=False, fp=1) for _ in range(3)]
        + [_result("hard", success=True) for _ in range(3)]
    )
    found = identifier._context_gap("sqli", results, scenarios)
    # easy passes, hard passes too: no context gap regardless of mid
    assert found is None


def test_context_gap_needs_easy_pass_and_hard_fail():
    identifier = WeaknessIdentifier()
    scenarios = [_scenario("easy", 2), _scenario("hard", 4)]
    results = (
        [_result("easy", success=True) for _ in range(3)]
        + [_result("hard", success=False, fp=1) for _ in range(3)]
    )
    weakness = identifier._context_gap("sqli", results, scenarios)
    assert weakness is not None and weakness.kind == "context_gap"
    assert weakness.severity == 1.0


def test_identify_skips_families_below_min_samples():
    identifier = WeaknessIdentifier()
    results = [_result(success=False, fp=1) for _ in range(4)]  # 4 < 5
    assert identifier.identify(results, [_scenario("s-1")]) == []


def test_identify_reports_adaptation_gap_regardless_of_sample_count():
    match = SparringMatchResult(
        scenario_id="s-1", red_score=80.0, blue_score=20.0, winner="red",
        rounds_log=(), lessons=(),
    )
    weaknesses = WeaknessIdentifier().identify([], [_scenario("s-1")], [match])
    assert len(weaknesses) == 1
    assert weaknesses[0].kind == "adaptation_gap"
    assert weaknesses[0].severity == 0.8


def test_adaptation_gap_ignored_for_blue_wins():
    match = SparringMatchResult(
        scenario_id="s-1", red_score=30.0, blue_score=70.0, winner="blue",
        rounds_log=(), lessons=(),
    )
    assert WeaknessIdentifier().identify([], [_scenario("s-1")], [match]) == []


def test_identify_returns_detectors_sorted_by_family():
    identifier = WeaknessIdentifier()
    results = (
        [_result("s-1", success=False, fp=1) for _ in range(5)]
        + [_result("x-1", success=False, fp=1) for _ in range(5)]
    )
    scenarios = [_scenario("s-1"), _scenario("x-1", families=("xss",))]
    weaknesses = identifier.identify(results, scenarios)
    kinds = [w.kind for w in weaknesses]
    assert kinds.count("skill_gap") == 2
    assert [w.skill_family for w in weaknesses if w.kind == "skill_gap"] == [
        "sqli", "xss"
    ]


def test_weakness_roundtrips_through_dict():
    weakness = WeaknessIdentifier()._skill_gap(
        "sqli", [_result(success=False, fp=1) for _ in range(5)]
    )
    payload = weakness.as_dict()
    assert payload["advisory"] is True
    assert payload["detail"].startswith("advisory:")
