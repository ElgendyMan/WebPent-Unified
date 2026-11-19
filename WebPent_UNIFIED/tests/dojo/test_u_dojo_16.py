"""U-DOJO-7 edge cases: the L-5 sample gate and trend windows."""

from __future__ import annotations

from webpent.dojo.practice_runner import PracticeResult
from webpent.dojo.scenario_library import Scenario
from webpent.dojo.skill_assessor import MIN_SAMPLES, SkillAssessor


def _scenario(sid: str = "s-1", families=("sqli",)) -> Scenario:
    return Scenario(
        scenario_id=sid, family="sqli", title="t", description="d", difficulty=1,
        template_id="flask_sqli_login", seed=1,
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


SCENARIO = _scenario()


def test_min_samples_is_ten():
    assert MIN_SAMPLES == 10


def test_zero_samples_is_insufficient_and_zeroed():
    profile = SkillAssessor().assess("sqli", [], [SCENARIO])
    assert profile.samples == 0
    assert profile.sufficient is False
    assert profile.skill == 0.0


def test_exactly_ten_samples_is_sufficient():
    results = [_result() for _ in range(MIN_SAMPLES)]
    profile = SkillAssessor().assess("sqli", results, [SCENARIO])
    assert profile.samples == MIN_SAMPLES
    assert profile.sufficient is True


def test_nine_samples_stay_insufficient():
    results = [_result() for _ in range(MIN_SAMPLES - 1)]
    profile = SkillAssessor().assess("sqli", results, [SCENARIO])
    assert profile.sufficient is False


def test_false_positives_drag_the_skill():
    clean = SkillAssessor().assess(
        "sqli", [_result() for _ in range(MIN_SAMPLES)], [SCENARIO]
    )
    dirty = SkillAssessor().assess(
        "sqli", [_result(fp=1) for _ in range(MIN_SAMPLES)], [SCENARIO]
    )
    assert clean.skill > dirty.skill
    assert dirty.fp_rate == 1.0


def test_time_ratio_is_capped_at_one():
    results = [_result(time_steps=99) for _ in range(MIN_SAMPLES)]
    profile = SkillAssessor().assess("sqli", results, [SCENARIO])
    assert profile.time_ratio == 1.0


def test_scenario_families_decide_membership():
    both = _scenario("s-2", families=("sqli", "xss"))
    results = [_result("s-2") for _ in range(MIN_SAMPLES)]
    sqli = SkillAssessor().assess("sqli", results, [both])
    xss = SkillAssessor().assess("xss", results, [both])
    jwt = SkillAssessor().assess("jwt", results, [both])
    assert sqli.samples == MIN_SAMPLES
    assert xss.samples == MIN_SAMPLES
    assert jwt.samples == 0


def test_results_of_other_scenarios_are_excluded():
    other = _scenario("s-9")
    results = [_result("s-9") for _ in range(MIN_SAMPLES)]
    profile = SkillAssessor().assess("sqli", results, [other])
    # the scenario declares sqli in skill_families, so s-9 results DO count
    assert profile.samples == MIN_SAMPLES


def test_trend_windows_partition_chronologically():
    results = [_result(score=float(50 + i)) for i in range(15)]
    profiles = SkillAssessor().trend("sqli", results, [SCENARIO], window=10)
    assert len(profiles) == 2
    assert profiles[0].samples == 10
    assert profiles[1].samples == 5
    assert profiles[0].avg_score < profiles[1].avg_score


def test_direction_reports_the_measured_slope():
    rising = SkillAssessor().trend(
        "sqli", [_result(score=float(i * 10)) for i in range(1, 21)], [SCENARIO],
        window=10,
    )
    assert SkillAssessor().direction(rising) == "improving"
    falling = SkillAssessor().trend(
        "sqli", [_result(score=float(200 - i * 10)) for i in range(1, 21)],
        [SCENARIO], window=10,
    )
    assert SkillAssessor().direction(falling) == "declining"


def test_direction_is_flat_for_identical_windows():
    profiles = SkillAssessor().trend(
        "sqli", [_result() for _ in range(20)], [SCENARIO], window=10
    )
    assert SkillAssessor().direction(profiles) == "flat"


def test_direction_with_single_window_is_flat():
    single = (SkillAssessor().assess("sqli", [_result()], [SCENARIO]),)
    assert SkillAssessor().direction(single) == "flat"


def test_trend_window_below_one_is_clamped():
    results = [_result() for _ in range(3)]
    profiles = SkillAssessor().trend("sqli", results, [SCENARIO], window=0)
    assert len(profiles) == 3


def test_trend_of_empty_results_is_empty():
    assert SkillAssessor().trend("sqli", [], [SCENARIO]) == ()


def test_profile_roundtrips_through_dict():
    profile = SkillAssessor().assess("sqli", [_result()], [SCENARIO])
    payload = profile.as_dict()
    assert payload["skill_family"] == "sqli"
    assert payload["samples"] == 1
