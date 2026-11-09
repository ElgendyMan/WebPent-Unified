"""U-DOJO-7: the skill assessor (plan Task 7)."""

from __future__ import annotations

import pytest

from webpent.dojo.practice_runner import PracticeResult
from webpent.dojo.scenario_library import ScenarioLibrary
from webpent.dojo.skill_assessor import SkillAssessor

CONFIG_DIR = "config/dojo/scenarios"


def _result(scenario_id: str, *, success=True, score=97.0, fp=0,
            requests=1, time_steps=1, budget=10) -> PracticeResult:
    return PracticeResult(
        scenario_id=scenario_id,
        success=success,
        score=score,
        requests_used=requests,
        false_positives=fp,
        time_steps=time_steps,
        budget=budget,
    )


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


@pytest.fixture(scope="module")
def scenarios(library: ScenarioLibrary):
    return [library.get("sqli-01"), library.get("jwt-01")]


def test_skill_formula_matches_spec(scenarios):
    """skill = 100 x (0.4sr + 0.3avg + 0.2(1-fp) + 0.1(1-tr)), hand-computed."""
    results = [_result("sqli-01") for _ in range(10)]
    profile = SkillAssessor().assess("sqli", results, scenarios)
    # sr=1.0, avg=0.97, fp=0, tr=0.1 -> 100 x (0.4+0.291+0.2+0.09) = 98.1
    assert profile.skill == 98.1
    assert profile.sufficient is True

    mixed = [
        _result("sqli-01", success=i < 5, score=50.0, fp=0 if i < 7 else 1,
                time_steps=2)
        for i in range(10)
    ]
    profile2 = SkillAssessor().assess("sqli", mixed, scenarios)
    # sr=0.5, avg=0.5, fp=0.3, tr=0.2 -> 100 x (0.2+0.15+0.14+0.08) = 57.0
    assert profile2.skill == 57.0


def test_min_ten_samples_enforced(scenarios):
    results = [_result("sqli-01") for _ in range(5)]
    thin = SkillAssessor().assess("sqli", results, scenarios)
    assert thin.sufficient is False
    assert thin.samples == 5
    full = SkillAssessor().assess("sqli", results * 2, scenarios)
    assert full.sufficient is True
    assert full.samples == 10


def test_trend_measures_improvement(scenarios):
    weak = [_result("sqli-01", success=False, score=24.0, fp=1) for _ in range(10)]
    strong = [_result("sqli-01") for _ in range(10)]
    profiles = SkillAssessor().trend("sqli", weak + strong, scenarios, window=10)
    assert len(profiles) == 2
    assert SkillAssessor.direction(profiles) == "improving"
    assert profiles[1].skill > profiles[0].skill


def test_skill_family_filtering(scenarios):
    """Results from other skill families must not leak into this profile."""
    results = [_result("sqli-01") for _ in range(10)]
    results.append(_result("jwt-01"))
    profile = SkillAssessor().assess("sqli", results, scenarios)
    assert profile.samples == 10
    jwt_profile = SkillAssessor().assess("jwt_weakness", results, scenarios)
    assert jwt_profile.samples == 1
    assert jwt_profile.sufficient is False
