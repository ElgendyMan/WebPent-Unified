"""U-DOJO-8: the weakness identifier (plan Task 8)."""

from __future__ import annotations

import pytest

from webpent.dojo.practice_runner import PracticeResult
from webpent.dojo.scenario_library import ScenarioLibrary
from webpent.dojo.sparring import SparringMatchResult
from webpent.dojo.weakness_identifier import WEAKNESS_KINDS, WeaknessIdentifier

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
def sqli_all(library: ScenarioLibrary):
    return library.by_family("sqli")


def test_five_kinds_covered():
    assert {
        "skill_gap", "consistency_gap", "context_gap", "speed_gap",
        "adaptation_gap",
    } == WEAKNESS_KINDS


def test_skill_gap_detected(sqli_all):
    results = [_result("sqli-01", success=False, score=24.0, fp=1) for _ in range(10)]
    weaknesses = WeaknessIdentifier().identify(results, sqli_all)
    assert "skill_gap" in {w.kind for w in weaknesses}
    skill = next(w for w in weaknesses if w.kind == "skill_gap")
    assert skill.skill_family == "sqli"
    assert skill.severity > 0.5


def test_speed_gap_detected(sqli_all):
    """Passing but burning the whole budget is a speed gap, not a skill gap."""
    results = [
        _result("sqli-01", success=True, score=70.0, requests=10, time_steps=10)
        for _ in range(10)
    ]
    weaknesses = WeaknessIdentifier().identify(results, sqli_all)
    kinds = {w.kind for w in weaknesses}
    assert "speed_gap" in kinds
    assert "skill_gap" not in kinds


def test_consistency_gap_detected(sqli_all):
    """Wild score swings with a passing average point at consistency."""
    results = [
        _result("sqli-01", success=True, score=100.0) if i % 2 == 0
        else _result("sqli-01", success=False, score=24.0, fp=1)
        for i in range(10)
    ]
    weaknesses = WeaknessIdentifier().identify(results, sqli_all)
    assert "consistency_gap" in {w.kind for w in weaknesses}


def test_context_gap_detected(sqli_all):
    """Easy scenarios pass, hard ones fail: the gap is context, not skill."""
    results = (
        [_result("sqli-01") for _ in range(5)]
        + [_result("sqli-08", success=False, score=24.0, fp=1) for _ in range(5)]
    )
    weaknesses = WeaknessIdentifier().identify(results, sqli_all)
    assert "context_gap" in {w.kind for w in weaknesses}


def test_adaptation_gap_detected():
    """A red victor over the blue playbook is an adaptation gap."""
    sparring = SparringMatchResult(
        scenario_id="sqli-01",
        red_score=92.5,
        blue_score=0.0,
        winner="red",
        rounds_log=(),
        lessons=(),
    )
    weaknesses = WeaknessIdentifier().identify([], [], sparring_results=[sparring])
    assert "adaptation_gap" in {w.kind for w in weaknesses}
    assert any("sqli-01" in w.detail for w in weaknesses)


def test_all_findings_advisory(sqli_all):
    """L-7: every weakness is advisory material, never a silent judgment."""
    results = [_result("sqli-01", success=False, score=24.0, fp=1) for _ in range(10)]
    weaknesses = WeaknessIdentifier().identify(results, sqli_all)
    assert weaknesses
    assert all(w.advisory for w in weaknesses)
    assert all(w.detail for w in weaknesses)
