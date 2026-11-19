"""U-DOJO-9: the practice generator (plan Task 9)."""

from __future__ import annotations

import pytest

from webpent.dojo.practice_generator import PracticeGenerator
from webpent.dojo.practice_runner import PracticeRunner
from webpent.dojo.scenario_library import ScenarioLibrary
from webpent.dojo.tournament import BUILTIN_AGENTS
from webpent.dojo.weakness_identifier import Weakness

CONFIG_DIR = "config/dojo/scenarios"


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


def _weaknesses() -> list[Weakness]:
    return [
        Weakness(
            kind="skill_gap",
            skill_family="sqli",
            severity=0.9,
            detail="advisory: sqli fundamentals",
        ),
        Weakness(
            kind="speed_gap",
            skill_family="info_disclosure",
            severity=0.3,
            detail="advisory: slow but effective",
        ),
    ]


def test_plan_has_phases(library):
    plan = PracticeGenerator().generate(_weaknesses(), library, seed=7)
    assert plan.warmup and plan.focus and plan.sparring
    assert plan.reassessment
    phases = {item.phase for item in plan.warmup + plan.focus + plan.sparring}
    assert phases == {"warmup", "focus", "sparring"}


def test_plan_targets_weakest_first(library):
    plan = PracticeGenerator().generate(_weaknesses(), library, seed=7)
    focus_families = [item.family for item in plan.focus]
    assert focus_families, "focus phase must exist"
    assert focus_families[0] == "sqli", "the 0.9-severity family comes first"
    assert focus_families.index("sqli") < focus_families.index("info_disclosure")


def test_plan_executable(library):
    """Every plan item names a real scenario and runs through PracticeRunner."""
    plan = PracticeGenerator().generate(_weaknesses(), library, seed=7)
    runner = PracticeRunner()
    agent = BUILTIN_AGENTS["adaptive"]
    executed = 0
    for item in plan.warmup + plan.focus:
        scenario = library.get(item.scenario_id)  # KeyError if dangling
        result = runner.run(agent, scenario)
        assert result.scenario_id == item.scenario_id
        executed += 1
    for item in plan.sparring:
        library.get(item.scenario_id)  # sparring items must name real labs
        executed += 1
    assert executed >= len(plan.warmup) + len(plan.focus)


def test_reassessment_criteria_present(library):
    plan = PracticeGenerator().generate(_weaknesses(), library, seed=7)
    assert len(plan.reassessment) >= 2
    assert all(str(c).strip() for c in plan.reassessment)


def test_plan_deterministic(library):
    first = PracticeGenerator().generate(_weaknesses(), library, seed=7)
    second = PracticeGenerator().generate(_weaknesses(), library, seed=7)
    assert first.as_dict() == second.as_dict()
