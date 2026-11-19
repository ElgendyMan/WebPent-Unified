"""U-DOJO-6 edge cases: rounds, rotation, and honest winners (L-6/L-7)."""

from __future__ import annotations

import json

import pytest

from webpent.dojo.defender import DEFENSE_PATTERNS
from webpent.dojo.lab_generator import LabGenerator
from webpent.dojo.scenario_library import Scenario, ScenarioLibrary
from webpent.dojo.sparring import SparringMatch
from webpent.dojo.tournament import BUILTIN_AGENTS

CONFIG_DIR = "config/dojo/scenarios"


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


def _scenario() -> Scenario:
    return Scenario(
        scenario_id="s-1", family="sqli", title="t", description="d", difficulty=1,
        template_id="flask_sqli_login", seed=3,
        ground_truth={"vuln_class": "sqli", "location": "/login",
                      "signature": "' OR 1=1"},
        hints=("h1", "h2"), lesson_tags=("tag",), skill_families=("sqli",),
        request_budget=10,
    )


def test_nonpositive_round_count_is_clamped_to_one(library):
    match = SparringMatch().run(
        BUILTIN_AGENTS["adaptive"], library.get("sqli-01"), DEFENSE_PATTERNS,
        rounds=0,
    )
    assert len(match.rounds_log) == 1


def test_rounds_zero_with_custom_scenario():
    match = SparringMatch().run(BUILTIN_AGENTS["adaptive"], _scenario(),
                                        DEFENSE_PATTERNS, rounds=0)
    assert len(match.rounds_log) == 1


def test_five_rounds_produce_five_log_entries():
    match = SparringMatch().run(BUILTIN_AGENTS["adaptive"], _scenario(),
                                        DEFENSE_PATTERNS, rounds=5)
    assert len(match.rounds_log) == 5
    assert [r.round_no for r in match.rounds_log] == [1, 2, 3, 4, 5]


def test_empty_defense_set_yields_no_lessons():
    match = SparringMatch().run(BUILTIN_AGENTS["adaptive"], _scenario(), ())
    assert match.lessons == ()
    assert all(r.pattern == "none" for r in match.rounds_log)


def test_red_wins_when_any_round_succeeds():
    match = SparringMatch().run(BUILTIN_AGENTS["adaptive"], _scenario(),
                                DEFENSE_PATTERNS)
    assert match.winner == "red"
    assert any(r.red_success for r in match.rounds_log)


def test_blue_wins_when_no_round_succeeds():
    match = SparringMatch().run(BUILTIN_AGENTS["naive"], _scenario(),
                                DEFENSE_PATTERNS)
    assert match.winner == "blue"
    assert match.blue_score == 100.0


def test_patterns_rotate_by_round_number():
    two_patterns = DEFENSE_PATTERNS[:2]
    match = SparringMatch().run(
        BUILTIN_AGENTS["adaptive"], _scenario(), two_patterns, rounds=5
    )
    patterns = [r.pattern for r in match.rounds_log]
    assert patterns[0] == patterns[4], "rotation wraps with modulo"
    assert patterns[0] != patterns[1]
    assert patterns[3] == patterns[1]


def test_scores_are_averages_of_the_rounds():
    match = SparringMatch().run(BUILTIN_AGENTS["adaptive"], _scenario(),
                                        DEFENSE_PATTERNS, rounds=3)
    expected_red = round(
        sum(r.red_score for r in match.rounds_log) / len(match.rounds_log), 2
    )
    assert match.red_score == expected_red


def test_round_log_records_success_outcomes():
    match = SparringMatch().run(BUILTIN_AGENTS["adaptive"], _scenario(),
                                        DEFENSE_PATTERNS, rounds=4)
    assert any(r.red_success for r in match.rounds_log)


def test_lessons_are_advisory_and_tagged():
    match = SparringMatch().run(BUILTIN_AGENTS["adaptive"], _scenario(),
                                DEFENSE_PATTERNS)
    assert match.lessons
    assert all(lesson.startswith("advisory:") for lesson in match.lessons)


def test_match_result_roundtrips_through_dict():
    match = SparringMatch().run(BUILTIN_AGENTS["adaptive"], _scenario(),
                                DEFENSE_PATTERNS)
    payload = match.as_dict()
    assert payload["scenario_id"] == match.scenario_id
    assert payload["winner"] == match.winner
    assert len(payload["rounds_log"]) == len(match.rounds_log)
    assert payload["lessons"] == list(match.lessons)
    revived = json.loads(json.dumps(payload))
    assert revived == payload


def test_sparring_never_touches_the_network(library):
    lab = LabGenerator().start("flask_sqli_login", seed=1)
    assert lab.base_url.startswith("dojo://"), "the arena is offline-only"
