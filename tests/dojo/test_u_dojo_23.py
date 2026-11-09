"""U-DOJO-4/5 edge cases: the arena roster and the twelve blue patterns."""

from __future__ import annotations

import pytest

from webpent.dojo.defender import DEFENSE_PATTERNS, get_pattern
from webpent.dojo.lab_generator import LabGenerator
from webpent.dojo.scenario_library import Scenario, ScenarioLibrary
from webpent.dojo.tournament import BUILTIN_AGENTS, TournamentRunner

CONFIG_DIR = "config/dojo/scenarios"


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


def _scenario() -> Scenario:
    return Scenario(
        scenario_id="s-1", family="sqli", title="t", description="d", difficulty=1,
        template_id="flask_sqli_login", seed=5,
        ground_truth={"vuln_class": "sqli", "location": "/login",
                      "signature": "' OR 1=1"},
        hints=("h1", "h2"), lesson_tags=("tag",), skill_families=("sqli",),
        request_budget=10,
    )


def test_roster_has_exactly_four_named_agents():
    assert sorted(BUILTIN_AGENTS) == ["adaptive", "methodical", "naive",
                                      "signature_matcher"]


def test_round_robin_with_a_single_agent():
    result = TournamentRunner().round_robin(
        [_scenario()], agents={"solo": BUILTIN_AGENTS["adaptive"]}
    )
    assert len(result.standings) == 1
    assert result.standings[0].agent == "solo"


def test_standings_are_sorted_by_total_then_name():
    result = TournamentRunner().round_robin([_scenario()])
    totals = [s.total_score for s in result.standings]
    assert totals == sorted(totals, reverse=True)


def test_naive_agent_is_priced_for_false_positives():
    """L-6 honesty: a claim-always agent must show false positives."""
    result = TournamentRunner().round_robin([_scenario()])
    naive = next(s for s in result.standings if s.agent == "naive")
    assert naive.false_positives >= 1


def test_agent_names_in_standings_match_the_roster():
    result = TournamentRunner().round_robin([_scenario()])
    assert {s.agent for s in result.standings} == set(BUILTIN_AGENTS)


def test_tournament_result_roundtrips_through_dict():
    payload = TournamentRunner().round_robin([_scenario()]).as_dict()
    assert set(payload["standings"][0]) >= {"agent", "total_score", "successes",
                                            "false_positives"}


def test_twelve_patterns_with_unique_names():
    assert len(DEFENSE_PATTERNS) == 12
    names = [p.name for p in DEFENSE_PATTERNS]
    assert len(set(names)) == 12


def test_get_pattern_by_name_and_unknown_name():
    assert get_pattern("add_input_filter").name == "add_input_filter"
    with pytest.raises(KeyError):
        get_pattern("not-a-pattern")


def test_pattern_application_does_not_mutate_the_original_lab():
    lab = LabGenerator().start("flask_sqli_login", seed=1)
    before = lab.state_hash
    patched = get_pattern("add_input_filter").apply(lab)
    assert lab.state_hash == before, "the original lab is untouched"
    assert patched.state_hash != before, "the patched copy diverges"


def test_add_input_filter_only_filters_exploitable_points():
    lab = LabGenerator().start("flask_sqli_login", seed=1)
    patched = get_pattern("add_input_filter").apply(lab)
    for point in patched.vuln_points:
        if point.exploitable:
            assert point.filter_token
        else:
            assert not point.filter_token


def test_elevate_auth_requirement_covers_every_route():
    lab = LabGenerator().start("flask_sqli_login", seed=1)
    patched = get_pattern("elevate_auth_requirement").apply(lab)
    assert all(route.requires_auth != "none" for route in patched.routes)


def test_decoy_hardening_puts_decoys_first():
    lab = LabGenerator().start("flask_sqli_login", seed=1)
    patched = get_pattern("decoy_hardening").apply(lab)
    exploitable = [
        i for i, p in enumerate(patched.vuln_points) if p.exploitable
    ]
    decoys = [i for i, p in enumerate(patched.vuln_points) if not p.exploitable]
    assert decoys and exploitable
    assert max(decoys) < min(exploitable)


def test_shrink_request_budget_keeps_at_least_one():
    lab = LabGenerator().start("flask_sqli_login", seed=1)
    lab.request_budget = 2
    patched = get_pattern("shrink_request_budget").apply(lab)
    assert patched.request_budget == 1
    assert lab.request_budget == 2


def test_rate_limit_lockout_sets_budget_to_one():
    lab = LabGenerator().start("flask_sqli_login", seed=1)
    patched = get_pattern("rate_limit_lockout").apply(lab)
    assert patched.request_budget == 1
    assert lab.request_budget != 1


def test_signature_rotation_hashes_the_exploitable_signature():
    lab = LabGenerator().start("flask_sqli_login", seed=1)
    original = next(
        p.signature for p in lab.vuln_points if p.exploitable
    )
    patched = get_pattern("signature_rotation").apply(lab)
    rotated = next(p.signature for p in patched.vuln_points if p.exploitable)
    assert rotated != original
    assert len(rotated) == 8
