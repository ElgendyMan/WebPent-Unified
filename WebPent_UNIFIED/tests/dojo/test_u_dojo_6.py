"""U-DOJO-6: tournament mode (plan Task 6)."""

from __future__ import annotations

import dataclasses

import pytest

from webpent.dojo.lab_generator import LabGenerator
from webpent.dojo.scenario_library import ScenarioLibrary
from webpent.dojo.tournament import BUILTIN_AGENTS, TournamentRunner

CONFIG_DIR = "config/dojo/scenarios"


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


@pytest.fixture(scope="module")
def sample(library: ScenarioLibrary):
    return [library.get("sqli-01"), library.get("idor-01")]


def test_four_builtin_agents_present():
    assert set(BUILTIN_AGENTS) == {
        "naive", "methodical", "signature_matcher", "adaptive",
    }


def test_round_robin_scores_ranked(sample):
    result = TournamentRunner().round_robin(sample)
    assert len(result.standings) == 4
    scores = [s.total_score for s in result.standings]
    for higher, lower in zip(scores, scores[1:], strict=False):
        assert higher >= lower, "standings must be ranked non-increasing"
    assert sum(s.successes for s in result.standings) > 0


def test_round_robin_rewards_honest_skill(sample):
    """The blind claimer must not beat the honest explorers (L-6 in spirit)."""
    result = TournamentRunner().round_robin(sample)
    by_name = {s.agent: s for s in result.standings}
    assert by_name["adaptive"].total_score >= by_name["naive"].total_score
    assert by_name["methodical"].successes > 0


def test_ab_comparison_two_agents(sample):
    comparison = TournamentRunner().ab_comparison(
        BUILTIN_AGENTS["adaptive"], BUILTIN_AGENTS["naive"], sample
    )
    assert comparison["agents"] == ["adaptive", "naive"]
    assert "adaptive" in comparison["totals"]
    assert "naive" in comparison["totals"]
    assert comparison["per_scenario"]["adaptive"]["sqli-01"].scenario_id == "sqli-01"
    assert comparison["same_seeds"] is True


def test_tournament_deterministic(sample):
    first = TournamentRunner().round_robin(sample)
    second = TournamentRunner().round_robin(sample)
    assert first == second


def test_builtin_agents_never_use_ground_truth(library):
    """L-3 spirit: built-ins plan from surface info only (L-1 offline, L-4)."""
    scenario = library.get("sqli-01")
    poisoned = dataclasses.replace(
        scenario,
        ground_truth={
            **scenario.ground_truth,
            "signature": "TOPSECRET",
            "location": "/TOPSECRET",
        },
    )
    lab = LabGenerator().start(scenario.template_id, seed=scenario.seed)
    view = lab.public_view()
    for name, agent in BUILTIN_AGENTS.items():
        requests = agent.plan(view, poisoned)
        assert requests, f"{name} planned nothing"
        for request in requests:
            assert "TOPSECRET" not in request.path
            assert all(
                "TOPSECRET" not in value for value in request.params.values()
            ), f"{name} peeked at the poisoned ground truth"
        conclusion = agent.conclude([])
        assert "TOPSECRET" not in conclusion.signature
