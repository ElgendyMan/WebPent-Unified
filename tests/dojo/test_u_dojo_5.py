"""U-DOJO-5: the counter adapter (plan Task 5)."""

from __future__ import annotations

import pytest

from webpent.dojo.counter_adapter import AdaptationChallenge
from webpent.dojo.defender import DEFENSE_PATTERNS, get_pattern
from webpent.dojo.engine import DojoRequest
from webpent.dojo.lab_generator import LabGenerator
from webpent.dojo.practice_runner import Conclusion
from webpent.dojo.scenario_library import ScenarioLibrary

CONFIG_DIR = "config/dojo/scenarios"


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


@pytest.fixture(scope="module")
def sqli_scenarios(library: ScenarioLibrary):
    return library.by_family("sqli")


def _red_for(scenario):
    """A ground-truth red agent, built from the trainer-side vuln map (L-3)."""
    lab = LabGenerator().start(scenario.template_id, seed=scenario.seed)
    point = next(p for p in lab.vuln_points if p.exploitable)
    request = DojoRequest("POST", point.path, {point.param: point.signature})

    class _Red:
        def plan(self, lab_view, scen):
            return [request]

        def conclude(self, responses):
            return Conclusion(
                claims_finding=True,
                vuln_class=scenario.vuln_class,
                location=scenario.location,
            )

    return _Red()


def test_at_least_10_defense_patterns_registered():
    assert len(DEFENSE_PATTERNS) >= 10


def test_adaptation_applies_next_pattern_on_red_win(sqli_scenarios):
    scenario = sqli_scenarios[0]
    playbook = [
        get_pattern("rate_limit_lockout"),   # red beats this
        get_pattern("rotate_param_name"),    # red cannot beat this
        get_pattern("signature_rotation"),
    ]
    result = AdaptationChallenge().run(_red_for(scenario), scenario, playbook)
    applied = [entry.pattern for entry in result.rounds]
    assert applied[0] == "none"
    assert applied[1] == "rate_limit_lockout"
    assert applied[2] == "rotate_param_name"
    assert result.red_victor is False


def test_adaptation_exhausts_patterns_declares_red_victor(sqli_scenarios):
    scenario = sqli_scenarios[0]
    weak_playbook = [
        get_pattern("rate_limit_lockout"),
        get_pattern("shrink_request_budget"),
        get_pattern("require_exploit_token"),
    ]
    result = AdaptationChallenge().run(_red_for(scenario), scenario, weak_playbook)
    assert result.red_victor is True
    assert all(entry.red_success for entry in result.rounds)
    assert any("victor" in lesson for lesson in result.lessons)


def test_bypass_attempt_measured(sqli_scenarios):
    """Every round with a defense records whether red bypassed it."""
    scenario = sqli_scenarios[0]
    playbook = [
        get_pattern("rate_limit_lockout"),
        get_pattern("rotate_param_name"),
    ]
    result = AdaptationChallenge().run(_red_for(scenario), scenario, playbook)
    by_pattern = {entry.pattern: entry for entry in result.rounds}
    assert by_pattern["rate_limit_lockout"].bypassed is True
    assert by_pattern["rotate_param_name"].bypassed is False
    assert result.bypass_counts["rate_limit_lockout"] == 1
    assert result.bypass_counts["rotate_param_name"] == 0


def test_anti_overfit_needs_five_scenarios(sqli_scenarios):
    """A defense may only be declared effective after >=5 scenarios (guard)."""
    pattern = get_pattern("add_input_filter")
    challenge = AdaptationChallenge()
    thin = challenge.evaluate_pattern(pattern, _red_for, sqli_scenarios[:2])
    assert thin.sufficient is False
    assert thin.effective is False
    assert "5" in thin.note

    full = challenge.evaluate_pattern(pattern, _red_for, sqli_scenarios)
    assert full.sufficient is True
    assert full.scenarios_evaluated == len(sqli_scenarios)
    assert full.bypasses == 0
    assert full.effective is True
