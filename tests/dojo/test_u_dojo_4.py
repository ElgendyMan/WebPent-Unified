"""U-DOJO-4: the sparring protocol, red against blue (plan Task 4)."""

from __future__ import annotations

import pytest

from webpent.dojo.defender import DEFENSE_PATTERNS
from webpent.dojo.engine import DojoRequest
from webpent.dojo.lab_generator import LabGenerator
from webpent.dojo.practice_runner import Conclusion
from webpent.dojo.scenario_library import ScenarioLibrary
from webpent.dojo.sparring import SparringMatch

CONFIG_DIR = "config/dojo/scenarios"


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


@pytest.fixture()
def scenario(library: ScenarioLibrary):
    return library.get("sqli-01")


class ScriptedRed:
    """A red agent that replays the ground-truth payload (trainer-built)."""

    def __init__(self, request: DojoRequest, claim: bool = True):
        self._request = request
        self._claim = claim

    def plan(self, lab_view: dict, scenario) -> list[DojoRequest]:
        return [self._request] if self._request is not None else []

    def conclude(self, responses) -> Conclusion:
        return Conclusion(
            claims_finding=self._claim,
            vuln_class="sqli" if self._claim else "",
            location="/login" if self._claim else "",
        )


@pytest.fixture()
def red(scenario) -> ScriptedRed:
    """A red agent built from the pre-patch ground truth (L-3, trainer side)."""
    lab = LabGenerator().start(scenario.template_id, seed=scenario.seed)
    point = next(p for p in lab.vuln_points if p.exploitable)
    return ScriptedRed(DojoRequest("POST", point.path, {point.param: point.signature}))


def test_twelve_defense_patterns_registered():
    assert len(DEFENSE_PATTERNS) >= 10
    names = {p.name for p in DEFENSE_PATTERNS}
    assert {
        "add_input_filter", "elevate_auth_requirement", "rotate_param_name",
        "shrink_request_budget", "normalize_input_matching",
        "remove_vulnerable_route", "require_exploit_token",
        "rate_limit_lockout", "session_bind_param", "strict_type_validation",
        "decoy_hardening", "signature_rotation",
    } <= names


def test_defense_pattern_patches_lab(scenario):
    generator = LabGenerator()
    lab = generator.start(scenario.template_id, seed=scenario.seed)
    for pattern in DEFENSE_PATTERNS:
        patched = pattern.apply(lab)
        assert patched.state_hash != lab.state_hash, pattern.name
        assert patched.instance_id == lab.instance_id


def test_red_win_means_defense_weak(red, scenario):
    """L-6: a red win over a patch is recorded as a blue weakness, unvarnished."""
    pattern = next(p for p in DEFENSE_PATTERNS if p.name == "rate_limit_lockout")
    result = SparringMatch().run(red, scenario, [pattern], rounds=1)
    assert result.winner == "red"
    assert any(
        "weakness" in lesson and "rate_limit_lockout" in lesson
        for lesson in result.lessons
    )


def test_blue_win_when_red_exhausts(red, scenario):
    pattern = next(p for p in DEFENSE_PATTERNS if p.name == "rotate_param_name")
    result = SparringMatch().run(red, scenario, [pattern], rounds=2)
    assert result.winner == "blue"
    assert all(not entry.red_success for entry in result.rounds_log)


def test_match_scores_both_sides(red, scenario):
    held = next(p for p in DEFENSE_PATTERNS if p.name == "add_input_filter")
    broken = next(p for p in DEFENSE_PATTERNS if p.name == "rate_limit_lockout")
    mixed = SparringMatch().run(red, scenario, [broken, held], rounds=2)
    assert 0.0 <= mixed.red_score <= 100.0
    assert 0.0 <= mixed.blue_score <= 100.0
    assert mixed.red_score > 0.0
    assert mixed.blue_score > 0.0
    assert mixed.winner in {"red", "blue"}


def test_match_is_deterministic(red, scenario):
    pattern = next(p for p in DEFENSE_PATTERNS if p.name == "add_input_filter")
    first = SparringMatch().run(red, scenario, [pattern], rounds=2)
    second = SparringMatch().run(red, scenario, [pattern], rounds=2)
    assert first == second


def test_lessons_captured(red, scenario):
    """L-7: lessons come out ready for advisory import, nothing silently dropped."""
    broken = next(p for p in DEFENSE_PATTERNS if p.name == "rate_limit_lockout")
    held = next(p for p in DEFENSE_PATTERNS if p.name == "add_input_filter")
    result = SparringMatch().run(red, scenario, [broken, held], rounds=2)
    assert result.lessons
    assert len(result.lessons) == 2
    assert all(lesson.startswith("advisory:") for lesson in result.lessons)
