"""U-DOJO-3: the practice runner (plan: docs/plans/2026-10-16-v85-dojo.md)."""

from __future__ import annotations

import socket

import pytest

from webpent.dojo.engine import DojoRequest
from webpent.dojo.lab_generator import LabGenerator
from webpent.dojo.practice_runner import Conclusion, PracticeRunner
from webpent.dojo.scenario_library import ScenarioLibrary

CONFIG_DIR = "config/dojo/scenarios"


class ScriptedAgent:
    """A deterministic agent with a fixed plan and conclusion."""

    def __init__(self, requests: list[DojoRequest], conclusion: Conclusion):
        self._requests = list(requests)
        self._conclusion = conclusion

    def plan(self, lab_view: dict, scenario) -> list[DojoRequest]:
        # one planning wave, then signal done with an empty plan
        planned, self._requests = self._requests, []
        return planned

    def conclude(self, responses) -> Conclusion:
        return self._conclusion


def _agent_for(scenario, *, claim: bool) -> ScriptedAgent:
    """Build a scripted agent from the trainer-side ground truth (L-3)."""
    generator = LabGenerator()
    lab = generator.start(scenario.template_id, seed=scenario.seed)
    point = next(p for p in lab.vuln_points if p.exploitable)
    request = DojoRequest(
        "GET" if point.path != "/login" else "POST",
        point.path,
        {point.param: point.signature},
        {},
    )
    conclusion = Conclusion(
        claims_finding=claim,
        vuln_class=scenario.vuln_class if claim else "",
        location=scenario.location if claim else "",
        signature=scenario.signature if claim else "",
    )
    return ScriptedAgent([request], conclusion)


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


@pytest.fixture()
def runner() -> PracticeRunner:
    return PracticeRunner(LabGenerator())


def test_correct_payload_succeeds(runner: PracticeRunner, library: ScenarioLibrary):
    scenario = library.get("sqli-01")
    result = runner.run(_agent_for(scenario, claim=True), scenario)
    assert result.success is True
    assert result.false_positives == 0
    assert result.requests_used == 1
    assert result.score > 50.0
    assert any("vuln_hit" in step for step in result.evidence)


def test_wrong_payload_fails(runner: PracticeRunner, library: ScenarioLibrary):
    scenario = library.get("sqli-01")
    agent = ScriptedAgent(
        [DojoRequest("POST", "/login", {"username": "admin", "password": "x"})],
        Conclusion(claims_finding=True, vuln_class="sqli", location="/login"),
    )
    result = runner.run(agent, scenario)
    assert result.success is False
    assert result.score < 50.0


def test_decoy_claim_is_false_positive(
    runner: PracticeRunner, library: ScenarioLibrary
):
    """L-6: claiming a decoy hit is recorded as a false positive, score drops."""
    scenario = library.get("sqli-01")
    generator = LabGenerator()
    lab = generator.start(scenario.template_id, seed=scenario.seed)
    decoy = next(p for p in lab.vuln_points if not p.exploitable)
    agent = ScriptedAgent(
        [DojoRequest("POST", decoy.path, {decoy.param: decoy.signature})],
        Conclusion(
            claims_finding=True,
            vuln_class=scenario.vuln_class,
            location=scenario.location,
        ),
    )
    honest = ScriptedAgent(
        [DojoRequest("POST", decoy.path, {decoy.param: decoy.signature})],
        Conclusion(claims_finding=False),
    )
    claiming = runner.run(agent, scenario)
    honest_result = runner.run(honest, scenario)
    assert claiming.success is False
    assert claiming.false_positives == 1
    assert claiming.score < honest_result.score


def test_score_formula_matches_spec():
    """score = 100 x (0.5s + 0.2t + 0.1r + 0.2(1-fp)), hand-computed cases."""
    # perfect: budget 10, 1 request, 1 step, no fp:
    # 100 x (0.5 + 0.2x0.9 + 0.1x0.9 + 0.2x1) = 100 x 0.97 = 97.0
    assert PracticeRunner.score(
        success=True, requests_used=1, time_steps=1,
        false_positives=0, budget=10,
    ) == 97.0
    # failure with an fp claim: budget 10, 4 requests, 1 step:
    # 100 x (0 + 0.2x0.9 + 0.1x0.6 + 0.2x0) = 100 x 0.24 = 24.0
    assert PracticeRunner.score(
        success=False, requests_used=4, time_steps=1,
        false_positives=1, budget=10,
    ) == 24.0
    # wasted everything: 0
    assert PracticeRunner.score(
        success=False, requests_used=10, time_steps=10,
        false_positives=1, budget=10,
    ) == 0.0


def test_same_seed_same_result(library: ScenarioLibrary):
    """L-4: identical seed and agent produce identical PracticeResult."""
    scenario = library.get("sqli-01")
    first = PracticeRunner(LabGenerator()).run(
        _agent_for(scenario, claim=True), scenario
    )
    second = PracticeRunner(LabGenerator()).run(
        _agent_for(scenario, claim=True), scenario
    )
    assert first == second


def test_no_network_in_practice(
    runner: PracticeRunner, library: ScenarioLibrary, monkeypatch
):
    """L-1: practice runs with sockets disabled end to end."""

    def explode(*args, **kwargs):
        raise AssertionError("no network calls allowed in the dojo (L-1)")

    monkeypatch.setattr(socket, "socket", explode)
    scenario = library.get("idor-01")
    result = runner.run(_agent_for(scenario, claim=True), scenario)
    assert result.success is True
