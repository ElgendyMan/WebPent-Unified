"""U-DOJO-3 edge cases: the score formula and the honesty judge (L-6)."""

from __future__ import annotations

from webpent.dojo.engine import DojoRequest
from webpent.dojo.lab_generator import LabGenerator
from webpent.dojo.practice_runner import Conclusion, PracticeResult, PracticeRunner
from webpent.dojo.scenario_library import Scenario

BUDGET = 10


def _scenario(**overrides) -> Scenario:
    data = {
        "scenario_id": "t-1",
        "family": "sqli",
        "title": "t",
        "description": "d",
        "difficulty": 1,
        "template_id": "flask_sqli_login",
        "seed": 3,
        "ground_truth": {
            "vuln_class": "sqli", "location": "/login", "signature": "' OR 1=1",
        },
        "hints": ("h1", "h2"),
        "lesson_tags": ("tag",),
        "skill_families": ("sqli",),
        "request_budget": BUDGET,
    }
    data.update(overrides)
    return Scenario(**data)


class _FixedAgent:
    """Plans one correct probe, concludes with a fixed conclusion."""

    name = "fixed"

    def __init__(self, conclusion: Conclusion) -> None:
        self.conclusion = conclusion

    def plan(self, lab_view, scenario) -> list[DojoRequest]:
        return [DojoRequest("POST", "/login", {"username": "' OR 1=1"})]

    def conclude(self, responses) -> Conclusion:
        return self.conclusion


# -- the formula, hand-computed -------------------------------------------------


def test_score_perfect_run():
    # 100 * (0.5 + 0.2*(1-1/10) + 0.1*(1-1/10) + 0.2) = 97.0
    assert PracticeRunner.score(
        success=True, requests_used=1, time_steps=1,
        false_positives=0, budget=BUDGET,
    ) == 97.0


def test_score_zero_budget_is_bounded_not_dividing_by_zero():
    value = PracticeRunner.score(
        success=True, requests_used=0, time_steps=0,
        false_positives=0, budget=0,
    )
    assert value == 100.0


def test_score_time_overflow_floors_at_zero():
    value = PracticeRunner.score(
        success=True, requests_used=0, time_steps=BUDGET + 5,
        false_positives=0, budget=BUDGET,
    )
    # time_eff floored to 0; success + requests(0) + no-fp terms: 100*0.8 = 80.0
    assert value == 80.0


def test_score_request_overflow_floors_at_zero():
    value = PracticeRunner.score(
        success=True, requests_used=BUDGET * 3, time_steps=1,
        false_positives=0, budget=BUDGET,
    )
    # req_eff floored; time_eff 0.9: 100*(0.5+0.18+0.2) = 88.0
    assert value == 88.0


def test_score_false_positive_costs_twenty_points():
    clean = PracticeRunner.score(
        success=True, requests_used=0, time_steps=0,
        false_positives=0, budget=BUDGET,
    )
    dirty = PracticeRunner.score(
        success=True, requests_used=0, time_steps=0,
        false_positives=1, budget=BUDGET,
    )
    assert clean - dirty == 20.0


def test_score_failed_honest_run_keeps_efficiency_terms():
    value = PracticeRunner.score(
        success=False, requests_used=2, time_steps=1,
        false_positives=0, budget=BUDGET,
    )
    # 100 * (0.2*0.9 + 0.1*0.8 + 0.2) = 46.0
    assert value == 46.0


# -- the judge (L-6) -------------------------------------------------------------


def _run_with(conclusion: Conclusion, scenario: Scenario) -> PracticeResult:
    lab = LabGenerator().start(scenario.template_id, seed=scenario.seed)
    return PracticeRunner().run(_FixedAgent(conclusion), scenario, lab)


def test_honest_correct_claim_succeeds():
    result = _run_with(
        Conclusion(claims_finding=True, vuln_class="sqli", location="/login"),
        _scenario(),
    )
    assert result.success is True
    assert result.false_positives == 0


def test_claim_without_evidence_is_a_false_positive():
    result = _run_with(
        Conclusion(claims_finding=True, vuln_class="sqli", location="/login"),
        _scenario(template_id="php_xss_comment_board"),
    )
    assert result.success is False
    assert result.false_positives == 1


def test_evidence_without_claim_is_not_a_false_positive():
    result = _run_with(
        Conclusion(claims_finding=False), _scenario()
    )
    assert result.success is False
    assert result.false_positives == 0


def test_wrong_class_claim_is_judged_false():
    result = _run_with(
        Conclusion(claims_finding=True, vuln_class="xss", location="/login"),
        _scenario(),
    )
    assert result.success is False
    assert result.false_positives == 1


def test_wrong_location_claim_is_judged_false():
    result = _run_with(
        Conclusion(claims_finding=True, vuln_class="sqli", location="/dashboard"),
        _scenario(),
    )
    assert result.success is False
    assert result.false_positives == 1


def test_budget_exhaustion_stops_the_waves():
    scenario = _scenario(request_budget=3)
    lab = LabGenerator().start(scenario.template_id, seed=scenario.seed)
    # RT-02 corrected semantics: a provided lab keeps its own budget, so the
    # exhaustion line is set on the lab, not stomped in by the runner
    lab.request_budget = 3
    result = PracticeRunner().run(_FixedAgent(Conclusion(False)), scenario, lab)
    assert result.requests_used == 3
    assert result.time_steps <= 3


def test_run_respects_provided_lab_budget_keeps_own():
    # RT-02 corrected semantics: a lab handed in keeps its own budget (only
    # consumed by its requests), never stomped to the scenario budget (L-5)
    scenario = _scenario()
    lab = LabGenerator().start(scenario.template_id, seed=scenario.seed)
    lab.request_budget = 999
    result = PracticeRunner().run(_FixedAgent(Conclusion(False)), scenario, lab)
    assert lab.request_budget == 999 - result.requests_used


def test_run_sizes_a_fresh_lab_with_scenario_budget():
    scenario = _scenario()
    result = PracticeRunner().run(_FixedAgent(Conclusion(False)), scenario)
    assert result.budget == BUDGET


def test_evidence_records_the_transcript():
    result = _run_with(
        Conclusion(claims_finding=True, vuln_class="sqli", location="/login"),
        _scenario(),
    )
    assert any("vuln_hit" in line for line in result.evidence)
    assert any(line.startswith("claim:") for line in result.evidence)


def test_result_roundtrips_through_json():
    result = _run_with(Conclusion(False), _scenario())
    payload = result.as_dict()
    assert payload["scenario_id"] == "t-1"
    assert isinstance(payload["evidence"], list)
