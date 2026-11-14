"""RED-TEAM ROUND 2 - dojo C2/C3 batch, fail-first (0.34.0 window).

Every test below was written BEFORE its fix and fails on the current
baseline; each corresponds to one verified finding from
docs/RED_TEAM_ROUND2_20261102.md section 2:

    R2-dojo-02   PracticeRunner scores/records the scenario budget even
                 when a pattern-hardened lab enforces a smaller one
    R2-dojo-03   adaptation gaps derive scenario.family instead of
                 scenario.skill_families -> undrillable weaknesses
    R2-dojo-04   a pattern red never faces is still declared effective
    R2-dojo-05   the skill CLI enumerates scenario.family values while
                 SkillAssessor matches scenario.skill_families
    R2-dojo-06   the input-filter denylist is case-sensitive while the
                 default signature matcher is case-insensitive
    R2-dojo-07   normalize_input checked first makes strict_types a
                 silent no-op when both toggles are set
    R2-dojo-08   cap=1 keeps every line (lines[-0:] slice)
    R2-dojo-09   load_dir silently skips .yml files
    R2-dojo-10   trainer save() is a plain, non-atomic write_text
"""

from __future__ import annotations

import json
import os

import pytest
from typer.testing import CliRunner

from webpent.cli.dojo import PREAMBLE_LINE, dojo_app
from webpent.dojo.counter_adapter import AdaptationChallenge
from webpent.dojo.defender import get_pattern
from webpent.dojo.engine import DojoRequest, SimulatedTarget
from webpent.dojo.lab_generator import LabGenerator
from webpent.dojo.practice_runner import Conclusion, PracticeRunner
from webpent.dojo.progress import ProgressTracker
from webpent.dojo.scenario_library import Scenario, ScenarioLibrary
from webpent.dojo.sparring import SparringMatchResult
from webpent.dojo.trainer import TrainingSession
from webpent.dojo.weakness_identifier import WeaknessIdentifier

CONFIG_DIR = "config/dojo/scenarios"
TARGET = SimulatedTarget()
GENERATOR = LabGenerator()
RUNNER = CliRunner()


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


def _scenario(scenario_id: str, **overrides) -> Scenario:
    """A synthetic sqli scenario with a fully controlled budget."""
    data = {
        "scenario_id": scenario_id,
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
        "request_budget": 16,
    }
    data.update(overrides)
    return Scenario(**data)


class _ChattyRed:
    """Burns one request per wave, never claims anything (fp stays 0)."""

    def plan(self, lab_view, scenario) -> list[DojoRequest]:
        return [DojoRequest("POST", "/login", {"username": "probe"})]

    def conclude(self, responses) -> Conclusion:
        return Conclusion(claims_finding=False)


def _truth_red(scenario: Scenario):
    """A ground-truth red agent, built from the trainer-side vuln map."""
    lab = GENERATOR.start(scenario.template_id, seed=scenario.seed)
    point = next(p for p in lab.vuln_points if p.exploitable)
    request = DojoRequest("POST", point.path, {point.param: point.signature})

    class _Red:
        def plan(self, lab_view, scen) -> list[DojoRequest]:
            return [request]

        def conclude(self, responses) -> Conclusion:
            return Conclusion(
                claims_finding=True,
                vuln_class=scenario.vuln_class,
                location=scenario.location,
            )

    return _Red()


# ---------------------------------------------------------------------------
# R2-dojo-02
# ---------------------------------------------------------------------------

def test_r2dojo_02_runner_scores_with_enforced_pattern_budget():
    """A pattern-hardened lab enforces its own smaller budget; the score
    and the recorded budget must use the enforced budget, not the
    scenario's, or the hardening inflates the score mechanically (L-5)."""
    scenario = _scenario("r2d2-1", request_budget=16)
    lab = GENERATOR.start(scenario.template_id, seed=scenario.seed)
    lab.request_budget = int(scenario.request_budget)
    lab = get_pattern("shrink_request_budget").apply(lab)
    assert lab.request_budget == 4

    result = PracticeRunner().run(_ChattyRed(), scenario, lab)

    # the lab consumed exactly its enforced 4-request budget
    assert result.requests_used == 4
    # the recorded budget is the ENFORCED one, not the scenario's 16
    assert result.budget == 4
    # 4/4 used of a 4 budget: efficiency terms floor at 0 -> 100 * 0.2
    assert result.score == 20.0

    # control: a fresh lab is still sized by the scenario budget
    fresh = PracticeRunner().run(_ChattyRed(), scenario)
    assert fresh.budget == 16


# ---------------------------------------------------------------------------
# R2-dojo-03
# ---------------------------------------------------------------------------

def test_r2dojo_03_adaptation_gaps_use_skill_families(library):
    """adaptation gaps must be emitted per ground-truth skill family
    (jwt scenarios carry [jwt_weakness, jwt_key_confusion], family jwt);
    otherwise library.filter(skill_family=...) never drills them."""
    scenario = library.get("jwt-01")
    match = SparringMatchResult(
        scenario_id="jwt-01", red_score=88.0, blue_score=12.0,
        winner="red", rounds_log=(), lessons=(),
    )
    weaknesses = WeaknessIdentifier().identify([], [scenario], [match])
    gaps = [w for w in weaknesses if w.kind == "adaptation_gap"]
    assert {w.skill_family for w in gaps} == {
        "jwt_weakness", "jwt_key_confusion",
    }
    # and every emitted family is actually drillable via the generator path
    for gap in gaps:
        assert library.filter(skill_family=gap.skill_family)


# ---------------------------------------------------------------------------
# R2-dojo-04
# ---------------------------------------------------------------------------

def test_r2dojo_04_verdict_requires_pattern_application():
    """If red never wins a baseline round the pattern is never applied in
    any round; bypasses==0 then says nothing and must NOT read effective."""
    scenarios = [
        _scenario(f"r2d4-{i}", seed=30 + i) for i in range(1, 6)
    ]

    def losing_red(scenario):
        class _Loser:
            def plan(self, lab_view, scen):
                return []

            def conclude(self, responses):
                return Conclusion(claims_finding=False)

        return _Loser()

    challenge = AdaptationChallenge()
    verdict = challenge.evaluate_pattern(
        get_pattern("rate_limit_lockout"), losing_red, scenarios
    )
    assert verdict.sufficient is True
    assert verdict.bypasses == 0
    assert verdict.effective is False
    assert "pattern never applied" in verdict.note

    # control: when red does win a baseline round the pattern is applied;
    # a held pattern with zero bypasses stays effective as before
    verdict_held = challenge.evaluate_pattern(
        get_pattern("rotate_param_name"), _truth_red, scenarios
    )
    assert verdict_held.sufficient is True
    assert verdict_held.bypasses == 0
    assert verdict_held.effective is True


# ---------------------------------------------------------------------------
# R2-dojo-05
# ---------------------------------------------------------------------------

def test_r2dojo_05_skill_cmd_enumerates_skill_families(tmp_path):
    """``dojo skill`` must enumerate scenario.skill_families (what
    SkillAssessor.assess matches), not scenario.family values, or shipped
    families like jwt_weakness can never be sampled."""
    result = RUNNER.invoke(dojo_app, ["skill", "--dojo-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output.split(PREAMBLE_LINE + "\n", 1)[1])
    profiles = [p["skill_family"] for p in payload["profiles"]]
    assert "jwt_weakness" in profiles
    assert "jwt_key_confusion" in profiles
    expected = sorted(
        {f for s in ScenarioLibrary.load_dir(CONFIG_DIR).all()
         for f in s.skill_families}
    )
    assert profiles == expected


# ---------------------------------------------------------------------------
# R2-dojo-06
# ---------------------------------------------------------------------------

def test_r2dojo_06_input_filter_is_case_insensitive_by_default():
    """The default matcher is case-insensitive, so the denylist check must
    be too, or case variants of the exact accepted payload evade it."""
    lab = GENERATOR.start("flask_sqli_login", seed=5)
    lab = get_pattern("add_input_filter").apply(lab)
    variant = TARGET.respond(
        lab, DojoRequest("POST", "/login", {"username": "' or 1=1"})
    )
    assert variant.has("filtered"), f"case variant evaded the filter: {variant}"
    assert not variant.has("vuln_hit")
    # control: the exact-case payload is filtered as before
    exact = TARGET.respond(
        lab, DojoRequest("POST", "/login", {"username": "' OR 1=1"})
    )
    assert exact.has("filtered")


# ---------------------------------------------------------------------------
# R2-dojo-07
# ---------------------------------------------------------------------------

def test_r2dojo_07_strict_types_takes_precedence_over_normalize():
    """With both toggles set, strict_types must win: a superstring of the
    signature is not an exact match and must not hit the vuln point."""
    lab = GENERATOR.start("flask_sqli_login", seed=5)
    lab.normalize_input = True
    lab.strict_types = True
    padded = TARGET.respond(
        lab, DojoRequest("POST", "/login", {"username": "' OR 1=1 --"})
    )
    assert padded.has("ok"), f"strict_types was shadowed: {padded}"
    assert not padded.has("vuln_hit")
    # control: the exact signature still matches under strict_types
    exact = TARGET.respond(
        lab, DojoRequest("POST", "/login", {"username": "' OR 1=1"})
    )
    assert exact.has("vuln_hit")


# ---------------------------------------------------------------------------
# R2-dojo-08
# ---------------------------------------------------------------------------

def test_r2dojo_08_append_line_cap_of_one_trims_to_one(tmp_path):
    """cap=1 used to slice lines[-0:], which keeps everything; the cap
    must always trim, keeping only the newest line."""
    path = tmp_path / "capped.jsonl"
    ProgressTracker._append_line(path, "first", cap=1)
    ProgressTracker._append_line(path, "second", cap=1)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines == ["second"]


# ---------------------------------------------------------------------------
# R2-dojo-09
# ---------------------------------------------------------------------------

def _scenario_yaml(scenario_id: str, seed: int) -> str:
    return (
        "family: mix\n"
        "scenarios:\n"
        f"  - scenario_id: {scenario_id}\n"
        "    title: t\n"
        "    description: d\n"
        "    difficulty: 1\n"
        "    template_id: flask_sqli_login\n"
        f"    seed: {seed}\n"
        "    ground_truth: {vuln_class: sqli, location: /login,"
        " signature: \"' OR 1=1\"}\n"
        "    hints: [h1, h2]\n"
        "    lesson_tags: [tag]\n"
        "    skill_families: [sqli]\n"
        "    request_budget: 8\n"
    )


def test_r2dojo_09_load_dir_reads_yml_files(tmp_path):
    """The docstring promises every YAML file; .yml files must load too,
    deterministically ordered with the .yaml ones."""
    (tmp_path / "alpha.yaml").write_text(
        _scenario_yaml("r2d9-a", 11), encoding="utf-8"
    )
    (tmp_path / "beta.yml").write_text(
        _scenario_yaml("r2d9-b", 12), encoding="utf-8"
    )
    loaded = ScenarioLibrary.load_dir(tmp_path)
    ids = [s.scenario_id for s in loaded.all()]
    assert ids == ["r2d9-a", "r2d9-b"]


# ---------------------------------------------------------------------------
# R2-dojo-10
# ---------------------------------------------------------------------------

def test_r2dojo_10_trainer_save_is_atomic_and_cleans_up(tmp_path, monkeypatch):
    """save() must write through a temp file and os.replace, leaving the
    previously saved state intact and no temp file behind on failure."""
    session = TrainingSession(library, ["sqli-01"], dojo_dir=tmp_path)
    first = session.save()
    good = first.read_text(encoding="utf-8")
    assert TrainingSession.load(first, library).scenario_ids == ("sqli-01",)

    def crash(src, dst):
        raise OSError("simulated crash mid-write")

    monkeypatch.setattr(os, "replace", crash)
    with pytest.raises(OSError):
        session.save()
    monkeypatch.undo()

    # the previously saved state file is untouched
    assert first.read_text(encoding="utf-8") == good
    # and no torn temp file was left behind
    assert list(tmp_path.glob("*.tmp")) == []
