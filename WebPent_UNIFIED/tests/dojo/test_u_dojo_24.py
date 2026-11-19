"""U-DOJO-2/9 edge cases: lab lifecycle and bounded, seeded plans."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError

import pytest

from webpent.dojo.lab_generator import EXTERNAL_LABS, LabGenerator
from webpent.dojo.practice_generator import (
    MAX_FOCUS_ITEMS_PER_FAMILY,
    MAX_SPARRING_ITEMS,
    MAX_WARMUP_ITEMS,
    PHASES,
    PracticeGenerator,
    TrainingPlan,
)
from webpent.dojo.practice_runner import PracticeResult
from webpent.dojo.scenario_library import ScenarioLibrary
from webpent.dojo.weakness_identifier import Weakness, WeaknessIdentifier

CONFIG_DIR = "config/dojo/scenarios"


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


@pytest.fixture()
def generator() -> LabGenerator:
    return LabGenerator()


# -- the lab factory ------------------------------------------------------------


def test_nine_templates_are_listed_sorted(generator):
    templates = generator.list_available()
    assert len(templates) == 9
    ids = [t.template_id for t in templates]
    assert ids == sorted(ids)


def test_unknown_template_raises_keyerror(generator):
    with pytest.raises(KeyError):
        generator.start("no-such-template", seed=1)


def test_external_template_is_refused_by_name(generator):
    assert EXTERNAL_LABS
    with pytest.raises(ValueError, match=next(iter(EXTERNAL_LABS))):
        generator.start(next(iter(EXTERNAL_LABS)), seed=1)


def test_same_seed_builds_identical_labs(generator):
    a = generator.start("flask_sqli_login", seed=42)
    b = generator.start("flask_sqli_login", seed=42)
    assert a.instance_id == b.instance_id
    assert a.state_hash == b.state_hash
    assert a.valid_tokens == b.valid_tokens


def test_different_seeds_diverge(generator):
    a = generator.start("flask_sqli_login", seed=1)
    b = generator.start("flask_sqli_login", seed=2)
    assert a.instance_id != b.instance_id
    assert a.valid_tokens != b.valid_tokens


def test_retention_keeps_only_five_instances(generator):
    ids = [generator.start("flask_sqli_login", seed=i).instance_id for i in range(7)]
    alive = [i for i in ids if _alive(generator, i)]
    assert len(alive) == 5


def _alive(generator, instance_id: str) -> bool:
    try:
        generator.get(instance_id)
    except KeyError:
        return False
    return True


def test_stop_retires_a_lab(generator):
    lab = generator.start("flask_sqli_login", seed=9)
    generator.stop(lab.instance_id)
    with pytest.raises(KeyError):
        generator.get(lab.instance_id)


def test_reset_restores_budget_and_flags(generator):
    lab = generator.start("flask_sqli_login", seed=9)
    fresh_state = lab.state_hash
    lab.request_budget = 0
    lab.normalize_input = True
    generator.reset(lab.instance_id)
    restored = generator.get(lab.instance_id)
    assert restored.request_budget > 0
    assert restored.state_hash == fresh_state


def test_get_vuln_map_separates_truth_from_decoys(generator):
    lab = generator.start("flask_sqli_login", seed=9)
    payload = generator.get_vuln_map(lab.instance_id)
    assert payload["vuln_points"]
    assert payload["decoys"]
    assert all(p.exploitable for p in payload["vuln_points"])
    assert not any(p.exploitable for p in payload["decoys"])


def test_retention_retires_the_oldest_first(generator):
    ids = [
        generator.start("php_xss_comment_board", seed=i).instance_id
        for i in range(6)
    ]
    assert _alive(generator, ids[0]) is False
    assert all(_alive(generator, i) for i in ids[1:])


# -- the plan generator -----------------------------------------------------------


def _weakness(kind: str, family: str = "sqli", severity: float = 0.9) -> Weakness:
    return Weakness(kind=kind, skill_family=family, severity=severity,
                    detail=f"advisory: {kind}")


def _results(sid: str, success: bool, score: float, n: int = 5) -> list:
    return [
        PracticeResult(
            scenario_id=sid, success=success, score=score, requests_used=1,
            false_positives=0 if success else 1, time_steps=1, budget=10,
        )
        for _ in range(n)
    ]


def test_phases_are_the_four_specified():
    assert PHASES == ("warmup", "focus", "sparring", "reassessment")


def test_plan_without_weaknesses_has_only_warmup(library):
    plan = PracticeGenerator().generate([], library, seed=0)
    assert plan.focus == ()
    assert plan.sparring == ()
    assert plan.warmup
    assert plan.reassessment


def test_warmup_only_uses_easy_scenarios(library):
    plan = PracticeGenerator().generate([], library, seed=0)
    ids = {item.scenario_id for item in plan.warmup}
    assert ids
    for scenario_id in ids:
        assert library.get(scenario_id).difficulty <= 2


def test_warmup_is_capped(library):
    plan = PracticeGenerator().generate([], library, seed=0)
    assert len(plan.warmup) <= MAX_WARMUP_ITEMS


def test_focus_targets_the_weakest_family_first(library):
    scenarios = list(library.all())
    results = (
        _results("sqli-01", False, 20.0)
        + _results("xss-01", False, 60.0)
    )
    weaknesses = WeaknessIdentifier().identify(
        results, [s for s in scenarios if s.scenario_id in ("sqli-01", "xss-01")]
    )
    plan = PracticeGenerator().generate(weaknesses, library, seed=0)
    assert plan.focus
    assert plan.focus[0].family == "sqli"


def test_focus_per_family_is_capped(library):
    sqli_scenarios = [s for s in library.all() if s.family == "sqli"]
    results = [
        r for sid in [s.scenario_id for s in sqli_scenarios]
        for r in _results(sid, False, 10.0)
    ]
    scenarios = [s for s in library.all() if s.scenario_id in {
        r.scenario_id for r in results
    }]
    weaknesses = WeaknessIdentifier().identify(results, scenarios)
    plan = PracticeGenerator().generate(weaknesses, library, seed=0)
    sqli_focus = [i for i in plan.focus if i.family == "sqli"]
    assert sqli_focus
    assert len(sqli_focus) <= MAX_FOCUS_ITEMS_PER_FAMILY


def test_sparring_is_capped_and_honest(library):
    plan = PracticeGenerator().generate(
        [_weakness("skill_gap"), _weakness("consistency_gap", "xss"),
         _weakness("speed_gap", "jwt")],
        library, seed=0,
    )
    assert 0 < len(plan.sparring) <= MAX_SPARRING_ITEMS


def test_plan_roundtrips_through_json(library):
    plan = PracticeGenerator().generate([_weakness("skill_gap")], library, seed=2)
    payload = json.loads(json.dumps(plan.as_dict()))
    assert payload["seed"] == 2
    assert set(payload) == {"seed", "warmup", "focus", "sparring", "reassessment"}


def test_plan_item_describes_its_phase(library):
    plan = PracticeGenerator().generate([_weakness("skill_gap")], library, seed=2)
    assert plan.focus[0].phase == "focus"
    assert plan.warmup[0].phase == "warmup"
    assert plan.sparring[0].phase == "sparring"
    assert all(item.drills for item in plan.focus)


def test_plan_is_frozen(library):
    plan = PracticeGenerator().generate([_weakness("skill_gap")], library, seed=2)
    with pytest.raises(FrozenInstanceError):
        plan.seed = 99  # type: ignore[misc]
    assert isinstance(plan, TrainingPlan)
