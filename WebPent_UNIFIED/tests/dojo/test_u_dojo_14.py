"""U-DOJO-2 edge cases: the library refuses anything incomplete (L-3/L-4)."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
import yaml

from webpent.dojo.scenario_library import ScenarioLibrary

CONFIG_DIR = "config/dojo/scenarios"


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


def _write(tmp_path: Path, payload: dict, name: str = "fam.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return path


def _valid_scenario(**overrides: dict) -> dict:
    data = {
        "scenario_id": "s-1",
        "title": "t",
        "description": "d",
        "difficulty": 2,
        "template_id": "flask_sqli_login",
        "seed": 1,
        "ground_truth": {
            "vuln_class": "sqli", "location": "/login", "signature": "' OR 1=1",
        },
        "hints": ["h1", "h2"],
        "lesson_tags": ["tag"],
        "skill_families": ["sqli"],
        "request_budget": 10,
    }
    data.update(overrides)
    return {"family": "fam", "scenarios": [data]}


def test_missing_field_is_refused_with_names(tmp_path):
    raw = _valid_scenario()
    del raw["scenarios"][0]["hints"]
    _write(tmp_path, raw)
    with pytest.raises(ValueError, match="hints"):
        ScenarioLibrary.load_dir(tmp_path)


def test_ground_truth_must_be_a_mapping(tmp_path):
    raw = _valid_scenario()
    raw["scenarios"][0]["ground_truth"] = "sqli at /login"
    _write(tmp_path, raw)
    with pytest.raises(ValueError, match="mapping"):
        ScenarioLibrary.load_dir(tmp_path)


def test_ground_truth_keys_are_required(tmp_path):
    raw = _valid_scenario()
    del raw["scenarios"][0]["ground_truth"]["signature"]
    _write(tmp_path, raw)
    with pytest.raises(ValueError, match="signature"):
        ScenarioLibrary.load_dir(tmp_path)


def test_difficulty_outside_range_is_refused(tmp_path):
    _write(tmp_path, _valid_scenario(difficulty=6))
    with pytest.raises(ValueError, match="difficulty"):
        ScenarioLibrary.load_dir(tmp_path)
    _write(tmp_path, _valid_scenario(difficulty=0), "two.yaml")
    with pytest.raises(ValueError, match="difficulty"):
        ScenarioLibrary.load_dir(tmp_path)


def test_nonpositive_budget_is_refused(tmp_path):
    _write(tmp_path, _valid_scenario(request_budget=0))
    with pytest.raises(ValueError, match="request_budget"):
        ScenarioLibrary.load_dir(tmp_path)


def test_fewer_than_two_hints_is_refused(tmp_path):
    _write(tmp_path, _valid_scenario(hints=["only"]))
    with pytest.raises(ValueError, match="hints"):
        ScenarioLibrary.load_dir(tmp_path)


def test_missing_directory_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        ScenarioLibrary.load_dir(tmp_path / "absent")


def test_yaml_without_scenarios_key_raises(tmp_path):
    (tmp_path / "bad.yaml").write_text("family: sqli\n", encoding="utf-8")
    with pytest.raises(ValueError, match="scenarios"):
        ScenarioLibrary.load_dir(tmp_path)


def test_duplicate_ids_are_refused(tmp_path):
    raw = _valid_scenario()
    raw["scenarios"].append(dict(raw["scenarios"][0]))
    _write(tmp_path, raw)
    with pytest.raises(ValueError, match="duplicate"):
        ScenarioLibrary.load_dir(tmp_path)


def test_filter_combinations(library):
    easy_sqli = library.filter(
        family="sqli", max_difficulty=2, skill_family="sqli"
    )
    assert easy_sqli
    assert all(s.family == "sqli" and s.difficulty <= 2 for s in easy_sqli)
    hard = library.filter(min_difficulty=4)
    assert all(s.difficulty >= 4 for s in hard)
    nothing = library.filter(family="sqli", min_difficulty=9)
    assert nothing == ()


def test_get_unknown_id_raises_keyerror(library):
    with pytest.raises(KeyError):
        library.get("no-such-scenario")


def test_by_family_unknown_family_is_empty(library):
    assert library.by_family("not-a-family") == ()


def test_reload_is_deterministic(library):
    again = ScenarioLibrary.load_dir(CONFIG_DIR)
    assert again.scenarios == library.scenarios


def test_scenario_properties_expose_ground_truth(library):
    scenario = library.get("sqli-01")
    assert scenario.vuln_class == scenario.ground_truth["vuln_class"]
    assert scenario.location == scenario.ground_truth["location"]
    assert scenario.signature == scenario.ground_truth["signature"]
    assert len(scenario.hints) >= 2


def test_scenario_is_frozen(library):
    scenario = library.get("sqli-01")
    with pytest.raises(FrozenInstanceError):
        scenario.difficulty = 9  # type: ignore[misc]
