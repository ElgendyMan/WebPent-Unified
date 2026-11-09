"""U-DOJO-2: the Scenario Library (plan: docs/plans/2026-10-16-v85-dojo.md)."""

from __future__ import annotations

from pathlib import Path

import pytest

from webpent.dojo.scenario_library import ScenarioLibrary

CONFIG_DIR = Path("config/dojo/scenarios")

EXPECTED_FAMILIES = {
    "idor", "xss", "sqli", "ssrf", "business_logic",
    "race_condition", "auth_bypass", "jwt", "info_disclosure",
}


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


def test_library_loads_72_scenarios(library: ScenarioLibrary):
    assert len(library.all()) >= 72, (
        f"DoD requires >=72 scenarios, got {len(library.all())}"
    )


def test_every_scenario_has_ground_truth_and_hints(
    library: ScenarioLibrary,
):
    """L-3: no scenario without full ground truth and graduated hints."""
    for scenario in library.all():
        gt = scenario.ground_truth
        assert gt.get("vuln_class"), scenario.scenario_id
        assert gt.get("location"), scenario.scenario_id
        assert gt.get("signature"), scenario.scenario_id
        assert len(scenario.hints) >= 2, scenario.scenario_id
        assert scenario.lesson_tags, scenario.scenario_id
        assert scenario.skill_families, scenario.scenario_id
        assert scenario.request_budget > 0, scenario.scenario_id
        assert 1 <= scenario.difficulty <= 5, scenario.scenario_id


def test_nine_families_present(library: ScenarioLibrary):
    assert set(library.families()) == EXPECTED_FAMILIES
    for family in EXPECTED_FAMILIES:
        items = library.by_family(family)
        assert len(items) >= 8, f"{family} needs >=8 scenarios"


def test_scenario_ids_unique(library: ScenarioLibrary):
    ids = [s.scenario_id for s in library.all()]
    assert len(ids) == len(set(ids))


def test_filter_by_family_and_difficulty(library: ScenarioLibrary):
    easy = library.filter(family="sqli", max_difficulty=2)
    assert easy, "expected easy sqli scenarios"
    assert all(s.difficulty <= 2 for s in easy)
    assert all(s.family == "sqli" for s in easy)


def test_load_is_deterministic(library: ScenarioLibrary):
    """L-4: two loads return identical order and content."""
    again = ScenarioLibrary.load_dir(CONFIG_DIR)
    assert library.all() == again.all()


def test_get_unknown_raises(library: ScenarioLibrary):
    with pytest.raises(KeyError):
        library.get("no-such-scenario")
