"""U-DOJO-11 edge cases: hint costs, lifecycle guards, persistence (L-8)."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from webpent.dojo.scenario_library import ScenarioLibrary
from webpent.dojo.trainer import HINT_COST, StepResult, StepView, TrainingSession

CONFIG_DIR = "config/dojo/scenarios"


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


def _session(library: ScenarioLibrary, ids: list[str] | None = None) -> TrainingSession:
    return TrainingSession(
        library,
        scenario_ids=["sqli-01", "sqli-02"] if ids is None else ids,
        dojo_dir=None,
    )


def _correct_answer(library: ScenarioLibrary, scenario_id: str) -> dict:
    scenario = library.get(scenario_id)
    return {
        "vuln_class": scenario.vuln_class,
        "location": scenario.location,
        "signature": scenario.signature,
    }


def test_hint_cost_is_ten():
    assert HINT_COST == 10.0


def test_one_hint_costs_ten_points(library):
    session = _session(library, ["sqli-01"])
    session.request_hint()
    outcome = session.answer(_correct_answer(library, "sqli-01"))
    assert outcome.correct is True
    assert session.score() == 100.0 - HINT_COST


def test_two_hints_cost_twenty_points(library):
    session = _session(library, ["sqli-01"])
    session.request_hint()
    session.request_hint()
    session.answer(_correct_answer(library, "sqli-01"))
    assert session.score() == 80.0


def test_excess_hint_requests_are_free(library):
    """The exhausted-ladder message costs nothing (no further hint consumed)."""
    session = _session(library, ["sqli-01"])
    for _ in range(6):
        session.request_hint()
    session.answer(_correct_answer(library, "sqli-01"))
    hints = session._hints_per_step[0]
    assert hints == len(library.get("sqli-01").hints)
    assert session.score() == 100.0 - HINT_COST * hints


def test_hints_reset_for_the_next_step(library):
    session = _session(library, ["sqli-01", "sqli-02"])
    session.request_hint()
    session.answer(_correct_answer(library, "sqli-01"))
    assert session.hints_used == 0, "the new step starts with a clean ladder"
    assert session._hints_per_step == [1]


def test_wrong_answer_records_the_hints_it_used(library):
    session = _session(library, ["sqli-01", "sqli-02"])
    session.request_hint()
    session.answer({"vuln_class": "xss", "location": "/x", "signature": "?"})
    session.answer(_correct_answer(library, "sqli-01"))
    # both answers were scored against step 1: two entries for the failed step
    assert len(session._hints_per_step) == 2
    assert session.current_index == 1


def test_present_after_finish_raises(library):
    session = _session(library, ["sqli-01"])
    session.answer(_correct_answer(library, "sqli-01"))
    assert session.finished is True
    with pytest.raises(IndexError):
        session.present()


def test_answer_after_finish_raises(library):
    session = _session(library, ["sqli-01"])
    session.answer(_correct_answer(library, "sqli-01"))
    with pytest.raises(IndexError):
        session.answer(_correct_answer(library, "sqli-01"))


def test_request_hint_after_finish_raises(library):
    session = _session(library, ["sqli-01"])
    session.answer(_correct_answer(library, "sqli-01"))
    with pytest.raises(IndexError):
        session.request_hint()


def test_empty_session_is_finished_with_zero_score(library):
    session = _session(library, [])
    assert session.finished is True
    assert session.score() == 0.0


def test_partial_answer_never_advances(library):
    scenario = library.get("sqli-01")
    session = _session(library, ["sqli-01", "sqli-02"])
    session.answer({
        "vuln_class": scenario.vuln_class,
        "location": scenario.location,
        "signature": "wrong-signature",
    })
    assert session.current_index == 0
    assert session.correct_count == 0


def test_step_view_is_frozen(library):
    session = _session(library, ["sqli-01"])
    view = session.present()
    assert isinstance(view, StepView)
    with pytest.raises(FrozenInstanceError):
        view.scenario_id = "x"  # type: ignore[misc]
    assert isinstance(session.answer({"vuln_class": "x", "location": "y",
                                      "signature": "z"}), StepResult)


def test_save_uses_webpent_dojo_dir_environment(library, tmp_path, monkeypatch):
    monkeypatch.setenv("WEBPENT_DOJO_DIR", str(tmp_path))
    session = _session(library, ["sqli-01"])
    path = session.save()
    assert str(path).startswith(str(tmp_path))


def test_load_preserves_hint_history_and_score(library, tmp_path):
    session = _session(library, ["sqli-01", "sqli-02"])
    session.request_hint()
    session.answer(_correct_answer(library, "sqli-01"))
    session.request_hint()
    session.answer(_correct_answer(library, "sqli-02"))
    assert session.score() == (90.0 + 90.0) / 2
    path = session.save()
    restored = TrainingSession.load(path, library)
    assert restored._hints_per_step == session._hints_per_step == [1, 1]
    assert restored.score() == session.score() == 90.0
