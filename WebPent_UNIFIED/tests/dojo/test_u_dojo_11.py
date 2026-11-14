"""U-DOJO-11: the operator trainer (plan Task 11)."""

from __future__ import annotations

import pytest

from webpent.dojo.scenario_library import ScenarioLibrary
from webpent.dojo.trainer import TrainingSession

CONFIG_DIR = "config/dojo/scenarios"


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


@pytest.fixture
def session(library: ScenarioLibrary) -> TrainingSession:
    return TrainingSession(
        library,
        scenario_ids=["sqli-01", "sqli-02", "sqli-03"],
        dojo_dir=None,  # in-memory; save() decides the target
    )


def test_session_starts_with_preamble(session):
    """L-8: a preamble comes before any training content."""
    preamble = session.preamble()
    assert preamble.strip()
    assert "advisory" in preamble.lower()
    assert "simulated" in preamble.lower()


def test_step_present_evaluate_advance(library, session):
    """Deterministic cycle: present -> answer -> evaluate -> next."""
    view = session.present()
    # L-3: the surface view never leaks ground truth
    assert view.scenario_id == "sqli-01"
    dumped = repr(view)
    assert "topsecret" not in dumped.lower()

    wrong = session.answer({"vuln_class": "xss", "location": "/nope", "signature": "?"})
    assert wrong.correct is False
    assert session.current_index == 0, "a wrong answer does not advance"

    scenario = library.get("sqli-01")
    right = session.answer(
        {
            "vuln_class": scenario.vuln_class,
            "location": scenario.location,
            "signature": scenario.signature,
        }
    )
    assert right.correct is True
    assert session.current_index == 1, "a correct answer advances to the next step"


def test_hint_escalation(library, session):
    first = session.request_hint()
    second = session.request_hint()
    assert first != second
    scenario = library.get("sqli-01")
    assert first == scenario.hints[0]
    assert second == scenario.hints[1]
    last = session.request_hint()
    assert last == scenario.hints[2]
    exhausted = session.request_hint()
    assert exhausted != first
    assert "no more hints" in exhausted.lower()


def test_session_completes_with_score(library, session):
    for scenario_id in ("sqli-01", "sqli-02", "sqli-03"):
        scenario = library.get(scenario_id)
        session.answer(
            {
                "vuln_class": scenario.vuln_class,
                "location": scenario.location,
                "signature": scenario.signature,
            }
        )
    assert session.finished is True
    assert session.score() == 100.0


def test_session_state_isolated(library, tmp_path):
    """Session state lives only inside the dojo folder (L-2/L-10)."""
    session = TrainingSession(
        library, scenario_ids=["sqli-01", "sqli-02"], dojo_dir=tmp_path
    )
    session.answer(
        {
            "vuln_class": library.get("sqli-01").vuln_class,
            "location": library.get("sqli-01").location,
            "signature": library.get("sqli-01").signature,
        }
    )
    state_path = session.save()
    assert str(state_path).startswith(str(tmp_path))
    assert state_path.exists()

    restored = TrainingSession.load(state_path, library)
    assert restored.current_index == session.current_index
    assert restored.score() == session.score()
