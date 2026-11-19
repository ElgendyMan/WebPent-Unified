"""Dojo integration: the whole training environment, laws and all."""

from __future__ import annotations

import json
import os
import resource
import subprocess
import sys
import time

import pytest

from webpent.dojo.case_study import CaseStudyWriter
from webpent.dojo.defender import DEFENSE_PATTERNS
from webpent.dojo.practice_generator import PracticeGenerator
from webpent.dojo.practice_runner import PracticeRunner
from webpent.dojo.progress import ProgressTracker
from webpent.dojo.scenario_library import ScenarioLibrary
from webpent.dojo.skill_assessor import SkillAssessor
from webpent.dojo.sparring import SparringMatch
from webpent.dojo.tournament import BUILTIN_AGENTS, TournamentRunner
from webpent.dojo.weakness_identifier import WeaknessIdentifier

CONFIG_DIR = "config/dojo/scenarios"


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir(CONFIG_DIR)


def _practice_results(library: ScenarioLibrary, agent="adaptive"):
    runner = PracticeRunner()
    return [
        runner.run(BUILTIN_AGENTS[agent], scenario) for scenario in library.all()
    ]


def test_full_pipeline_end_to_end(library, tmp_path, monkeypatch):
    """scenario library -> practice -> sparring -> skill -> weaknesses -> plan."""
    monkeypatch.setenv("WEBPENT_DOJO_DIR", str(tmp_path))
    tracker = ProgressTracker(tmp_path)
    runner = PracticeRunner()
    scenario = library.get("sqli-01")

    result = runner.run(BUILTIN_AGENTS["adaptive"], scenario)
    tracker.record({"command": "practice", "scenario_id": result.scenario_id,
                    "success": result.success, "score": result.score})

    match = SparringMatch().run(BUILTIN_AGENTS["adaptive"], scenario, DEFENSE_PATTERNS)
    assert match.lessons

    profile = SkillAssessor().assess("sqli", [result], [scenario])
    assert profile.samples == 1 and profile.sufficient is False

    weaknesses = WeaknessIdentifier().identify([result], [scenario],
                                               sparring_results=[match])
    plan = PracticeGenerator().generate(weaknesses, library, seed=3)
    assert plan.focus

    study = CaseStudyWriter.from_match(match, scenario)
    assert study.startswith("# Dojo Case Study: sqli-01")
    assert tracker.summary()["entries"] == 1


def test_zero_sockets_full_flow(library, tmp_path, monkeypatch):
    """L-1: the entire flow runs with every socket forbidden."""
    monkeypatch.setenv("WEBPENT_DOJO_DIR", str(tmp_path))

    import socket

    def _forbidden(*args, **kwargs):
        raise AssertionError("the dojo must never open a socket")

    original = socket.socket
    socket.socket = _forbidden
    try:
        _practice_results(library)
        scenario = library.get("sqli-01")
        SparringMatch().run(BUILTIN_AGENTS["adaptive"], scenario, DEFENSE_PATTERNS)
        study = CaseStudyWriter.from_match(
            SparringMatch().run(BUILTIN_AGENTS["adaptive"], scenario, DEFENSE_PATTERNS),
            scenario,
        )
        assert study
    finally:
        socket.socket = original


def test_same_seed_byte_identical(library):
    """L-4: two full passes over the same inputs produce identical output."""
    first = _practice_results(library)
    second = _practice_results(library)
    assert [r.as_dict() for r in first] == [r.as_dict() for r in second]

    scenario = library.get("sqli-01")
    match_a = SparringMatch().run(BUILTIN_AGENTS["adaptive"], scenario, DEFENSE_PATTERNS)
    match_b = SparringMatch().run(BUILTIN_AGENTS["adaptive"], scenario, DEFENSE_PATTERNS)
    assert CaseStudyWriter.from_match(match_a, scenario) == CaseStudyWriter.from_match(
        match_b, scenario
    )


def test_dojo_never_imports_campaign_modules():
    """L-10: importing the dojo pulls in no campaign or CLI machinery."""
    code = (
        "import sys;"
        "import webpent.dojo.trainer, webpent.dojo.tournament,"
        "webpent.dojo.weakness_identifier, webpent.dojo.practice_generator,"
        "webpent.dojo.case_study, webpent.dojo.progress, webpent.dojo.skill_assessor;"
        "bad = [m for m in sys.modules if m.startswith('webpent.autonomous')"
        " or m.startswith('webpent.cli')];"
        "print('BAD:' + ','.join(bad) if bad else 'CLEAN')"
    )
    env = dict(os.environ, PYTHONPATH="src")
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=env,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert "CLEAN" in out.stdout, out.stdout


def test_audit_ledger_retention_capped(tmp_path):
    tracker = ProgressTracker(tmp_path)
    for i in range(1005):
        tracker.audit("practice", f"run-{i}")
    lines = (tmp_path / "audit_log.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1000
    assert json.loads(lines[-1])["detail"] == "run-1004"
    # the history ledger itself is append-only and uncapped
    for i in range(3):
        tracker.record({"kind": "practice", "score": float(i)})
    assert len(tracker.history()) == 3


def test_outputs_are_json_roundtrippable(library):
    """External enablement: every dojo artifact survives a JSON roundtrip."""
    results = _practice_results(library)
    weaknesses = WeaknessIdentifier().identify(results, list(library.all()))
    plan = PracticeGenerator().generate(weaknesses, library, seed=5)
    match = SparringMatch().run(
        BUILTIN_AGENTS["adaptive"], library.get("sqli-01"), DEFENSE_PATTERNS
    )
    payloads = [
        [w.as_dict() for w in weaknesses],
        plan.as_dict(),
        match.as_dict(),
        [r.as_dict() for r in results],
    ]
    for payload in payloads:
        revived = json.loads(json.dumps(payload))
        assert revived == payload


def test_lessons_always_advisory(library):
    """L-7: every lesson the dojo emits is advisory material."""
    for scenario in library.all()[:4]:
        match = SparringMatch().run(
            BUILTIN_AGENTS["adaptive"], scenario, DEFENSE_PATTERNS
        )
        assert match.lessons
        assert all(lesson.startswith("advisory:") for lesson in match.lessons)


def test_preamble_precedes_any_training_content(library, tmp_path):
    """L-8: the preamble exists and comes before any scenario content."""
    from webpent.dojo.trainer import TrainingSession

    session = TrainingSession(
        library, scenario_ids=["sqli-01"], dojo_dir=tmp_path
    )
    preamble = session.preamble()
    assert preamble.strip()
    assert "simulated" in preamble.lower()
    view = session.present()
    assert view.scenario_id == "sqli-01"


def test_dojo_writes_only_inside_dojo_dir(library, tmp_path, monkeypatch):
    """L-2: a full practice-and-record cycle creates files only in the dojo dir."""
    monkeypatch.chdir(tmp_path)
    tracker = ProgressTracker(tmp_path / "state")
    result = PracticeRunner().run(BUILTIN_AGENTS["adaptive"], library.get("sqli-01"))
    tracker.record({"command": "practice", "score": result.score})
    tracker.audit("practice")
    created = {
        str(p.relative_to(tmp_path))
        for p in tmp_path.rglob("*")
        if p.is_file() and "state" not in str(p)
    }
    assert created == set(), f"files leaked outside the dojo dir: {created}"
    assert (tmp_path / "state" / "history.jsonl").exists()
    assert (tmp_path / "state" / "audit_log.jsonl").exists()


def test_full_tournament_within_resource_bounds(library):
    """CPU/memory bounds: a full tournament stays fast and lean."""
    start = time.monotonic()
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    result = TournamentRunner().round_robin(list(library.all()))
    elapsed = time.monotonic() - start
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    assert len(result.standings) == 4
    assert elapsed < 60.0, f"tournament took {elapsed:.1f}s"
    assert after - before < 500_000, f"memory grew by {after - before} KB"
