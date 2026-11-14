"""U-DOJO red-team hardening (plan: docs/plans/2026-10-16-v86-red-team.md).

Each test here was written to FAIL against v86 before its fix: the burn
clamp (RT-07), vuln-point auth (RT-08), HTTP-method routing (RT-01),
defense budget patterns (RT-02), FIFO retention (RT-03), hint-state
persistence (RT-04), pure-failure skill gaps (RT-05), full-ledger
rehydration (RT-06), and the bounded, robust progress ledger (RT-09/10).
"""

from __future__ import annotations

import json
from dataclasses import replace

from typer.testing import CliRunner

from webpent.cli.dojo import dojo_app
from webpent.dojo.defender import get_pattern
from webpent.dojo.engine import DojoRequest, SimulatedTarget
from webpent.dojo.lab_generator import LabGenerator
from webpent.dojo.practice_runner import PracticeResult, PracticeRunner
from webpent.dojo.progress import ProgressTracker
from webpent.dojo.scenario_library import ScenarioLibrary
from webpent.dojo.sparring import SparringMatch
from webpent.dojo.tournament import NaiveAgent
from webpent.dojo.trainer import TrainingSession
from webpent.dojo.weakness_identifier import WeaknessIdentifier

CONFIG_DIR = "config/dojo/scenarios"
TARGET = SimulatedTarget()
GENERATOR = LabGenerator()
LIBRARY = ScenarioLibrary.load_dir(CONFIG_DIR)


# -- RT-07: burn() clamps negative counts -------------------------------------


def test_burn_negative_count_leaves_budget_unchanged():
    lab = GENERATOR.start("flask_sqli_login", seed=11)
    before = lab.request_budget
    TARGET.burn(lab, -5)
    assert lab.request_budget == before


def test_burn_negative_count_cannot_grow_past_zero_floor():
    lab = GENERATOR.start("flask_sqli_login", seed=12)
    lab.request_budget = 0
    TARGET.burn(lab, -3)
    assert lab.request_budget == 0


# -- RT-08: VulnPoint.requires_auth is honored --------------------------------


def _open_auth_point_lab():
    """The ssrf lab with its route-level auth removed, so the POINT-level
    requires_auth ("user") is the only gate left on /fetch."""
    lab = GENERATOR.start("django_ssrf_endpoint", seed=3)
    routes = tuple(
        replace(r, requires_auth="none") if r.path == "/fetch" else r
        for r in lab.routes
    )
    return replace(lab, routes=routes)


def test_point_auth_blocks_unauthenticated_hit():
    lab = _open_auth_point_lab()
    response = TARGET.respond(
        lab, DojoRequest("GET", "/fetch", {"url": "169.254.169.254"})
    )
    assert response.status == 200
    assert not response.has("vuln_hit")


def test_point_auth_allows_authenticated_hit():
    lab = _open_auth_point_lab()
    token = sorted(lab.valid_tokens)[0]
    response = TARGET.respond(
        lab,
        DojoRequest(
            "GET", "/fetch", {"url": "169.254.169.254"}, {"session": token}
        ),
    )
    assert response.has("vuln_hit")


# -- RT-01: the engine honors the HTTP method ----------------------------------


def test_get_on_post_only_route_is_rejected():
    lab = GENERATOR.start("flask_sqli_login", seed=5)
    login = next(r for r in lab.routes if r.path == "/login")
    assert login.method == "POST"
    response = TARGET.respond(
        lab, DojoRequest("GET", "/login", {"username": "' OR 1=1"})
    )
    assert response.status == 405
    assert response.has("method_not_allowed")


def test_post_on_post_route_hits_ground_truth():
    lab = GENERATOR.start("flask_sqli_login", seed=5)
    response = TARGET.respond(
        lab, DojoRequest("POST", "/login", {"username": "' OR 1=1"})
    )
    assert response.has("vuln_hit")
    assert "sqli" in response.flags


def test_method_match_is_case_insensitive():
    lab = GENERATOR.start("flask_sqli_login", seed=5)
    response = TARGET.respond(
        lab, DojoRequest("post", "/login", {"username": "' OR 1=1"})
    )
    assert response.has("vuln_hit")


def test_unknown_path_still_404():
    lab = GENERATOR.start("flask_sqli_login", seed=5)
    response = TARGET.respond(lab, DojoRequest("DELETE", "/nope"))
    assert response.status == 404
    assert response.has("not_found")


def test_builtin_agents_plan_with_the_route_method():
    from webpent.dojo.tournament import BUILTIN_AGENTS

    lab = GENERATOR.start("flask_sqli_login", seed=5)
    scenario = LIBRARY.get("sqli-01")
    for agent in BUILTIN_AGENTS.values():
        for request in agent.plan(lab.public_view(), scenario):
            route = next(
                (r for r in lab.routes if r.path == request.path), None
            )
            if route is not None:
                assert request.method.upper() == route.method.upper(), (
                    f"{type(agent).__name__} sent {request.method} "
                    f"to a {route.method} route"
                )


# -- RT-02: defense budget patterns take effect --------------------------------


def test_runner_respects_a_provided_lab_budget():
    scenario = LIBRARY.get("sqli-01")
    lab = GENERATOR.start(scenario.template_id, seed=scenario.seed)
    lab.request_budget = 1
    result = PracticeRunner().run(NaiveAgent(), scenario, lab)
    assert result.requests_used <= 1


def test_sparring_passes_shrunk_budget_to_runner(monkeypatch):
    captured: dict = {}
    original = PracticeRunner.run

    def spy(self, agent, scenario, lab=None):
        captured["budget"] = None if lab is None else lab.request_budget
        return original(self, agent, scenario, lab)

    monkeypatch.setattr(PracticeRunner, "run", spy)
    scenario = LIBRARY.get("sqli-01")
    SparringMatch().run(
        NaiveAgent(), scenario, [get_pattern("shrink_request_budget")],
        rounds=1,
    )
    # scenario budget 16 shrunk to a quarter by the pattern: the runner
    # must receive 4, not the unstomped 16 nor a fresh 24
    assert captured["budget"] == 4


# -- RT-03: retention is FIFO ---------------------------------------------------


def test_retention_retires_in_start_order_not_lexicographic():
    generator = LabGenerator()
    started = [
        generator.start("flask_sqli_login", seed=s).instance_id
        for s in (5, 3, 1, 0, 2, 4)
    ]
    # six starts on one template: exactly one must be retired, and it is
    # the FIRST one started (seed 5), never the lexicographically smallest
    try:
        generator.get(started[0])
        first_still_alive = True
    except KeyError:
        first_still_alive = False
    assert first_still_alive is False


# -- RT-04: trainer hint state survives a reload --------------------------------


def test_trainer_hint_state_survives_reload(tmp_path):
    scenario_ids = [
        s.scenario_id for s in sorted(LIBRARY.all(), key=lambda s: s.scenario_id)
        if s.family == "sqli"
    ][:2]
    session = TrainingSession(
        LIBRARY, scenario_ids=scenario_ids, dojo_dir=tmp_path
    )
    first_hint = session.request_hint()
    state = session.save()
    reloaded = TrainingSession.load(state, LIBRARY)
    assert reloaded.hints_used == 1
    second_hint = reloaded.request_hint()
    hints = LIBRARY.get(scenario_ids[0]).hints
    assert first_hint == hints[0]
    assert second_hint == hints[1]


# -- RT-05: pure honest failure is a skill gap ----------------------------------


def test_zero_success_zero_fp_family_still_flags_skill_gap():
    scenario = LIBRARY.get("sqli-01")
    results = [
        PracticeResult(
            scenario_id=scenario.scenario_id, success=False, score=20.0,
            requests_used=5, false_positives=0, time_steps=2, budget=10,
        )
        for _ in range(6)
    ]
    weaknesses = WeaknessIdentifier().identify(results, [scenario])
    assert "skill_gap" in {w.kind for w in weaknesses}


# -- RT-06: the ledger carries the full measured result -------------------------


def test_cli_ledger_records_full_result_payload(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        dojo_app, ["practice", "sqli-01", "--agent", "naive",
                   "--dojo-dir", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    lines = (tmp_path / "history.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    entry = json.loads(lines[-1])
    assert entry["command"] == "practice"
    assert "false_positives" in entry
    assert "requests_used" in entry
    assert "time_steps" in entry
    assert "budget" in entry


def test_cli_skill_reflects_ledger_false_positives(tmp_path):
    runner = CliRunner()
    for _ in range(3):
        invoked = runner.invoke(
            dojo_app, ["practice", "sqli-01", "--agent", "naive",
                       "--dojo-dir", str(tmp_path)]
        )
        assert invoked.exit_code == 0, invoked.output
    skill_result = runner.invoke(
        dojo_app, ["skill", "--family", "sqli", "--dojo-dir", str(tmp_path)]
    )
    assert skill_result.exit_code == 0, skill_result.output
    body = skill_result.output
    assert '"samples"' in body


# -- RT-09/10: bounded, robust ledger -------------------------------------------


def test_history_is_capped(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBPENT_DOJO_DIR", str(tmp_path))
    from webpent.dojo.progress import MAX_HISTORY_LINES

    assert MAX_HISTORY_LINES == 5000
    tracker = ProgressTracker()
    for i in range(MAX_HISTORY_LINES + 25):
        tracker.record({"kind": "practice", "score": 50.0, "n": i})
    lines = (tmp_path / "history.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    assert len(lines) == MAX_HISTORY_LINES
    assert json.loads(lines[-1])["n"] == MAX_HISTORY_LINES + 24


def test_trend_survives_non_numeric_scores(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBPENT_DOJO_DIR", str(tmp_path))
    tracker = ProgressTracker()
    tracker.record({"kind": "practice", "score": "n/a"})
    tracker.record({"kind": "practice", "score": 60.0})
    tracker.record({"kind": "practice", "score": 80.0})
    assert tracker.trend() == "improving"


def test_summary_survives_non_numeric_scores(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBPENT_DOJO_DIR", str(tmp_path))
    tracker = ProgressTracker()
    tracker.record({"kind": "practice", "score": None})
    tracker.record({"kind": "practice", "score": 70.0})
    summary = tracker.summary()
    assert summary["entries"] == 2
