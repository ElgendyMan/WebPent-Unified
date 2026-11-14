"""v82 Tasks 9-12: swarm coordinator, temporal, rate-limit map, session topology."""

from __future__ import annotations

from webpent.autonomous.amplifiers.operational import (
    rate_limit_map,
    session_topology,
    temporal_profile,
)
from webpent.autonomous.amplifiers.swarm import ROLE_ORDER, run_swarm, run_swarm_round

# -- swarm -----------------------------------------------------------------


def test_round_runs_all_roles_in_fixed_order() -> None:
    state = {
        "known_endpoints": ["http://lab.example/a", "http://lab.example/b"],
        "explored_endpoints": ["http://lab.example/a"],
        "proven_classes": ["sqli"],
        "verify_candidates": ["http://lab.example/b"],
        "amplifier_reports": {
            "wayback": {"candidates": [{"path": "/old", "source": "wayback"}]}
        },
    }
    report = run_swarm_round(state)
    outputs = report["round"]["outputs"]
    assert list(outputs) == list(ROLE_ORDER)
    assert outputs["scout"]["inbox"][0]["path"] == "/old"
    assert outputs["striker"]["candidates"] == ["http://lab.example/b"]
    assert outputs["philosopher"]["chains"], "sqli x untested endpoint = chain lead"
    assert outputs["skeptic"]["to_validate"] == ["http://lab.example/b"]
    assert outputs["scribe"]["summary"]["chains"] >= 1
    assert report["advisory"] is True


def test_failing_role_is_recorded_not_fatal() -> None:
    import webpent.autonomous.amplifiers.swarm as swarm

    original = swarm.role_scout

    def broken(state):
        raise RuntimeError("scout down")

    swarm.role_scout = broken
    try:
        report = run_swarm_round({"known_endpoints": ["http://x.example/"]})
        assert "scout" in report["round"]["errors"]
        assert report["round"]["outputs"]["striker"]["candidates"] == ["http://x.example/"]
    finally:
        swarm.role_scout = original


def test_swarm_rounds_are_bounded_and_deterministic() -> None:
    state = {"known_endpoints": ["http://lab.example/a"]}
    r1 = run_swarm(state, rounds=99)
    r2 = run_swarm(state, rounds=2)
    assert len(r1["rounds"]) == 4  # MAX_ROUNDS bound
    assert len(r2["rounds"]) == 2
    assert r1["rounds"][0] == r2["rounds"][0]


# -- temporal ---------------------------------------------------------------


def test_periodic_window_detected() -> None:
    obs = [{"ts": "03:00", "size": 100, "status": 200}] * 3 + [{"ts": "04:10", "size": 100}]
    report = temporal_profile(obs)
    assert any(s["kind"] == "periodic_window" for s in report["signals"])
    assert report["hour_histogram"]["3"] == 3


def test_size_shift_detected_as_deploy_window() -> None:
    obs = [
        {"ts": 1, "size": 100},
        {"ts": 2, "size": 100},
        {"ts": 3, "size": 300},
        {"ts": 4, "size": 300},
    ]
    report = temporal_profile(obs)
    assert any(s["kind"] == "response_size_shift" for s in report["signals"])


def test_empty_or_garbage_observations_are_honest() -> None:
    assert temporal_profile([])["signals"] == []
    assert temporal_profile("nope")["advisory"] is True
    report = temporal_profile([{"ts": "not-a-time", "size": "x"}])
    assert report["signals"] == []


# -- rate limit map ---------------------------------------------------------


def test_map_and_unbounded_suspect() -> None:
    obs = (
        [{"url": "http://lab.example/login", "status": 401}] * 4
        + [{"url": "http://lab.example/search", "status": 429}] * 2
        + [
            {
                "url": "http://lab.example/search",
                "status": 200,
                "limit_headers": {"X-RateLimit-Remaining": "0"},
            }
        ]
    )
    report = rate_limit_map(obs)
    assert report["map"]["http://lab.example/search"]["limited"] == 2
    assert "http://lab.example/search" not in report["unbounded_suspects"]
    assert report["unbounded_suspects"] == ["http://lab.example/login"]
    assert report["advisory"] is True


def test_few_requests_are_not_suspects() -> None:
    report = rate_limit_map([{"url": "http://lab.example/x", "status": 200}])
    assert report["unbounded_suspects"] == []


# -- session topology --------------------------------------------------------


def test_fixation_suspect_detected() -> None:
    events = [
        {"phase": "pre_login", "cookies": {"sessionid": "abc123"}},
        {"phase": "post_login", "cookies": {"sessionid": "abc123"}},
    ]
    report = session_topology(events)
    kinds = [i["kind"] for i in report["indicators"]]
    assert "session_fixation_suspect" in kinds


def test_rotated_session_is_clean() -> None:
    events = [
        {"phase": "pre_login", "cookies": {"sessionid": "abc123"}},
        {"phase": "post_login", "cookies": {"sessionid": "xyz789"}},
    ]
    assert session_topology(events)["indicators"] == []


def test_incomplete_logout_and_riding() -> None:
    events = [
        {"phase": "post_login", "cookies": {"sessionid": "abc"}},
        {"phase": "post_logout", "cookies": {"sessionid": "abc"}},
        {"phase": "switch_user", "cookies": {"sessionid": "abc"}},
    ]
    kinds = [i["kind"] for i in session_topology(events)["indicators"]]
    assert "incomplete_logout_suspect" in kinds
    assert "session_riding_suspect" in kinds


def test_garbage_events_degrade() -> None:
    assert session_topology("x")["indicators"] == []
    assert session_topology([{"phase": "weird", "cookies": {}}])["indicators"] == []
