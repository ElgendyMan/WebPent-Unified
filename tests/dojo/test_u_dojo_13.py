"""U-DOJO-1 engine edge cases: the deterministic matcher under the Dojo."""

from __future__ import annotations

import pytest

from webpent.dojo.engine import (
    DojoRequest,
    DojoResponse,
    LabInstance,
    RouteSpec,
    SimulatedTarget,
    VulnPoint,
    stable_hash,
)
from webpent.dojo.lab_generator import LabGenerator


@pytest.fixture()
def lab() -> LabInstance:
    return LabGenerator().start("flask_sqli_login", seed=7)


@pytest.fixture()
def target() -> SimulatedTarget:
    return SimulatedTarget()


def test_stable_hash_is_deterministic_and_discriminating():
    first = stable_hash("a", 1, {"k": "v"})
    second = stable_hash("a", 1, {"k": "v"})
    other = stable_hash("a", 2, {"k": "v"})
    assert first == second
    assert first != other
    assert len(first) == 64


def test_request_response_roundtrip():
    request = DojoRequest("POST", "/login", {"username": "x"}, {"session": "t"}, "b")
    payload = request.as_dict()
    assert payload["method"] == "POST"
    assert payload["params"] == {"username": "x"}
    revived = DojoRequest(**payload)
    assert revived == request
    response = DojoResponse(200, "body", ("ok", "vuln_hit"))
    assert response.has("vuln_hit") and not response.has("decoy_hit")
    assert response.as_dict()["flags"] == ["ok", "vuln_hit"]


def test_unknown_route_is_not_found(target, lab):
    response = target.respond(lab, DojoRequest("GET", "/nope"))
    assert response.status == 404
    assert response.has("not_found")


def test_auth_blocked_without_valid_token(target, lab):
    response = target.respond(lab, DojoRequest("GET", "/dashboard"))
    assert response.status == 401
    assert response.has("auth_blocked")


def test_valid_token_passes_auth(target, lab):
    token = sorted(lab.valid_tokens)[0]
    response = target.respond(
        lab, DojoRequest("GET", "/dashboard", headers={"session": token})
    )
    assert response.status == 200
    assert response.has("ok")


def test_budget_exhaustion_rate_limits(target, lab):
    # probe with the route's real method; RT-01 made the engine honor it
    lab.request_budget = 2
    assert target.respond(lab, DojoRequest("POST", "/login")).status == 200
    assert target.respond(lab, DojoRequest("POST", "/login")).status == 200
    limited = target.respond(lab, DojoRequest("POST", "/login"))
    assert limited.status == 429
    assert limited.has("rate_limited")
    # a rate-limited turn must not consume anything further
    assert lab.request_budget == 0


def test_burn_consumes_budget_and_floors_at_zero(target, lab):
    lab.request_budget = 5
    assert target.burn(lab, 3) == 2
    assert target.burn(lab, 99) == 0


def test_exploitable_point_hits_with_class_flag(target, lab):
    response = target.respond(
        lab, DojoRequest("POST", "/login", {"username": "' OR 1=1"})
    )
    assert response.has("vuln_hit")
    assert "sqli" in response.flags


def test_decoy_point_is_neutralized(target, lab):
    response = target.respond(
        lab, DojoRequest("POST", "/login", {"username": "union select"})
    )
    assert response.has("decoy_hit")
    assert not response.has("vuln_hit")


def test_filter_token_blocks_payload(target, lab):
    lab.request_budget = 10
    lab.vuln_points = (
        VulnPoint("sqli", "/login", "username", "' OR 1=1", "none", True,
                  filter_token="' OR 1=1"),
    )
    response = target.respond(
        lab, DojoRequest("POST", "/login", {"username": "' OR 1=1"})
    )
    assert response.has("filtered")
    assert not response.has("vuln_hit")


def test_normalize_mode_requires_case_sensitive_substring(target, lab):
    from webpent.dojo.engine import VulnPoint

    lab.vuln_points = (
        VulnPoint("xss", "/login", "username", "alert(1)", "none", True, ""),
    )
    payload = "ALERT(1)"
    lab.normalize_input = False
    default = target.respond(lab, DojoRequest("POST", "/login", {"username": payload}))
    assert default.has("vuln_hit"), "default matching is case-insensitive"

    lab.normalize_input = True
    strict = target.respond(lab, DojoRequest("POST", "/login", {"username": payload}))
    assert strict.has("ok"), "normalize mode is case-sensitive"


def test_strict_types_requires_exact_equality(target, lab):
    lab.strict_types = True
    padded = target.respond(
        lab, DojoRequest("POST", "/login", {"username": "x' OR 1=1"})
    )
    assert padded.has("ok"), "strict mode rejects partial matches"
    exact = target.respond(
        lab, DojoRequest("POST", "/login", {"username": "' OR 1=1"})
    )
    assert exact.has("vuln_hit")


def test_public_view_never_leaks_ground_truth(lab):
    view = lab.public_view()
    dumped = repr(view)
    assert "' OR 1=1" not in dumped
    assert "union select" not in dumped
    assert not any("signature" in route for route in view["routes"])
    assert view["request_budget"] == lab.request_budget


def test_state_hash_tracks_configuration(lab):
    before = lab.state_hash
    lab.normalize_input = True
    assert lab.state_hash != before
    lab.normalize_input = False
    assert lab.state_hash == before


def test_route_spec_defaults():
    spec = RouteSpec("/x")
    assert spec.method == "GET" and spec.requires_auth == "none"
