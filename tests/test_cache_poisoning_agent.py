"""P2-302 tests — cache-poisoning detector (library stage).

No network: probes are data; the differential confirmation runs on canned
responses.
"""

from __future__ import annotations

from webpent.agents.cache_poisoning.agent import (
    analyze_cache_differential,
    build_cache_key_probes,
)


def test_probe_families_cover_header_and_param_variants() -> None:
    probes = build_cache_key_probes("/home")
    headers = [p for p in probes if p["kind"] == "header"]
    params = [p for p in probes if p["kind"] == "param_variant"]
    assert len(headers) == 5
    names = {next(iter(p["attack_request"]["headers"])) for p in headers}
    assert {"X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL"} <= names
    assert len(params) == 4
    # every probe carries its clean control for the two-request differential
    assert all(p["control_request"] for p in probes)


def test_probe_paths_append_params_with_correct_separator() -> None:
    plain, with_query = build_cache_key_probes("/home"), build_cache_key_probes("/home?x=1")
    assert plain[5]["path"].startswith("/home?")
    assert with_query[5]["path"].startswith("/home?x=1&")


def test_differential_confirmed_only_with_full_evidence() -> None:
    verdict = analyze_cache_differential(
        victim_response="<html>cached cp-canary payload</html>",
        attack_response="<html>cached cp-canary payload</html>",
        control_response="<html>cached normal content</html>",
    )
    # victim differs from control by MORE than the canary -> inconclusive, not confirmed
    assert verdict["poisoned"] is False
    assert verdict["confidence"] == "inconclusive_victim_shape_differs"

    verdict2 = analyze_cache_differential(
        victim_response="<html>cached normal cp-canary</html>",
        attack_response="<html>injected cp-canary</html>",
        control_response="<html>cached normal </html>",
    )
    assert verdict2["poisoned"] is True
    assert verdict2["confidence"] == "differential_confirmed"
    assert verdict2["advisory_only"] is True
    assert "blocked" in verdict2["promotion_guard"]


def test_differential_fail_closed_paths() -> None:
    # attack never landed
    assert analyze_cache_differential("v", "no canary", "c")["poisoned"] is False
    # control is contaminated -> differential worthless
    assert analyze_cache_differential("v", "cp-canary", "cp-canary")["poisoned"] is False
    # victim never served the canary
    assert analyze_cache_differential("v", "cp-canary", "clean")["poisoned"] is False
