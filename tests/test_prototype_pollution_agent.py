"""P2-301 tests — prototype-pollution detector (library stage).

No network: probes are data; reflection analysis runs on canned responses.
"""

from __future__ import annotations

import pytest

from webpent.agents.prototype_pollution.agent import (
    analyze_reflection_pair,
    build_pollution_payload_set,
    build_pollution_probes,
)


def test_payload_set_covers_deep_key_gadget_family() -> None:
    payloads = build_pollution_payload_set()
    assert len(payloads) == 4
    joined = repr(payloads)
    assert "__proto__" in joined
    assert "constructor" in joined
    # every payload is canary-tagged for unambiguous attribution
    assert all("ppcanary_true" in repr(p) for p in payloads)


def test_payload_set_canary_namespacing() -> None:
    payloads = build_pollution_payload_set(canary="pp_run42")
    assert all("pp_run42_true" in repr(p) for p in payloads)
    assert all("ppcanary_true" not in repr(p) for p in payloads)


def test_payload_set_rejects_empty_canary() -> None:
    with pytest.raises(ValueError):
        build_pollution_payload_set(canary="  ")


def test_probes_have_negative_controls_and_governed_shape() -> None:
    probes = build_pollution_probes("/api/settings", method="post")
    assert len(probes) == 4
    assert all(p["method"] == "POST" for p in probes)
    assert all(p["path"] == "/api/settings" for p in probes)
    for p in probes:
        assert p["negative_control"] == {"benign": "control"}
        assert p["expected_signal"] == "canary_reflected_in_response_or_state"


def test_reflection_positive_requires_canary_and_difference() -> None:
    verdict = analyze_reflection_pair(
        baseline_response='{"ok": true}',
        candidate_response='{"ok": true, "merged": "ppcanary_true", "__proto__": {...}}',
    )
    assert verdict["polluted"] is True
    assert "__proto__" in verdict["sink_hints"]
    # advisory-only + promotion guard: never auto-confirmed
    assert verdict["advisory_only"] is True
    assert "blocked" in verdict["promotion_guard"]


def test_reflection_fail_closed_paths() -> None:
    # canary absent -> no claim
    assert analyze_reflection_pair("b", "c")["polluted"] is False
    # canary in baseline control -> no claim
    assert analyze_reflection_pair("has ppcanary here", "has ppcanary here")["polluted"] is False
    # identical pair -> no claim
    assert analyze_reflection_pair("same", "same")["polluted"] is False
