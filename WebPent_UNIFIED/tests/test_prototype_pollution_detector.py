"""Tests for the deterministic prototype-pollution detector (Ultimate
plan 2026-10-27, proposal 7 phase 4).

Two layers, both pure over injected evidence:
  1. ``analyze_client_merge_gadgets`` — static gadget-pattern hints in
     captured JS samples (advisory observations only).
  2. ``validate_server_side_pollution`` — the canonical ValidationResult
     over captured JSON request/response pairs.
"""

from __future__ import annotations

from webpent.production.validators import EvidenceQuality, ValidationOutcome
from webpent.shared.prototype_pollution_detector import (
    analyze_client_merge_gadgets,
    prototype_pollution_detection_enabled,
    validate_server_side_pollution,
)


# ---------------------------------------------------------------------------
# analyze_client_merge_gadgets
# ---------------------------------------------------------------------------


def test_gadget_hints_detect_all_documented_patterns():
    source = "\n".join(
        [
            "const a = JSON.parse(input);",           # line 1 (no match)
            "if ('__proto__' in a) {}",               # line 2
            "obj.constructor.prototype.x = 1;",        # line 3
            "_.merge(target, a);",                     # line 4
            "_.set(cfg, path, value);",                # line 5
            "Object.assign(state.user, patch);",       # line 6 (nested target)
        ]
    )
    observations = analyze_client_merge_gadgets(
        [{"url": "https://target.test/static/app.js", "source": source}]
    )
    patterns = {obs["pattern"] for obs in observations}
    assert patterns == {
        "__proto__",
        "constructor.prototype",
        "lodash_merge",
        "lodash_set",
        "object.assign_nested_target",
    }
    for obs in observations:
        assert obs["severity"] == "low"
        assert obs["class"] == "prototype_pollution_gadget_hint"
        assert obs["advisory_only"] is True
        assert obs["url"] == "https://target.test/static/app.js"
        assert obs["line_hint"].startswith("line ")


def test_gadget_hint_line_numbers_are_correct():
    source = "var x = 1;\nvar y = 2;\n_.merge(config, user);"
    observations = analyze_client_merge_gadgets(
        [{"url": "https://target.test/a.js", "source": source}]
    )
    assert len(observations) == 1
    assert observations[0]["line_hint"] == "line 3"


def test_gadget_hints_benign_js_yields_nothing():
    source = "function add(a, b) { return a + b; }\nObject.assign(flat, other);"
    observations = analyze_client_merge_gadgets(
        [{"url": "https://target.test/clean.js", "source": source}]
    )
    assert observations == []
    assert analyze_client_merge_gadgets([]) == []


def test_gadget_hints_bracketed_prototype_traversal_detected():
    source = "pollute(obj['constructor']['prototype']);"
    observations = analyze_client_merge_gadgets(
        [{"url": "https://target.test/x.js", "source": source}]
    )
    assert any(obs["pattern"] == "constructor.prototype" for obs in observations)


def test_gadget_hints_observations_are_bounded():
    # 100 __proto__ mentions in one sample: capped at 20 per sample.
    source = "\n".join("__proto__" for _ in range(100))
    observations = analyze_client_merge_gadgets(
        [{"url": "https://target.test/big.js", "source": source}]
    )
    assert len(observations) == 20


def test_gadget_hints_skip_malformed_samples():
    # Non-string/missing source must be skipped, never crash.
    observations = analyze_client_merge_gadgets(
        [
            {"url": "https://target.test/none.js"},
            {"url": "https://target.test/int.js", "source": 42},
            "not-a-dict",
        ]
    )
    assert observations == []


# ---------------------------------------------------------------------------
# validate_server_side_pollution
# ---------------------------------------------------------------------------


def test_server_side_confirmed_when_accepted_probe_reflected_at_top_level():
    records = [
        {
            "request_json": {"__proto__": {"polluted": "marker"}},
            "status": 200,
            "response_json": {"ok": True, "polluted": "marker"},
        }
    ]
    result = validate_server_side_pollution(records)
    assert result.outcome is ValidationOutcome.CONFIRMED
    assert result.evidence_quality is EvidenceQuality.DETERMINISTIC_TOOL
    assert result.vulnerability_class == "prototype_pollution"
    assert result.candidate_evidence["reflected_keys"] == ["polluted"]
    assert result.refutation_path


def test_server_side_confirmed_via_constructor_prototype_variant():
    records = [
        {
            "request_json": {"constructor": {"prototype": {"isAdmin": True}}},
            "status": 200,
            "response_json": {"isAdmin": True},
        }
    ]
    result = validate_server_side_pollution(records)
    assert result.outcome is ValidationOutcome.CONFIRMED
    assert result.candidate_evidence["reflected_keys"] == ["isAdmin"]


def test_server_side_refuted_when_server_rejects_the_probe():
    records = [
        {
            "request_json": {"__proto__": {"polluted": "marker"}},
            "status": 400,
            "response_json": {"error": "invalid body"},
        }
    ]
    result = validate_server_side_pollution(records)
    assert result.outcome is ValidationOutcome.REFUTED
    assert result.details["reason"] == "rejected-or-sanitized"


def test_server_side_refuted_when_server_sanitizes_the_probe():
    records = [
        {
            "request_json": {"__proto__": {"polluted": "marker"}},
            "status": 200,
            "response_json": {"ok": True},  # accepted, marker dropped
        }
    ]
    result = validate_server_side_pollution(records)
    assert result.outcome is ValidationOutcome.REFUTED


def test_server_side_inconclusive_without_pollution_evidence():
    # Plain JSON traffic (no __proto__/constructor probes) and empty
    # input both stay INCONCLUSIVE — no JSON endpoints in evidence.
    records = [
        {"request_json": {"name": "value"}, "status": 200, "response_json": {"ok": True}}
    ]
    assert validate_server_side_pollution(records).outcome is ValidationOutcome.INCONCLUSIVE
    assert validate_server_side_pollution([]).outcome is ValidationOutcome.INCONCLUSIVE
    result = validate_server_side_pollution(records)
    assert result.details["reason"] == "no-json-endpoint-evidence"


def test_server_side_inconclusive_when_accepted_without_response_body():
    records = [
        {
            "request_json": {"__proto__": {"polluted": "marker"}},
            "status": 200,
            "response_json": None,  # accepted, but nothing to inspect
        }
    ]
    result = validate_server_side_pollution(records)
    assert result.outcome is ValidationOutcome.INCONCLUSIVE
    assert result.details["reason"] == "ambiguous-outcomes"


def test_detection_flag_defaults_on():
    assert prototype_pollution_detection_enabled() is True
