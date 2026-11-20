from __future__ import annotations

import json
from pathlib import Path

from benchmarks.metrics import compute_metrics, is_confirmed_with_required_controls

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "benchmarks" / "vip_v1"


def _read(name: str) -> dict:
    return json.loads((BENCHMARK / name).read_text(encoding="utf-8"))


def test_versioned_manifest_is_fail_closed_and_reproducible():
    manifest = _read("manifest.json")
    assert manifest["schema_version"] == 1
    assert manifest["metric_contract"]["confirmed_only"] is True
    assert set(manifest["metric_contract"]["required_confirmation_fields"]) == {
        "causal_signal",
        "negative_control_complete",
        "proof_bundle_sealed",
    }
    assert manifest["safety"]["modifies_target"] is False
    assert manifest["safety"]["requires_explicit_authorization"] is True


def test_expected_catalog_contains_twenty_evidence_contracts():
    expected = _read("expected_findings.json")["entries"]
    assert len(expected) == 20
    assert len({entry["key"] for entry in expected}) == 20
    assert all(entry["evidence_required"] for entry in expected)
    assert all(entry["negative_control_required"] for entry in expected)


def test_e2e_scenarios_cover_required_research_paths():
    scenarios = _read("scenarios.json")["scenarios"]
    assert {scenario["id"] for scenario in scenarios} == {"A", "B", "C", "D", "E"}
    assert all(scenario["required_artifacts"] for scenario in scenarios)
    assert all(scenario["success"] for scenario in scenarios)


def test_confirmation_requires_causal_control_and_sealed_proof():
    accepted = {
        "key": "header_sqli",
        "status": "confirmed",
        "causal_signal": True,
        "negative_control_complete": True,
        "proof_bundle_sealed": True,
    }
    for field in ("causal_signal", "negative_control_complete", "proof_bundle_sealed"):
        rejected = {**accepted, field: False}
        assert is_confirmed_with_required_controls(rejected) is False
    assert is_confirmed_with_required_controls(accepted) is True


def test_metrics_use_set_semantics_and_confirmed_findings_only():
    expected = [{"key": "a"}, {"key": "b"}, {"key": "c"}]
    observed = [
        {
            "key": "a",
            "status": "confirmed",
            "causal_signal": True,
            "negative_control_complete": True,
            "proof_bundle_sealed": True,
        },
        {
            "key": "a",
            "status": "confirmed",
            "causal_signal": True,
            "negative_control_complete": True,
            "proof_bundle_sealed": True,
        },
        {
            "key": "b",
            "status": "candidate",
            "causal_signal": True,
            "negative_control_complete": True,
            "proof_bundle_sealed": True,
        },
        {
            "key": "x",
            "status": "confirmed",
            "causal_signal": True,
            "negative_control_complete": True,
            "proof_bundle_sealed": True,
        },
    ]
    metrics = compute_metrics(expected, observed)
    assert metrics.true_positives == 1
    assert metrics.false_positives == 1
    assert metrics.false_negatives == 2
    assert metrics.precision == 0.5
    assert metrics.recall == 1 / 3
    assert round(metrics.f1, 6) == round(0.4, 6)
