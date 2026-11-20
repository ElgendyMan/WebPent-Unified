"""UM-DR-38 §9.1 — report-generator failure-mode regression tests.

The generator must REFUSE (identifiable failure message, no report
written) for each of the seven mandated failure modes:
  1. missing campaign data;
  2. null mandatory metrics;
  3. inconsistent counts;
  4. mismatched lab versions;
  5. missing ProofBundle references;
  6. missing replay results;
  7. contradictory campaign outcomes.

A well-formed record validates clean.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "umdr38_reports", str(SCRIPTS / "umdr38_reports.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _valid_run(run_id: int = 1) -> dict:
    return {
        "run": run_id,
        "campaign_id": f"umdr38-campaign-{run_id}-abc",
        "source_commit": "b" * 40,
        "tree_sha": "c" * 40,
        "lab_version": "invoice-lab/1.6.0",
        "elapsed_s": 61.0,
        "findings_total": 4,
        "findings_confirmed": 1,
        "lab_request_count": 108,
        "causal_guard_invocations": 2,
        "out_of_scope_request_count": 0,
        "confirmed_detail": [{
            "id": "f-1", "vuln_class": "auth_bypass",
            "url": "http://127.0.0.1:1/api/invoices/INV-A-101",
            "evidence_bundle_id": "proof_bundle_x",
        }],
        "verifications": [{
            "finding_id": "f-1", "passed": True,
            "reason": "verified_replay", "has_bundle": True,
        }],
        "invariant_checks": {
            "at_least_one_confirmed_idor": True,
            "confirmed_idors_carry_bundles": True,
            "enforced_admin_boundary_unconfirmed": True,
            "missing_resource_unconfirmed": True,
            "public_resource_unconfirmed": True,
            "decoy_route_unconfirmed": True,
            "out_of_scope_origin_zero_requests": True,
        },
    }


def _valid_combined() -> dict:
    runs = [_valid_run(1), _valid_run(2), _valid_run(3)]
    return {
        "schema": "umdr38-production-campaigns/v1",
        "run_count": 3,
        "lab_version": "invoice-lab/1.6.0",
        "runs": runs,
        "reproducibility": {"confirmed_counts": [1, 1, 1]},
    }


def test_valid_record_validates_clean() -> None:
    gen = _load_generator()
    assert gen.validate_campaigns(_valid_combined()) == []


def test_missing_campaign_data_rejected() -> None:
    gen = _load_generator()
    assert gen.validate_campaigns({"missing": True}) != []
    assert gen.validate_campaigns({"runs": []}) != []


def test_null_mandatory_metrics_rejected() -> None:
    gen = _load_generator()
    record = _valid_combined()
    record["runs"][1]["findings_confirmed"] = None
    record["runs"][1]["source_commit"] = None
    failures = gen.validate_campaigns(record)
    assert any("mandatory metric 'findings_confirmed' is null" in f
               for f in failures)
    assert any("mandatory metric 'source_commit' is null" in f
               for f in failures)


def test_inconsistent_counts_rejected() -> None:
    gen = _load_generator()
    record = _valid_combined()
    record["runs"][0]["findings_confirmed"] = 2  # detail has 1 entry
    failures = gen.validate_campaigns(record)
    assert any("findings_confirmed 2 != confirmed_detail entries 1"
               in f for f in failures)
    record = _valid_combined()
    record["run_count"] = 2  # 3 actual runs
    assert any("run_count 2 != actual runs 3" in f
               for f in gen.validate_campaigns(record))
    record = _valid_combined()
    record["reproducibility"]["confirmed_counts"] = [1, 1, 9]
    assert any("confirmed_counts disagrees" in f
               for f in gen.validate_campaigns(record))


def test_mismatched_lab_versions_rejected() -> None:
    gen = _load_generator()
    record = _valid_combined()
    record["runs"][0]["lab_version"] = "invoice-lab/1.5.0"
    failures = gen.validate_campaigns(record)
    assert any("lab_version 'invoice-lab/1.5.0' != authoritative"
               in f for f in failures)
    record = _valid_combined()
    record["lab_version"] = "invoice-lab/9.9.9"
    assert any("!= combined record" in f
               for f in gen.validate_campaigns(record))


def test_missing_proofbundle_references_rejected() -> None:
    gen = _load_generator()
    record = _valid_combined()
    record["runs"][2]["confirmed_detail"][0]["evidence_bundle_id"] = ""
    failures = gen.validate_campaigns(record)
    assert any("carries no ProofBundle reference" in f
               for f in failures)


def test_missing_replay_results_rejected() -> None:
    gen = _load_generator()
    record = _valid_combined()
    record["runs"][0]["verifications"] = [{
        "finding_id": "f-1", "passed": False, "reason": "replay_failed"}]
    failures = gen.validate_campaigns(record)
    assert any("no passing replay verification" in f
               for f in failures)


def test_contradictory_campaign_outcomes_rejected() -> None:
    gen = _load_generator()
    record = _valid_combined()
    record["runs"][1]["invariant_checks"][
        "out_of_scope_origin_zero_requests"] = False
    record["runs"][1]["out_of_scope_request_count"] = 3
    failures = gen.validate_campaigns(record)
    assert any("required invariant 'out_of_scope_origin_zero_requests'"
               in f for f in failures)
    assert any("out-of-scope origin received 3 requests" in f
               for f in failures)
    record = _valid_combined()
    record["runs"][0]["invariant_checks"][
        "at_least_one_confirmed_idor"] = False
    assert any("required invariant 'at_least_one_confirmed_idor'"
               in f for f in gen.validate_campaigns(record))
