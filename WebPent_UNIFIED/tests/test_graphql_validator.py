"""Tests for the deterministic GraphQL validators (Ultimate plan
2026-10-27, proposal 7 phase 3).

Follows the ``tests/test_postp0_phase5_validators.py`` posture — every
validator consumes injected evidence dicts and returns a canonical
``ValidationResult``; no network, no LLM, no subprocess. Includes the
plan-mandated "no GraphQL at all" case (all INCONCLUSIVE — the
validators can never fire on a target without a GraphQL surface).
"""

from __future__ import annotations

from webpent.production.validators import EvidenceQuality, ValidationOutcome
from webpent.validators.graphql_validator import (
    analyze_graphql_surface,
    graphql_testing_enabled,
    validate_batching_abuse,
    validate_depth_complexity_dos,
    validate_field_suggestion_leak,
    validate_introspection_exposure,
)

# The fixture introspection payload from the plan (proposal 7 phase 3):
# a Query type with a `users(id: ID)` field and no mutations.
INTROSPECTION_PAYLOAD = {
    "data": {
        "__schema": {
            "queryType": {
                "name": "Query",
                "fields": [
                    {"name": "users", "args": [{"name": "id", "type": {"name": "ID"}}]}
                ],
            },
            "mutationType": None,
        }
    }
}


# ---------------------------------------------------------------------------
# introspection exposure
# ---------------------------------------------------------------------------


def test_introspection_confirmed_on_production_endpoint():
    result = validate_introspection_exposure(
        INTROSPECTION_PAYLOAD, "https://target.test/graphql"
    )
    assert result.outcome is ValidationOutcome.CONFIRMED
    assert result.evidence_quality is EvidenceQuality.DETERMINISTIC_TOOL
    assert result.vulnerability_class == "graphql_introspection_exposure"
    assert result.details["endpoint"] == "https://target.test/graphql"
    assert result.details["operation_count"] == 1
    assert result.details["operation_name_sample"] == ["users"]
    assert "bounded" in result.details


def test_introspection_inconclusive_on_empty_payload():
    result = validate_introspection_exposure({}, "https://target.test/graphql")
    assert result.outcome is ValidationOutcome.INCONCLUSIVE


def test_introspection_inconclusive_on_malformed_payload():
    result = validate_introspection_exposure(
        {"errors": [{"message": "introspection disabled"}]},
        "https://target.test/graphql",
    )
    assert result.outcome is ValidationOutcome.INCONCLUSIVE


def test_introspection_inconclusive_on_non_production_endpoint():
    result = validate_introspection_exposure(
        INTROSPECTION_PAYLOAD, "https://staging.target.test/graphql", is_production=False
    )
    assert result.outcome is ValidationOutcome.INCONCLUSIVE
    assert result.details["reason"] == "non-production-endpoint"


# ---------------------------------------------------------------------------
# batching abuse
# ---------------------------------------------------------------------------


def test_batching_confirmed_when_batch_ok_but_sequential_limited():
    records = [
        {"batch_size": 1, "status": 429, "elapsed_ms": 5.0, "rate_limit_headers": {}},
        {"batch_size": 10, "status": 200, "elapsed_ms": 800.0, "rate_limit_headers": {}},
    ]
    result = validate_batching_abuse(records)
    assert result.outcome is ValidationOutcome.CONFIRMED
    assert result.vulnerability_class == "graphql_batching_abuse"
    assert result.candidate_evidence["batch_size"] == 10
    assert result.refutation_path


def test_batching_sequential_limit_detected_via_headers_not_just_429():
    records = [
        {
            "batch_size": 1,
            "status": 200,
            "elapsed_ms": 5.0,
            "rate_limit_headers": {"x-ratelimit-remaining": "0"},
        },
        {"batch_size": 25, "status": 200, "elapsed_ms": 900.0, "rate_limit_headers": {}},
    ]
    assert validate_batching_abuse(records).outcome is ValidationOutcome.CONFIRMED


def test_batching_refuted_when_batch_rejected():
    records = [
        {"batch_size": 1, "status": 429, "elapsed_ms": 5.0, "rate_limit_headers": {}},
        {"batch_size": 10, "status": 400, "elapsed_ms": 12.0, "rate_limit_headers": {}},
    ]
    result = validate_batching_abuse(records)
    assert result.outcome is ValidationOutcome.REFUTED
    assert result.details["reason"] == "batch-rejected"


def test_batching_inconclusive_without_sequential_limited_evidence():
    records = [
        {"batch_size": 1, "status": 200, "elapsed_ms": 5.0, "rate_limit_headers": {}},
        {"batch_size": 10, "status": 200, "elapsed_ms": 800.0, "rate_limit_headers": {}},
    ]
    result = validate_batching_abuse(records)
    assert result.outcome is ValidationOutcome.INCONCLUSIVE
    assert result.details["reason"] == "no-sequential-limited-evidence"


def test_batching_inconclusive_when_no_batch_probes():
    records = [{"batch_size": 1, "status": 200, "elapsed_ms": 5.0, "rate_limit_headers": {}}]
    assert validate_batching_abuse(records).outcome is ValidationOutcome.INCONCLUSIVE
    assert validate_batching_abuse([]).outcome is ValidationOutcome.INCONCLUSIVE


# ---------------------------------------------------------------------------
# field suggestion leak
# ---------------------------------------------------------------------------


def test_field_suggestion_confirmed_on_did_you_mean_body():
    records = [
        {
            "status": 400,
            "body": "Cannot query field 'userEail' on type 'Query'. Did you mean: userEmail?",
        }
    ]
    result = validate_field_suggestion_leak(records)
    assert result.outcome is ValidationOutcome.CONFIRMED
    assert result.vulnerability_class == "graphql_field_suggestion_leak"
    assert "userEmail" in result.candidate_evidence["suggested_fields"]


def test_field_suggestion_confirmed_on_200_with_errors_array():
    # GraphQL convention: errors ride on a 200 response.
    records = [
        {
            "status": 200,
            "body": '{"errors": [{"message": "Did you mean \'userEmail\'?"}]}',
        }
    ]
    result = validate_field_suggestion_leak(records)
    assert result.outcome is ValidationOutcome.CONFIRMED


def test_field_suggestion_refuted_when_errors_never_suggest():
    records = [
        {"status": 400, "body": "Cannot query field 'userEail' on type 'Query'."},
        {"status": 500, "body": "Internal error"},
    ]
    result = validate_field_suggestion_leak(records)
    assert result.outcome is ValidationOutcome.REFUTED


def test_field_suggestion_inconclusive_without_error_bodies():
    records = [{"status": 200, "body": '{"data": {"users": []}}'}]
    assert validate_field_suggestion_leak(records).outcome is ValidationOutcome.INCONCLUSIVE
    assert validate_field_suggestion_leak([]).outcome is ValidationOutcome.INCONCLUSIVE


def test_field_suggestion_token_must_be_field_shaped():
    # "Did you mean 123..." has no field-name-shaped token — no leak.
    records = [{"status": 400, "body": "Did you mean 1234567890123?"}]
    assert validate_field_suggestion_leak(records).outcome is ValidationOutcome.REFUTED


# ---------------------------------------------------------------------------
# depth / complexity DoS (DoS-adjacent — hard cap discipline)
# ---------------------------------------------------------------------------


def test_depth_confirmed_only_with_authorization_warning_and_cap_notes():
    # 120 samples; degradation (200ms >= 10x the 10ms baseline) at
    # every depth >= 100 — confirmation-grade out-of-band evidence.
    probe = {
        "max_tested_depth": 120,
        "response_times_ms": [10.0] * 99 + [200.0] * 21,
        "baseline_time_ms": 10.0,
        "threshold_ratio": 10.0,
    }
    result = validate_depth_complexity_dos(probe)
    assert result.outcome is ValidationOutcome.CONFIRMED
    assert result.vulnerability_class == "graphql_depth_complexity_dos"
    assert (
        "do not reproduce without authorization — DoS-adjacent"
        in result.details["advisory"]
    )
    # The hard cap must be visible on every result.
    assert result.details["framework_probe_cap"] == 50
    assert result.details["max_tested_depth_attested"] == 50
    assert result.details["evidence_exceeds_framework_probe_cap"] is True


def test_depth_refuted_when_server_rejected_deep_query():
    probe = {
        "max_tested_depth": 50,
        "response_times_ms": [10.0, 11.0],
        "baseline_time_ms": 10.0,
        "rejected": True,
    }
    result = validate_depth_complexity_dos(probe)
    assert result.outcome is ValidationOutcome.REFUTED
    assert result.details["reason"] == "server-rejected-deep-query"


def test_depth_inconclusive_when_growth_below_confirmation_floor():
    # 50x growth but only at depth 30 — below the depth>=100 floor and
    # beyond the framework's own 50 probe cap it can never be confirmed
    # by framework-generated evidence.
    probe = {
        "max_tested_depth": 30,
        "response_times_ms": [10.0] * 29 + [500.0],
        "baseline_time_ms": 10.0,
    }
    result = validate_depth_complexity_dos(probe)
    assert result.outcome is ValidationOutcome.INCONCLUSIVE
    assert result.details["reason"] == "below-confirmation-floor"
    assert result.details["max_tested_depth_attested"] == 30


def test_depth_hard_caps_the_attested_depth_at_50():
    probe = {
        "max_tested_depth": 500,
        "response_times_ms": [10.0] * 120,
        "baseline_time_ms": 10.0,
    }
    result = validate_depth_complexity_dos(probe)
    assert result.outcome is ValidationOutcome.INCONCLUSIVE
    assert result.details["max_tested_depth_raw"] == 500
    assert result.details["max_tested_depth_attested"] == 50
    assert result.details["evidence_exceeds_framework_probe_cap"] is True


def test_depth_inconclusive_on_empty_or_unusable_probe():
    assert validate_depth_complexity_dos({}).outcome is ValidationOutcome.INCONCLUSIVE
    unusable = {"max_tested_depth": 10, "response_times_ms": [], "baseline_time_ms": 10.0}
    assert validate_depth_complexity_dos(unusable).outcome is ValidationOutcome.INCONCLUSIVE


# ---------------------------------------------------------------------------
# orchestrator
# ---------------------------------------------------------------------------


def test_no_graphql_at_all_yields_all_inconclusive():
    results = analyze_graphql_surface([], {})
    assert len(results) == 4
    for result in results:
        assert result.outcome is ValidationOutcome.INCONCLUSIVE
        assert result.details["graphql_surface_reported"] is False
        assert "bounded" in result.details


def test_orchestrator_runs_all_validators_over_full_bundle():
    evidence = {
        "endpoint_url": "https://target.test/graphql",
        "introspection_payload": INTROSPECTION_PAYLOAD,
        "batch_records": [
            {"batch_size": 1, "status": 429, "elapsed_ms": 5.0, "rate_limit_headers": {}},
            {"batch_size": 10, "status": 200, "elapsed_ms": 800.0, "rate_limit_headers": {}},
        ],
        "error_responses": [
            {"status": 400, "body": "Did you mean: userEmail?"}
        ],
        "depth_probe": {
            "max_tested_depth": 30,
            "response_times_ms": [10.0] * 29 + [500.0],
            "baseline_time_ms": 10.0,
        },
    }
    operations = [{"operation": "users", "kind": "query", "args": []}]
    results = analyze_graphql_surface(operations, evidence)
    assert len(results) == 4
    outcomes = [r.outcome for r in results]
    assert ValidationOutcome.CONFIRMED in outcomes
    assert ValidationOutcome.INCONCLUSIVE in outcomes  # the depth probe
    for result in results:
        assert result.details["graphql_surface_reported"] is True


def test_orchestrator_tolerates_malformed_bundle_shapes():
    # Non-dict evidence / non-list records must degrade to INCONCLUSIVE,
    # never crash the node.
    results = analyze_graphql_surface(None, {"batch_records": "not-a-list"})
    assert len(results) == 4
    assert all(
        r.outcome is ValidationOutcome.INCONCLUSIVE for r in results
    )


def test_graphql_testing_flag_defaults_on():
    assert graphql_testing_enabled() is True
