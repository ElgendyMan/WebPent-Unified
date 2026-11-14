"""Tests for the deterministic OAuth misconfiguration validators
(Ultimate plan 2026-10-27, proposal 7 phase 5 — basic version).

Every validator consumes injected authorization-flow records and
returns a canonical ``ValidationResult``; no network. Includes the
query-value redaction contract for evidence samples.
"""

from __future__ import annotations

from webpent.production.validators import EvidenceQuality, ValidationOutcome
from webpent.validators.oauth_misconfig_validator import (
    _redact_url,
    analyze_oauth_flow,
    oauth_misconfig_detection_enabled,
    validate_redirect_uriManipulation,
    validate_state_parameter,
)

AUTHORIZATION_URL = "https://auth.target.test/authorize?client_id=webpent-client"


def _redirect_record(redirect_uri: str, status: int) -> dict:
    return {
        "authorization_url": AUTHORIZATION_URL,
        "redirect_uri": redirect_uri,
        "status": status,
    }


# ---------------------------------------------------------------------------
# validate_redirect_uriManipulation
# ---------------------------------------------------------------------------


def test_redirect_confirmed_when_foreign_host_uri_accepted():
    result = validate_redirect_uriManipulation(
        [_redirect_record("https://evil.test/callback", 302)]
    )
    assert result.outcome is ValidationOutcome.CONFIRMED
    assert result.evidence_quality is EvidenceQuality.DETERMINISTIC_TOOL
    assert result.vulnerability_class == "oauth_misconfiguration"
    assert result.candidate_evidence["status"] == 302
    assert result.refutation_path


def test_redirect_confirmed_on_protocol_relative_uri():
    result = validate_redirect_uriManipulation(
        [_redirect_record("//evil.test/callback", 200)]
    )
    assert result.outcome is ValidationOutcome.CONFIRMED


def test_redirect_confirmed_on_javascript_scheme_uri():
    result = validate_redirect_uriManipulation(
        [_redirect_record("javascript:alert(document.domain)", 200)]
    )
    assert result.outcome is ValidationOutcome.CONFIRMED


def test_redirect_refuted_when_evil_uri_rejected():
    result = validate_redirect_uriManipulation(
        [_redirect_record("https://evil.test/callback", 400)]
    )
    assert result.outcome is ValidationOutcome.REFUTED
    assert result.details["reason"] == "redirect-uri-rejected"


def test_redirect_inconclusive_when_only_legitimate_uris_probed():
    result = validate_redirect_uriManipulation(
        [_redirect_record("https://auth.target.test/callback", 302)]
    )
    assert result.outcome is ValidationOutcome.INCONCLUSIVE
    assert result.details["reason"] == "no-suspicious-uri"
    assert validate_redirect_uriManipulation([]).outcome is ValidationOutcome.INCONCLUSIVE


def test_redirect_same_host_subdomain_still_foreign_host():
    # A different host than the authorization server's own host — even
    # a sibling subdomain — is open-redirect-shaped per the spec.
    result = validate_redirect_uriManipulation(
        [_redirect_record("https://auth2.target.test/callback", 302)]
    )
    assert result.outcome is ValidationOutcome.CONFIRMED


# ---------------------------------------------------------------------------
# redaction contract
# ---------------------------------------------------------------------------


def test_redaction_replaces_long_query_values():
    redacted = _redact_url(
        "https://auth.target.test/authorize?client_id=abcdefghij&state=xyz123&debug=1"
    )
    assert "client_id=***" in redacted
    assert "state=***" in redacted
    assert "debug=1" in redacted  # short values (<= 4 chars) survive
    assert "abcdefghij" not in redacted
    assert "xyz123" not in redacted


def test_redirect_evidence_samples_are_redacted():
    result = validate_redirect_uriManipulation(
        [
            {
                "authorization_url": (
                    "https://auth.target.test/authorize?client_id=supersecretclient"
                ),
                "redirect_uri": "https://evil.test/cb?code=leakycode",
                "status": 302,
            }
        ]
    )
    sample = result.candidate_evidence["authorization_url"]
    assert "supersecretclient" not in sample
    assert "client_id=***" in sample
    uri_sample = result.candidate_evidence["redirect_uri"]
    assert "leakycode" not in uri_sample


# ---------------------------------------------------------------------------
# validate_state_parameter
# ---------------------------------------------------------------------------


def test_state_confirmed_when_missing_and_callback_unvalidated():
    result = validate_state_parameter(
        [{"has_state": False, "state_reflected_in_callback": False}]
    )
    assert result.outcome is ValidationOutcome.CONFIRMED
    assert result.vulnerability_class == "oauth_misconfiguration"
    assert result.candidate_evidence == {
        "has_state": False,
        "state_reflected_in_callback": False,
    }


def test_state_refuted_when_present_and_validated():
    result = validate_state_parameter(
        [{"has_state": True, "state_reflected_in_callback": True}]
    )
    assert result.outcome is ValidationOutcome.REFUTED
    assert result.details["reason"] == "state-present-and-validated"


def test_state_inconclusive_on_partial_posture():
    # State present but never validated in the callback — needs replay
    # evidence the injected records do not carry.
    result = validate_state_parameter(
        [{"has_state": True, "state_reflected_in_callback": False}]
    )
    assert result.outcome is ValidationOutcome.INCONCLUSIVE
    assert result.details["reason"] == "partial-posture"


def test_state_inconclusive_without_records():
    assert validate_state_parameter([]).outcome is ValidationOutcome.INCONCLUSIVE


# ---------------------------------------------------------------------------
# orchestrator
# ---------------------------------------------------------------------------


def test_analyze_oauth_flow_runs_both_validators():
    results = analyze_oauth_flow(
        {
            "redirect_records": [_redirect_record("https://evil.test/cb", 302)],
            "state_records": [{"has_state": False, "state_reflected_in_callback": False}],
        }
    )
    assert len(results) == 2
    assert all(
        r.outcome is ValidationOutcome.CONFIRMED and r.vulnerability_class == "oauth_misconfiguration"
        for r in results
    )


def test_analyze_oauth_flow_empty_bundle_is_all_inconclusive():
    results = analyze_oauth_flow({})
    assert len(results) == 2
    assert all(r.outcome is ValidationOutcome.INCONCLUSIVE for r in results)
    assert all("bounded" in r.details for r in results)


def test_detection_flag_defaults_on():
    assert oauth_misconfig_detection_enabled() is True
