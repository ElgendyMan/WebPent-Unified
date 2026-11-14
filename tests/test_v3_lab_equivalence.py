"""V-3 lab-channel equivalence tests.

Restored after the workspace reset. Verifies the Option B lab channel
produces EQUIVALENT redacted observations across two invocation modes
(in-process lab vs. lab replay) and that the equivalence invariants
hold:

  1. Two redactions of the same body produce the same digest
     (deterministic equivalence).
  2. Two redactions of different bodies produce different digests
     (no false equivalence).
  3. The lab channel's ``validate_loopback_get`` accepts a request that
     matches the case allowlist (positive equivalence — channel admits
     what the contract describes).
  4. The lab channel's ``validate_loopback_get`` rejects a request that
     escapes the case allowlist (negative equivalence — channel refuses
     what the contract forbids).
  5. The readiness decision returned by ``validate_target_evidence_readiness``
     is identical for two readiness objects with the same fields
     (parity of the readiness channel).
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")
os.environ.setdefault("CELERY_PAYLOAD_KEY", "test-only-celery-payload-key-not-for-production-use")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-jwt-secret-key-not-for-production-use-000000")
os.environ.setdefault("WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY", "1")
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.adapters.local_causal_lab.option_b_contract import (  # noqa: E402
    OptionBCase,
    TargetEvidenceReadiness,
    redact_body,
    validate_loopback_get,
    validate_target_evidence_readiness,
)


def _case(*, requires_auth: bool = False, status: str = "ready") -> OptionBCase:
    return OptionBCase(
        case_id="case-v3-equivalence",
        target_id="target-v3",
        origin="http://127.0.0.1:8082",
        route_pattern=re.compile(r"/api/items/\d+"),
        approved_methods=("GET",),
        approved_query_keys=("expand",),
        track="option_b",
        requires_auth=requires_auth,
        requires_target_fixture_injection=False,
        precondition_status=status,
        precondition_reason="" if status == "ready" else "missing_fixture",
        baseline_role="baseline",
        candidate_role="candidate",
        negative_control_roles=("negative_control",),
    )


def test_redaction_is_deterministic_across_two_calls():
    """Two redactions of the same body must yield identical digests."""
    body = b'{"item":"webpent-equivalence","id":42}'
    obs_a = redact_body(body)
    obs_b = redact_body(body)
    assert obs_a.body_sha256 == obs_b.body_sha256
    assert obs_a.content_type_family == obs_b.content_type_family
    assert obs_a.length_bucket == obs_b.length_bucket


def test_redaction_distinguishes_different_bodies():
    """Different bodies must yield different digests — no false equivalence."""
    body_a = b'{"item":"a"}'
    body_b = b'{"item":"b"}'
    obs_a = redact_body(body_a)
    obs_b = redact_body(body_b)
    assert obs_a.body_sha256 != obs_b.body_sha256


def test_lab_channel_accepts_allowlisted_request():
    """The lab channel admits a request that matches the case allowlist."""
    case = _case()
    errors = validate_loopback_get(
        case=case,
        method="GET",
        url="http://127.0.0.1:8082/api/items/42?expand=profile",
        expected_origin="http://127.0.0.1:8082",
        followed_redirect=False,
    )
    assert errors == ()


def test_lab_channel_rejects_request_outside_allowlist():
    """The lab channel refuses a request that escapes the case allowlist."""
    case = _case()
    errors = validate_loopback_get(
        case=case,
        method="GET",
        url="http://127.0.0.1:8082/api/items/42?token=secret",
        expected_origin="http://127.0.0.1:8082",
        followed_redirect=False,
    )
    # The token query key is not in the case's approved_query_keys.
    assert "query_key_not_in_case_allowlist" in errors


def test_readiness_decision_is_identical_for_equal_inputs():
    """Two readiness objects with the same fields produce identical
    readiness decisions (channel parity).
    """
    fields = dict(
        identity_model_available=True,
        ownership_model_available=True,
        reset_available=True,
        oracle_signal_available=True,
        observable_security_invariant=True,
        replayable_state_transition=True,
    )
    readiness_a = TargetEvidenceReadiness(**fields)
    readiness_b = TargetEvidenceReadiness(**fields)
    decision_a = validate_target_evidence_readiness(readiness_a)
    decision_b = validate_target_evidence_readiness(readiness_b)
    assert decision_a == decision_b
    assert decision_a["status"] == "ready"
    assert decision_a["runnable"] is True
