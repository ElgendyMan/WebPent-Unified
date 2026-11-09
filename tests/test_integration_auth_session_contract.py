# tests/test_integration_auth_session_contract.py
"""Auth validation verdict contract tests (capability matrix A4)."""

from __future__ import annotations

import pytest

from webpent.integration.auth_session_contract import (
    AuthFailurePoint,
    AuthValidationVerdict,
    merge_into_state_dict,
    record_from_verdict,
)


def test_success_verdict_requires_verified_session():
    verdict = AuthValidationVerdict(login_success=True, session_verified=True)
    assert verdict.failure_point is AuthFailurePoint.NONE


def test_success_without_session_verification_fails_closed():
    with pytest.raises(ValueError, match="successful_login_requires_session_verification"):
        AuthValidationVerdict(login_success=True)


def test_success_with_failure_point_is_inconsistent():
    with pytest.raises(ValueError, match="successful_login_must_not_carry_failure_point"):
        AuthValidationVerdict(
            login_success=True,
            failure_point=AuthFailurePoint.TOTP_SECRET,
            session_verified=True,
        )


def test_failure_requires_a_classified_failure_point():
    with pytest.raises(ValueError, match="failed_login_requires_failure_point"):
        AuthValidationVerdict(login_success=False)
    verdict = AuthValidationVerdict(
        login_success=False,
        failure_point=AuthFailurePoint.USERNAME_OR_PASSWORD,
    )
    assert verdict.session_verified is False


def test_failure_must_not_verify_session():
    with pytest.raises(ValueError, match="failed_login_must_not_verify_session"):
        AuthValidationVerdict(
            login_success=False,
            failure_point=AuthFailurePoint.OUT_OF_BAND,
            session_verified=True,
        )


def test_signal_strength_is_deterministic():
    success = AuthValidationVerdict(login_success=True, session_verified=True)
    failure = AuthValidationVerdict(
        login_success=False, failure_point=AuthFailurePoint.TOTP_SECRET
    )
    assert success.to_signal_strength() == 1.0
    assert failure.to_signal_strength() == 0.2


def test_record_drops_secret_values_and_counts_them():
    verdict = AuthValidationVerdict(login_success=True, session_verified=True)
    record = record_from_verdict(
        verdict,
        {
            "username": "tester",
            "password": "hunter2",
            "session_cookie": "SECRET",
            "token": "SECRET-TOKEN",
        },
    )
    assert record.redacted_value_keys_dropped == 3
    assert "hunter2" not in record.model_dump_json()
    assert "SECRET" not in record.model_dump_json()
    assert record.login_success is True


def test_merge_returns_new_state_and_never_touches_session_cookies():
    verdict = AuthValidationVerdict(
        login_success=False,
        failure_point=AuthFailurePoint.USERNAME_OR_PASSWORD,
    )
    state = {
        "target": "https://lab.local",
        "session_cookies": [{"name": "sid", "value": "KEEP-SECRET"}],
    }
    merged = merge_into_state_dict(state, verdict)
    # Input untouched (pure function).
    assert "auth_validation" not in state
    # New dict carries only the advisory record.
    assert merged["auth_validation"]["login_success"] is False
    assert merged["auth_validation"]["failure_point"] == "username_or_password"
    # Session cookies are copied by reference into the new dict — the
    # contract NEVER modifies or re-writes them, and stores no copy of
    # secret values in its own record.
    assert merged["session_cookies"] == state["session_cookies"]
    assert merged["auth_validation"]["redacted_value_keys_dropped"] == 0


def test_merge_counts_credential_keys_present_in_state():
    verdict = AuthValidationVerdict(login_success=True, session_verified=True)
    merged = merge_into_state_dict(
        verdict=verdict,
        state={"credentials": {"username": "u", "password": "p"}},
    )
    assert merged["auth_validation"]["redacted_value_keys_dropped"] == 1
    assert "password" not in merged["auth_validation"]


def test_no_verdict_authority_leakage():
    verdict = AuthValidationVerdict(login_success=True, session_verified=True)
    dump = verdict.model_dump_json()
    assert "CONFIRMED" not in dump
    assert "finding" not in dump.lower()
