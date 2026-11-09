from __future__ import annotations

from dataclasses import replace

from webpent.adapters.local_causal_lab.fixtures import (
    DisposableCanary,
    SyntheticIdentity,
    build_regression_fixture,
)


def test_regression_fixture_is_opaque_disposable_and_hashable() -> None:
    fixture = build_regression_fixture("owasp_webgoat")
    assert fixture.validate() == ()
    before = fixture.state_hash()
    reset = fixture.reset_check(before)
    assert reset["status"] == "verified"
    assert reset["state_hash_equal"] is True
    assert reset["application_reset_endpoint_called"] is False
    assert reset["application_mutation_performed"] is False
    assert reset["raw_values_persisted"] is False


def test_fixture_rejects_credentials_sessions_mutation_and_raw_values() -> None:
    fixture = build_regression_fixture("crapi")
    bad_identity = replace(fixture.identities[0], session_material_present=True)
    bad = replace(
        fixture, identities=(bad_identity, fixture.identities[1]), raw_values_persisted=True
    )
    errors = bad.validate()
    assert "credential_or_session_material_forbidden" in errors
    assert "raw_values_persistence_must_remain_false" in errors

    bad_canary = DisposableCanary("canary_bad", "synthetic", raw_value_persisted=True)
    assert "raw_canary_persistence_forbidden" in bad_canary.validate()


def test_fixture_reset_fails_closed_when_application_state_would_change() -> None:
    fixture = build_regression_fixture("owasp_webgoat")
    before = fixture.state_hash()
    mutated = replace(fixture, application_mutation_performed=True)
    result = mutated.reset_check(before)
    assert result["status"] == "blocked"
    assert result["state_hash_equal"] is False
    assert "application_mutation_must_remain_false" in result["validation_errors"]


def test_identity_ids_cannot_be_real_or_credential_bearing() -> None:
    identity = SyntheticIdentity("alice@example.com", "owner")
    assert "identity_must_be_opaque_test_id" in identity.validate()
    credentialed = SyntheticIdentity("test_subject_x", "owner", credential_material_present=True)
    assert "credential_or_session_material_forbidden" in credentialed.validate()
