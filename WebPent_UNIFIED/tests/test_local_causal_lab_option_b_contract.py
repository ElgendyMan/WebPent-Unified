from __future__ import annotations

from dataclasses import replace

from webpent.adapters.crapi.option_b import cases as crapi_cases
from webpent.adapters.crapi.option_b import validate_profile as validate_crapi
from webpent.adapters.local_causal_lab.option_b_contract import (
    redact_body,
    validate_loopback_get,
)
from webpent.adapters.webgoat.option_b import (
    cases as webgoat_cases,
)
from webpent.adapters.webgoat.option_b import (
    validate_profile as validate_webgoat,
)


def test_target_profiles_are_valid_and_keep_tracks_local() -> None:
    assert validate_webgoat() == []
    assert validate_crapi() == []
    assert {case.target_id for case in webgoat_cases()} == {"owasp_webgoat"}
    assert {case.target_id for case in crapi_cases()} == {"crapi"}
    assert all(case.precondition_status == "blocked" for case in (*webgoat_cases(), *crapi_cases()))


def test_loopback_get_allowlist_accepts_only_declared_webgoat_path() -> None:
    case = webgoat_cases()[1]
    assert (
        validate_loopback_get(
            case=case,
            method="GET",
            url="http://127.0.0.1:8080/WebGoat/PathTraversal/random-picture?id=1",
            expected_origin=case.origin,
        )
        == ()
    )


def test_loopback_policy_rejects_non_loopback_redirect_and_non_get() -> None:
    case = webgoat_cases()[1]
    assert "host_must_be_http_loopback_127001" in validate_loopback_get(
        case=case,
        method="GET",
        url="http://127.0.0.2:8080/WebGoat/PathTraversal/random-picture?id=1",
        expected_origin=case.origin,
    )
    assert "redirect_following_forbidden" in validate_loopback_get(
        case=case,
        method="GET",
        url="http://127.0.0.1:8080/WebGoat/PathTraversal/random-picture?id=1",
        expected_origin=case.origin,
        followed_redirect=True,
    )
    assert "method_not_approved_get_only" in validate_loopback_get(
        case=case,
        method="POST",
        url="http://127.0.0.1:8080/WebGoat/PathTraversal/random-picture?id=1",
        expected_origin=case.origin,
    )


def test_loopback_policy_rejects_unapproved_route_query_and_credentials() -> None:
    case = webgoat_cases()[1]
    for url in (
        "http://127.0.0.1:8080/WebGoat/login",
        "http://127.0.0.1:8080/WebGoat/PathTraversal/random-picture?id=1&token=secret",
        "http://127.0.0.1:8080/WebGoat/PathTraversal/random-picture?id=../secret",
        "http://user:pass@127.0.0.1:8080/WebGoat/PathTraversal/random-picture?id=1",
    ):
        assert validate_loopback_get(case=case, method="GET", url=url, expected_origin=case.origin)


def test_redaction_rejects_persistence_flags_and_keeps_only_typed_metadata() -> None:
    observation = redact_body(b"synthetic-canary", canary_digest="not-the-digest")
    assert observation.canary_present is False
    assert observation.raw_body_retained is False
    assert observation.validate() == ()
    unsafe = replace(observation, raw_body_retained=True)
    assert "raw_response_material_must_not_be_retained" in unsafe.validate()


def test_auth_required_case_cannot_be_marked_ready_without_session_fixture() -> None:
    case = crapi_cases()[1]
    invalid = replace(case, precondition_status="ready")
    assert "auth_case_cannot_be_ready_without_approved_session_fixture" in invalid.validate()


def test_case_without_independent_control_is_rejected() -> None:
    case = webgoat_cases()[1]
    invalid = replace(case, negative_control_roles=())
    assert "independent_negative_control_required" in invalid.validate()
