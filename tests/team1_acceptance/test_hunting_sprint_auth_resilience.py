"""Hunting Intelligence Sprint — auth resilience tests.

Synthetic only. Covers: API-key 4th auth type; OAuth2 state-checked flow;
basic-auth fallback; cookie-expiry inspection; zero-FP.
"""
from __future__ import annotations

import pytest

from webpent.recon.auth_resilience import (
    ApiKeyAuthExecutor,
    BasicAuthFallback,
    CookieExpiryInspector,
    OAuth2FlowHandler,
    OAuth2Outcome,
    SUPPORTED_AUTH_TYPES,
)


# -- API key (4th auth type) -------------------------------------------------
def test_api_key_is_fourth_supported_type():
    assert "api_key" in SUPPORTED_AUTH_TYPES
    assert len(SUPPORTED_AUTH_TYPES) == 5  # form, api_jwt, basic, oauth, api_key


def test_api_key_executor_builds_headers_and_m4_secret():
    ex = ApiKeyAuthExecutor(header_name="X-API-Key")
    headers = ex.build_headers("sk-live-abc123")
    assert headers["X-API-Key"] == "sk-live-abc123"
    # m4_secret shape matches frozen LoginMaterial api_key kind: "api-key:name=value"
    assert ex.m4_secret("sk-live-abc123") == "api-key:X-API-Key=sk-live-abc123"


def test_api_key_executor_rejects_empty_key():
    ex = ApiKeyAuthExecutor()
    out = ex.login(alias="owner", api_key="")
    assert out["success"] is False
    assert out["reason"] == "api_key_required"


def test_api_key_validation_via_injected_http():
    calls = []

    def http(method, url, headers, body):
        calls.append((method, url))
        return type("R", (), {"status_code": 200})()

    ex = ApiKeyAuthExecutor(validation_url="https://t/api/me")
    out = ex.login(alias="owner", api_key="k1", http=http)
    assert out["success"] is True
    assert calls == [("GET", "https://t/api/me")]
    assert out["material"]["kind"] == "api_key"
    assert "digest" in out["material"]  # no raw key in serialized output


# -- OAuth2 ------------------------------------------------------------------
def test_oauth_state_mismatch_fail_closed():
    flow = OAuth2FlowHandler(
        client_id="cid", redirect_uri="https://app/cb",
        authorize_url="https://idp/authorize", token_url="https://idp/token",
        state_generator=lambda: "fixed_state_123",
    )
    url = flow.build_authorize_url()
    assert "state=fixed_state_123" in url
    outcome = flow.handle_callback(code="c1", state="WRONG_STATE")
    assert isinstance(outcome, OAuth2Outcome)
    assert outcome.success is False
    assert outcome.state_verified is False
    assert "state_mismatch" in outcome.reason


def test_oauth_state_match_offline_success():
    flow = OAuth2FlowHandler(
        client_id="cid", redirect_uri="https://app/cb",
        authorize_url="https://idp/authorize", token_url="https://idp/token",
        state_generator=lambda: "s1",
    )
    flow.build_authorize_url()
    outcome = flow.handle_callback(code="code_abc", state="s1")  # no http -> offline
    assert outcome.success is True
    assert outcome.state_verified is True
    assert outcome.token_digest  # digest only, no raw token


def test_oauth_callback_without_authorize_build_fails():
    flow = OAuth2FlowHandler(client_id="c", redirect_uri="r", authorize_url="a", token_url="t")
    outcome = flow.handle_callback(code="c1", state="s1")
    assert outcome.success is False
    assert "authorize_url_not_built" in outcome.reason


# -- Basic auth fallback -----------------------------------------------------
def test_basic_auth_header_format():
    fb = BasicAuthFallback()
    headers = fb.header("alice", "secret")
    assert headers["Authorization"].startswith("Basic ")
    # base64("alice:secret") == YWxpY2U6c2VjcmV0
    assert headers["Authorization"] == "Basic YWxpY2U6c2VjcmV0"


def test_basic_fallback_only_when_no_stronger_signal():
    fb = BasicAuthFallback()
    assert fb.applies(www_authenticate="Basic realm=x", form_detected=False, api_detected=False) is True
    assert fb.applies(www_authenticate="Basic realm=x", form_detected=True, api_detected=False) is False  # form wins
    assert fb.applies(www_authenticate="", form_detected=False, api_detected=False) is False  # no www-authenticate


# -- Cookie expiry inspection ------------------------------------------------
def test_cookie_expired_in_past_marked_dead():
    insp = CookieExpiryInspector(now=lambda: 1_700_000_000.0)
    # Expires in the past -> session dead
    headers = ["session=abc; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/"]
    result = insp.inspect(headers)
    assert len(result) == 1
    assert result[0].name == "session"
    assert result[0].fresh is False
    assert "expires_in_past" in result[0].reason


def test_cookie_max_age_zero_marked_dead():
    insp = CookieExpiryInspector(now=lambda: 1_700_000_000.0)
    headers = ["sid=x; Max-Age=0"]
    result = insp.inspect(headers)
    assert result[0].fresh is False


def test_cookie_future_expiry_marked_fresh():
    insp = CookieExpiryInspector(now=lambda: 1_700_000_000.0)
    headers = ["sid=x; Max-Age=3600"]
    result = insp.inspect(headers)
    assert result[0].fresh is True
    assert result[0].max_age_seconds == 3600


def test_cookie_inspector_never_returns_values():
    insp = CookieExpiryInspector()
    headers = ["session=SECRET_VALUE_123; Max-Age=60"]
    result = insp.inspect(headers)
    d = result[0].as_dict()
    assert "SECRET_VALUE_123" not in str(d)  # names/metadata only
