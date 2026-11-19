from __future__ import annotations

import json

import httpx
import pytest

from webpent.recon.auth_detector import AuthDetector, AuthSignal
from webpent.recon.login_executor import LoginExecutor
from webpent.recon.principal_provisioning import PrincipalProvisioner
from webpent.recon.autonomous_crawler import _canonical_url
from webpent.recon.browser_crawler import BrowserCrawlConfig, _safe_navigation_target
from webpent.scope import ScopeEnforcer, ScopeParseError, parse_scope_text
from webpent import recon


def test_api_jwt_signal_routes_to_json_and_never_form_cookie_capture(monkeypatch):
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["content_type"] = request.headers.get("content-type")
        captured["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={"authentication": {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"}})

    from webpent.recon import login_executor as module
    monkeypatch.setattr(module, "make_safe_httpx_client", lambda **_: httpx.Client(transport=httpx.MockTransport(handler)))
    target = "http://juice.local"
    signal = AuthDetector(target_url=target).detect({
        "routes": [{"route": "/rest/user/login", "api_signal": True, "content_type": "application/json"}]
    }).primary
    assert signal is not None and signal.auth_type == "api_jwt"
    result = LoginExecutor(target_url=target).login(
        alias="owner", signal=signal, credentials={"username": "alice", "password": "pw"}
    )
    assert result.success is True
    assert captured == {"content_type": "application/json", "body": {"username": "alice", "password": "pw"}}
    assert result.reason == "jwt_login_response_validated"


def test_explicit_form_session_does_not_relabel_detected_api_jwt():
    detection = AuthDetector(target_url="http://juice.local").detect({
        "routes": [{"route": "/rest/user/login", "api_signal": True, "content_type": "application/json"}]
    })
    result = PrincipalProvisioner(target_url="http://juice.local", engagement_id="repair").provision(
        {"owner": {"auth_type": "form_session", "username": "alice", "password": "pw"}},
        detection=detection,
    )
    assert result.principals[0].login.success is False
    assert result.principals[0].login.reason == "configured_auth_type_not_detected"
    assert result.principals[0].login.auth_type == "form_session"


def test_explicit_api_jwt_route_is_allowed_only_when_operator_supplies_url(monkeypatch):
    seen = {}

    def fake_login(self, *, alias, signal, credentials):
        seen["auth_type"] = signal.auth_type
        seen["login_url"] = signal.login_url
        from webpent.recon.login_executor import LoginResult
        return LoginResult(alias, False, signal.auth_type, signal.login_url, None, "synthetic_no_network")

    monkeypatch.setattr(LoginExecutor, "login", fake_login)
    detection = AuthDetector(target_url="http://juice.local").detect({
        "routes": [{"route": "/login", "forms": [{"login_signal": True, "fields": []}]}]
    })
    result = PrincipalProvisioner(target_url="http://juice.local", engagement_id="repair").provision(
        {"owner": {"auth_type": "api_jwt", "login_url": "/rest/user/login", "username": "alice", "password": "pw"}},
        detection=detection,
    )
    assert seen == {"auth_type": "api_jwt", "login_url": "/rest/user/login"}
    assert result.principals[0].login.auth_type == "api_jwt"


def test_unsupported_auth_type_fails_closed():
    result = LoginExecutor(target_url="https://example.test").login(
        alias="owner", signal=AuthSignal(auth_type="magic", login_url="/login"), credentials={}
    )
    assert result.success is False
    assert result.reason == "unsupported_auth_type"


def test_scope_url_without_explicit_port_does_not_admit_non_default_port():
    policy = parse_scope_text(json.dumps({"in_scope": ["https://example.test"]}))
    enforcer = ScopeEnforcer(policy)
    assert enforcer.check_url("https://example.test/path").allowed
    assert not enforcer.check_url("https://example.test:8443/path").allowed


def test_scope_boolean_and_invalid_limits_are_parsed_fail_closed():
    policy = parse_scope_text(json.dumps({"in_scope": ["https://example.test"], "limits": {"no_destructive": "false"}}))
    assert policy.limits.no_destructive is False
    with pytest.raises(ScopeParseError):
        parse_scope_text(json.dumps({"in_scope": ["https://example.test"], "limits": {"max_requests_per_second": "nan"}}))
    with pytest.raises(ScopeParseError):
        parse_scope_text(json.dumps({"in_scope": [{"domain": "example.test", "port": 0}]}))
    with pytest.raises(ScopeParseError):
        parse_scope_text(json.dumps({"in_scope": [{"domain": "example.test", "allow": "maybe"}]}))


def test_crawler_and_browser_reject_credentialed_or_malformed_urls():
    assert _canonical_url("https://user:pass@example.test/private", "https://example.test") is None
    assert _safe_navigation_target("https://user:pass@example.test/private", "https://example.test") is False
    assert _safe_navigation_target("http://[bad", "http://example.test") is False
    with pytest.raises(ValueError):
        BrowserCrawlConfig(max_pages=0)
