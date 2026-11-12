# tests/test_umdr35_auth_success_detection.py
"""UM-DR-35.4 — Gate 35-D authentication reliability regression tests.

A successful HTTP status, a new cookie, a changed URL, or an ordinary HTML
page is NOT proof of authenticated access. The seven-stage lifecycle
distinguishes: request submitted -> response returned -> material captured
-> material accepted -> identity established -> protected access confirmed
-> session valid during campaign. Indistinguishable evidence is EXPLICITLY
inconclusive (never a silent success, never a false rejection).
"""
from __future__ import annotations

import httpx

import webpent.recon.login_executor as login_executor_module
from webpent.recon.auth_success_model import (
    AuthSuccessStage,
    assess_login_stage,
    assess_validation_observation,
    html_identity_evidence,
    stage_at_least,
)
from webpent.recon.login_executor import AuthSignal, LoginMaterial

_SPA_SHELL = "<html><body><div id=root></div><script src=/app.js></script></body></html>"
_HTML_WITH_IDENTITY = (
    "<html><body><nav><a href='/logout'>Log out</a>"
    "<a href='/account/settings'>My account</a></nav>"
    "<span data-testid='user-menu'>alice</span></body></html>"
)


def _api_executor(monkeypatch, handler):
    monkeypatch.setattr(
        login_executor_module,
        "make_safe_httpx_client",
        lambda **_kwargs: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    return login_executor_module.LoginExecutor(target_url="http://example.test")


class TestIdentityEvidence:
    def test_spa_shell_has_no_identity_evidence(self):
        assert html_identity_evidence(_SPA_SHELL) == []

    def test_generic_welcome_html_without_controls_is_not_identity(self):
        # "welcome" text alone, without account/logout controls, is weak.
        # Only the full marker set counts; a bare landing page must not pass.
        assert html_identity_evidence("<html><body>Welcome to our site</body></html>") == []

    def test_logout_and_account_controls_are_identity_evidence(self):
        markers = html_identity_evidence(_HTML_WITH_IDENTITY)
        assert "logout_control" in markers
        assert "account_settings_control" in markers
        assert "user_identity_element" in markers


class TestStageModel:
    def test_stage_ordering(self):
        assert stage_at_least(AuthSuccessStage.PROTECTED_ACCESS_CONFIRMED,
                              AuthSuccessStage.AUTHENTICATED_IDENTITY_ESTABLISHED)
        assert not stage_at_least(AuthSuccessStage.SESSION_MATERIAL_CAPTURED,
                                  AuthSuccessStage.AUTHENTICATED_IDENTITY_ESTABLISHED)

    def test_login_phase_never_claims_identity(self):
        assessment = assess_login_stage(
            request_submitted=True, login_status_code=200,
            session_material_captured=True)
        assert assessment.stage is AuthSuccessStage.SESSION_MATERIAL_CAPTURED
        assert assessment.success is False
        assert assessment.inconclusive is True

    def test_json_identity_scalars_establish_identity(self):
        a = assess_validation_observation(
            status_code=200, content_type="application/json",
            body='{"user": {"id": 7}}', json_identity_scalars=True)
        assert a.success is True
        assert a.stage is AuthSuccessStage.AUTHENTICATED_IDENTITY_ESTABLISHED

    def test_html_identity_markers_establish_identity(self):
        a = assess_validation_observation(
            status_code=200, content_type="text/html", body=_HTML_WITH_IDENTITY)
        assert a.success is True
        assert a.stage is AuthSuccessStage.AUTHENTICATED_IDENTITY_ESTABLISHED

    def test_generic_html_is_explicitly_inconclusive(self):
        a = assess_validation_observation(
            status_code=200, content_type="text/html", body=_SPA_SHELL)
        assert a.success is False
        assert a.inconclusive is True
        assert a.reason.startswith("validation_inconclusive_html")

    def test_anonymous_differential_confirms_protected_access(self):
        a = assess_validation_observation(
            status_code=200, content_type="text/html", body=_SPA_SHELL,
            anonymous_differential=True)
        assert a.success is True
        assert a.stage is AuthSuccessStage.PROTECTED_ACCESS_CONFIRMED

    def test_login_redirect_is_rejected_not_inconclusive(self):
        a = assess_validation_observation(
            status_code=302, login_redirect=True)
        assert a.success is False
        assert a.inconclusive is False

    def test_denied_surface_is_rejected_not_inconclusive(self):
        a = assess_validation_observation(status_code=403)
        assert a.success is False
        assert a.inconclusive is False


class TestLoginExecutorHonesty:
    def _signal(self) -> AuthSignal:
        return AuthSignal(auth_type="form_session", login_url="/login",
                          login_method="POST")

    def _material(self) -> LoginMaterial:
        return LoginMaterial("cookie", "sessionid", "session-value", "operator_session")

    def test_generic_html_200_is_not_successful_authentication(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/private":
                return httpx.Response(200, text=_SPA_SHELL)
            return httpx.Response(404)

        executor = _api_executor(monkeypatch, handler)
        result = executor._validate_material(
            "owner", self._signal(), self._material(), {"protected_url": "/private"})
        assert result.success is False
        assert result.inconclusive is True
        assert result.auth_success_stage == "session_material_captured"

    def test_html_with_identity_markers_validates(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/private":
                return httpx.Response(200, text=_HTML_WITH_IDENTITY)
            return httpx.Response(404)

        executor = _api_executor(monkeypatch, handler)
        result = executor._validate_material(
            "owner", self._signal(), self._material(), {"protected_url": "/private"})
        assert result.success is True
        assert result.reason == "session_validated"
        assert result.auth_success_stage == "authenticated_identity_established"
        assert result.inconclusive is False

    def test_all_missing_surfaces_is_inconclusive_not_rejected(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        executor = _api_executor(monkeypatch, handler)
        result = executor._validate_material(
            "owner", self._signal(), self._material(), {"protected_url": "/private"})
        assert result.success is False
        assert result.inconclusive is True
        assert result.reason == "session_validation_inconclusive_surfaces_unproven"

    def test_bare_jwt_without_identity_evidence_is_inconclusive(self, monkeypatch):
        opaque = "opaque-session-token-without-claims"

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/login" and request.method == "POST":
                return httpx.Response(200, json={"token": opaque})
            return httpx.Response(404)

        executor = _api_executor(monkeypatch, handler)
        signal = AuthSignal(auth_type="api_jwt", login_url="/api/login",
                            login_method="POST")
        result = executor.login(
            alias="owner", signal=signal,
            credentials={"username": "alice", "password": "secret"})
        assert result.success is False
        assert result.inconclusive is True
        assert result.reason == "jwt_login_response_inconclusive_no_identity_evidence"
        assert result.auth_success_stage == "session_material_captured"


class TestSessionCookieValidationHonesty:
    """agents/authentication: a 5xx surface can no longer validate a session."""

    def _run(self, monkeypatch, status_code, body=""):
        import webpent.agents.authentication.agent as auth_agent_module
        import webpent.shared.http as http_module

        response = httpx.Response(status_code, text=body)

        class _Client:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def get(self, *a, **k):
                return response

            def close(self):
                pass

        monkeypatch.setattr(http_module, "make_safe_httpx_client", _Client)
        return auth_agent_module._validate_session_cookies(
            "http://example.test", {"sessionid": "x"})

    def test_5xx_surface_no_longer_validates_session(self, monkeypatch):
        ok, reason = self._run(monkeypatch, 503)
        assert ok is False
        assert "unavailable" in reason

    def test_200_generic_html_validates_but_flags_inconclusive_identity(self, monkeypatch):
        ok, reason = self._run(monkeypatch, 200, _SPA_SHELL)
        assert ok is True
        assert "inconclusive" in reason

    def test_200_with_identity_markers_names_them(self, monkeypatch):
        ok, reason = self._run(monkeypatch, 200, _HTML_WITH_IDENTITY)
        assert ok is True
        assert "identity-bearing" in reason
