"""r6c login-executor validation honesty + payload-capture tests (Gaps 2 & 4).

r5 LAB evidence: ``_validation_url`` rendered ``<base>/None`` from ``str(None)``
when no validation surface was configured, and a 200 HTML SPA catch-all marked
the session ``session_validated`` (vacuous). r6c fixes:

- the validation URL is structurally unable to render ``<base>/None``;
- HTML 200 → ``success=True`` with ``reason="validation_inconclusive"``
  (material exists, the surface proved nothing) — JSON 200 keeps
  ``session_validated``;
- ``response_payload``/``identity_claims`` are runtime-only fields on
  ``LoginResult`` and never appear in ``as_dict()`` (B1 credential hygiene).

r9 revisions (D1–D4, DR-017): the r6c fallback that probed the signal's
LOGIN URL as the validation surface is REVERSED by design — a login surface
is not a session-validation surface (r7/r8: GET on a POST-only REST login
path → 500 → conflated rejection). The three r6c ``_validation_url``
fallback pins below are revised to the D1 contract: configured surface →
bounded discovered same-origin identity window → root, with the login URL
structurally excluded. T1–T5 cover the r9 defect register end to end.
"""

from __future__ import annotations

import base64
import json

import httpx

from webpent.recon import login_executor as login_executor_module
from webpent.recon.auth_detector import AuthDetector, AuthSignal
from webpent.recon.login_executor import LoginExecutor


def _jwt(payload: dict) -> str:
    head = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{head}.{body}.signature"


def _api_executor(monkeypatch, handler) -> LoginExecutor:
    monkeypatch.setattr(
        login_executor_module,
        "make_safe_httpx_client",
        lambda **_kwargs: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    return LoginExecutor(target_url="http://example.test")


API_SIGNAL = AuthSignal(
    auth_type="api_jwt",
    login_url="http://example.test/rest/user/login",
    login_fields={"username_field": "email", "password_field": "password"},
    token_type="jwt",
    token_capture="JSON token field",
)


def test_validation_url_never_renders_base_none_without_configured_surface():
    # r9 D1 revision: with no configured surface the fallback is the bounded
    # discovered identity window (first), with the root LAST — never the
    # login URL, and structurally never ``<base>/None``.
    executor = LoginExecutor(target_url="https://t.local")
    signal = AuthSignal(auth_type="form_session", login_url=None, login_method="POST")
    surfaces = executor._validation_surfaces(signal, {})
    urls = [url for _kind, url in surfaces]
    assert urls[0] == "https://t.local/whoami"  # governed identity vocabulary, first
    assert urls[-1] == "https://t.local"  # root stays the last fallback
    for url in urls:
        assert not url.endswith("/None")
        assert url != "https://t.local/None"


def test_validation_url_signal_login_url_is_structurally_excluded():
    # r9 D1 (REVERSES the r6c second-fallback pin): a login endpoint is a
    # login surface, not a session-validation surface. GET on a POST-only
    # REST login path is the r7/r8 500-conflation failure.
    executor = LoginExecutor(target_url="https://t.local")
    signal = AuthSignal(auth_type="form_session", login_url="/login", login_method="POST")
    surfaces = executor._validation_surfaces(signal, {})
    urls = [url for _kind, url in surfaces]
    assert "https://t.local/login" not in urls
    assert urls[-1] == "https://t.local"
    assert executor._validation_url(signal, {}) == "https://t.local/whoami"


def test_configured_protected_url_wins_and_literal_none_string_rejected():
    executor = LoginExecutor(target_url="https://t.local")
    signal = AuthSignal(auth_type="form_session", login_url="/login", login_method="POST")
    assert executor._validation_url(signal, {"protected_url": "/private"}) == "https://t.local/private"
    assert executor._validation_url(signal, {"validation_url": "/me"}) == "https://t.local/me"
    # Literal "None"/"none" string configs must never become <base>/None and
    # must never fall back to the login URL (r9 D1): the discovered identity
    # window is next, root last.
    surfaces = executor._validation_surfaces(signal, {"protected_url": "None"})
    urls = [url for _kind, url in surfaces]
    assert "https://t.local/login" not in urls
    assert urls[0] == "https://t.local/whoami"
    assert urls[-1] == "https://t.local"
    bare = AuthSignal(auth_type="form_session", login_url=None, login_method="POST")
    bare_urls = [url for _kind, url in executor._validation_surfaces(bare, {"protected_url": "None"})]
    assert bare_urls[0] == "https://t.local/whoami"
    assert bare_urls[-1] == "https://t.local"


def test_html_200_validation_is_inconclusive_not_session_validated(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/private":
            return httpx.Response(200, text="<html><body>spa-shell</body></html>")
        return httpx.Response(404)

    executor = _api_executor(monkeypatch, handler)
    signal = AuthSignal(auth_type="form_session", login_url="/login", login_method="POST")
    material = login_executor_module.LoginMaterial("cookie", "sessionid", "session-value", "operator_session")
    result = executor._validate_material("owner", signal, material, {"protected_url": "/private"})
    assert result.success is True
    assert result.reason == "validation_inconclusive"
    assert result.reason != "session_validated"


def test_json_200_validation_keeps_session_validated(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/private":
            return httpx.Response(200, json={"user": {"id": 1}})
        return httpx.Response(404)

    executor = _api_executor(monkeypatch, handler)
    signal = AuthSignal(auth_type="form_session", login_url="/login", login_method="POST")
    material = login_executor_module.LoginMaterial("cookie", "sessionid", "session-value", "operator_session")
    result = executor._validate_material("owner", signal, material, {"protected_url": "/private"})
    assert result.success is True
    assert result.reason == "session_validated"


def test_api_flow_attaches_payload_and_claims_runtime_only(monkeypatch):
    token = _jwt({"sub": "1", "userId": "7"})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/rest/user/login":
            return httpx.Response(200, json={"authentication": {"token": token}})
        if request.url.path == "/private":
            return httpx.Response(200, json={"user": {"id": 7}})
        return httpx.Response(404)

    executor = _api_executor(monkeypatch, handler)
    result = executor.login(
        alias="owner",
        signal=API_SIGNAL,
        credentials={
            "username": "operator-email",
            "password": "operator-password",
            "protected_url": "/private",
        },
    )
    assert result.success is True
    assert result.reason == "session_validated"
    assert result.response_payload == {"authentication": {"token": token}}
    assert result.identity_claims == {"sub": "1", "userId": "7"}
    # B1 hygiene: runtime-only fields must be absent from the serialized form.
    serialized = result.as_dict()
    assert "response_payload" not in serialized
    assert "identity_claims" not in serialized
    assert token not in json.dumps(serialized)
    assert serialized["material"]["kind"] == "bearer"


def test_api_fast_path_reason_and_payload_behavior_unchanged(monkeypatch):
    token = _jwt({"sub": "1"})

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"authentication": {"token": token}})

    executor = _api_executor(monkeypatch, handler)
    result = executor.login(
        alias="owner",
        signal=API_SIGNAL,
        credentials={"username": "operator-email", "password": "operator-password"},
    )
    # Pinned by tests/test_regression_campaign_pipeline.py:67 — unchanged.
    assert result.reason == "jwt_login_response_validated"
    assert result.success is True
    assert result.response_payload == {"authentication": {"token": token}}
    assert result.identity_claims == {"sub": "1"}
    serialized = result.as_dict()
    assert "response_payload" not in serialized and "identity_claims" not in serialized
    assert token not in json.dumps(serialized)


def test_form_flow_captures_json_payload_only_and_stays_absent_for_html(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login" and request.method == "GET":
            return httpx.Response(
                200,
                text='<form action="/login" method="POST">'
                '<input type="hidden" name="csrf" value="c">'
                '<input name="user"><input type="password" name="pass"></form>',
            )
        if request.url.path == "/login" and request.method == "POST":
            captured["wants_json"] = True
            if captured.get("json_response"):
                return httpx.Response(
                    200,
                    json={"status": "ok"},
                    headers={"Set-Cookie": "sessionid=session-value; Path=/"},
                )
            return httpx.Response(
                200,
                text="<html>welcome</html>",
                headers={"Set-Cookie": "sessionid=session-value; Path=/"},
            )
        if request.url.path == "/private":
            return httpx.Response(200, text="private")
        return httpx.Response(404)

    executor = _api_executor(monkeypatch, handler)
    signal = (
        AuthDetector(target_url="http://example.test")
        .detect(
            {
                "target_url": "http://example.test",
                "routes": [
                    {
                        "route": "/login",
                        "forms": [
                            {
                                "action": "/login",
                                "method": "POST",
                                "login_signal": True,
                                "fields": [{"name": "user"}, {"name": "pass"}],
                            }
                        ],
                        "auth_mechanisms": [],
                    }
                ],
            }
        )
        .primary
    )
    assert signal is not None

    captured["json_response"] = True
    json_result = executor.login(
        alias="owner",
        signal=signal,
        credentials={"username": "alice", "password": "correct", "protected_url": "/private"},
    )
    assert json_result.success is True
    assert json_result.response_payload == {"status": "ok"}

    captured["json_response"] = False
    html_result = executor.login(
        alias="owner",
        signal=signal,
        credentials={"username": "alice", "password": "correct", "protected_url": "/private"},
    )
    assert html_result.success is True
    assert html_result.response_payload is None  # non-JSON form response: fail-soft absent
    assert "response_payload" not in html_result.as_dict()


# ---------------------------------------------------------------------------
# r9 T1–T5 (DR-017): consolidated identity-provisioning fix regression tests.
# Mock same-origin HTTP only — no external targets.
# ---------------------------------------------------------------------------


def test_t1_post_only_login_endpoint_never_probed_for_validation(monkeypatch):
    """T1 (D1): a POST-only login endpoint that 500s on GET is structurally
    excluded from validation; the discovered window finds the real surface."""
    hits: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hits.append((request.method, request.url.path))
        if request.url.path == "/rest/user/login":
            if request.method == "GET":
                return httpx.Response(500, text="Error: Unexpected path")
            return httpx.Response(200, json={"authentication": {"token": "x"}})
        if request.url.path == "/whoami":
            return httpx.Response(200, json={"user": {"id": 7}})
        return httpx.Response(404)

    executor = _api_executor(monkeypatch, handler)
    material = login_executor_module.LoginMaterial("bearer", "Authorization", "not-a-real-token", "operator_token")
    result = executor._validate_material("owner", API_SIGNAL, material, {})
    assert result.success is True
    assert result.reason == "session_validated"
    assert result.validation_url == "http://example.test/whoami"
    # The login URL was never probed with GET, and it is not the surface.
    assert ("GET", "/rest/user/login") not in hits
    assert result.validation_url != API_SIGNAL.login_url
    assert result.validation_probes[0]["path"] == "/whoami"
    assert result.validation_probes[0]["result"] == "json_identity_resolved"


def test_t2_rejected_operator_token_falls_through_to_credential_login(monkeypatch):
    """T2 (D2): operator-token validation rejected → a REAL credential login
    POST is attempted before any failure is reported (the r8 short-circuit)."""
    token = _jwt({"sub": "1", "userId": "7"})
    hits: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hits.append((request.method, request.url.path))
        if request.url.path == "/rest/user/login" and request.method == "POST":
            return httpx.Response(200, json={"authentication": {"token": token}})
        return httpx.Response(404)

    executor = _api_executor(monkeypatch, handler)
    result = executor.login(
        alias="owner",
        signal=API_SIGNAL,
        credentials={
            "token": "garbage-operator-token",
            "username": "owner@example.test",
            "password": "correct",
        },
    )
    assert result.success is True
    assert result.reason == "jwt_login_response_validated"
    # The credential login actually happened (POST per the signal's strategy).
    assert ("POST", "/rest/user/login") in hits
    # The rejected token path stays visible in the honest reason chain.
    assert result.reason_chain[0] == "operator_token:session_validation_rejected"
    assert result.reason_chain[1].startswith("credential_login:")


def test_t3_conflicting_profile_auth_type_is_recorded_not_relabelled(monkeypatch):
    """T3 (D3): a profile auth_type conflicting with detection must never
    silently relabel the detected signal — requested/detected/executed are
    all recorded, and the detected strategy remains reachable."""
    token = _jwt({"sub": "1"})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/rest/user/login" and request.method == "POST":
            if "application/json" in request.headers.get("content-type", ""):
                return httpx.Response(200, json={"authentication": {"token": token}})
            return httpx.Response(403)
        if request.method == "GET":
            return httpx.Response(404)
        return httpx.Response(404)

    monkeypatch.setattr(
        login_executor_module,
        "make_safe_httpx_client",
        lambda **_kwargs: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    import webpent.recon.principal_provisioning as provisioning_module

    monkeypatch.setattr(
        provisioning_module,
        "make_safe_httpx_client",
        lambda **_kwargs: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    from webpent.recon.auth_detector import AuthDetection
    from webpent.recon.principal_provisioning import PrincipalProvisioner

    signal = AuthSignal(
        auth_type="api_jwt",
        login_url="http://example.test/rest/user/login",
        login_fields={"username_field": "email", "password_field": "password"},
        token_type="jwt",
        token_capture="JSON token field",
    )
    detection = AuthDetection((signal,), "http://example.test", ("owner",))
    result = PrincipalProvisioner(target_url="http://example.test", engagement_id="t3-mismatch").provision(
        [
            {
                "name": "owner",
                "auth_type": "form_session",
                "username": "owner@example.test",
                "password": "correct",
            }
        ],
        detection=detection,
    )
    assert len(result.principals) == 1
    record = result.principals[0].as_dict()
    assert record["requested_auth_type"] == "form_session"
    assert record["detected_auth_type"] == "api_jwt"
    # The DETECTED strategy won after the requested form strategy failed —
    # and the record says so instead of contradicting the detector silently.
    assert record["executed_auth_type"] == "api_jwt"
    assert record["auth_type"] == "api_jwt"
    assert record["success"] is True
    assert record["vault_bound"] is True


def test_t4_status_code_stays_none_without_login_response(monkeypatch):
    """T4 (D4): with no login response, ``status_code`` is None — the
    validation status is never duplicated into it (r8 500/500 conflation)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/private":
            return httpx.Response(404)
        return httpx.Response(404)

    executor = _api_executor(monkeypatch, handler)
    signal = AuthSignal(auth_type="form_session", login_url="/login", login_method="POST")
    material = login_executor_module.LoginMaterial("cookie", "sessionid", "session-value", "operator_session")
    rejected = executor._validate_material("owner", signal, material, {"protected_url": "/private"})
    assert rejected.success is False
    assert rejected.reason == "session_validation_rejected"
    assert rejected.status_code is None
    assert rejected.validation_status_code == 404

    def html_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>spa-shell</html>")

    executor_html = _api_executor(monkeypatch, html_handler)
    inconclusive = executor_html._validate_material("owner", signal, material, {"protected_url": "/private"})
    assert inconclusive.success is True
    assert inconclusive.reason == "validation_inconclusive"
    assert inconclusive.status_code is None
    assert inconclusive.validation_status_code == 200


def test_t5_unreachable_surfaces_fail_closed_with_precise_reason(monkeypatch):
    """T5 (D1): when no usable validation surface exists (root unreachable),
    the walk fails closed with ``validation_surface_unavailable`` — never a
    vacuous success, never a conflated status."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    executor = _api_executor(monkeypatch, handler)
    signal = AuthSignal(auth_type="form_session", login_url="/login", login_method="POST")
    material = login_executor_module.LoginMaterial("bearer", "Authorization", "token-value", "operator_token")
    result = executor._validate_material("owner", signal, material, {})
    assert result.success is False
    assert result.reason == "validation_surface_unavailable"
    assert result.status_code is None
    assert len(result.validation_probes) >= 1
    assert all(str(probe["result"]).startswith("exception:") for probe in result.validation_probes)
    assert result.validation_probes[-1]["path"] == "/"  # the root was the last probed surface


def test_discovered_anonymous_shape_200_never_validates(monkeypatch):
    """r9 D1 honesty: a discovered whoami-style surface that answers 200 with
    an anonymous shape under our material did NOT bind the session — the walk
    must skip it, never claim ``session_validated`` (the r5 vacuous-whoami
    lesson applied to the D1 window)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/whoami":
            return httpx.Response(200, json={"user": {}})  # anonymous shape
        if request.url.path == "/":
            return httpx.Response(200, text="<html>spa-shell</html>")
        return httpx.Response(404)

    executor = _api_executor(monkeypatch, handler)
    material = login_executor_module.LoginMaterial("bearer", "Authorization", "invalid-token", "operator_token")
    result = executor._validate_material("owner", API_SIGNAL, material, {})
    assert result.success is True
    assert result.reason == "validation_inconclusive"  # root HTML keep-alive, NOT session_validated
    assert result.validation_url == "http://example.test"  # rstrip'd root
    whoami_probe = result.validation_probes[0]
    assert whoami_probe["path"] == "/whoami"
    assert whoami_probe["result"] == "anonymous_shape"
