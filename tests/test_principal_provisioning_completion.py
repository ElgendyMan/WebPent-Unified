from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import httpx

from webpent.agents.hunter_contracts import (
    BudgetState,
    ExploitationResult,
    HunterState,
    HunterStatus,
    ValidationVerdict,
    Verdict,
)
from webpent.agents.hunter_graph import run_hunter_graph
from webpent.production.context_authority import (
    AuthContextRef,
    ContextAuthority,
    PrincipalRef,
    PrincipalRole,
)
from webpent.recon import login_executor as login_executor_module
from webpent.recon.auth_detector import AuthDetector, AuthSignal
from webpent.recon.login_executor import LoginExecutor


class _AuthHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def do_GET(self):
        if self.path == "/login":
            body = b'<form action="/login" method="POST"><input type="hidden" name="csrf" value="csrf-value"><input name="user"><input type="password" name="pass"><button type="submit">Login</button></form>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/private":
            cookie = self.headers.get("Cookie", "")
            if "SID=session-value" in cookie:
                body = b"private"
                self.send_response(200)
            else:
                body = b"login required"
                self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path != "/login":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        values = parse_qs(self.rfile.read(length).decode())
        if values.get("csrf") == ["csrf-value"] and values.get("user") == ["alice"] and values.get("pass") == ["correct"]:
            self.send_response(302)
            self.send_header("Set-Cookie", "SID=session-value; Path=/; HttpOnly")
            self.send_header("Location", "/private")
        else:
            self.send_response(403)
        self.end_headers()


def test_detector_identifies_form_api_basic_oauth_and_cookie_shapes():
    surface = {
        "target_url": "http://example.test",
        "routes": [
            {"route": "/login", "forms": [{"action": "/login", "method": "POST", "login_signal": True, "fields": [{"name": "email"}, {"name": "password"}]}], "auth_mechanisms": []},
            {"route": "/identity/api/auth/login", "api_signal": True, "content_type": "application/json", "forms": [], "auth_mechanisms": []},
            {"route": "/private", "auth_required": True, "content_type": "text/html", "forms": [], "auth_mechanisms": ["http-auth-challenge", "session-cookie:JSESSIONID"]},
            {"route": "/oauth/authorize", "redirect_target": "/oauth/callback", "forms": [], "auth_mechanisms": []},
        ],
    }
    detected = AuthDetector(target_url="http://example.test").detect(surface)
    types = {item.auth_type for item in detected.signals}
    assert {"form_session", "api_jwt", "basic", "oauth"} <= types
    assert detected.primary is not None
    assert "password" in detected.primary.login_fields["password_field"]


def test_login_executor_captures_and_validates_cookie_without_secret_serialization():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AuthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}"
        signal = AuthDetector(target_url=target).detect({"target_url": target, "routes": [{"route": "/login", "forms": [{"action": "/login", "method": "POST", "login_signal": True, "fields": [{"name": "user"}, {"name": "pass"}]}], "auth_mechanisms": []}]}).primary
        result = LoginExecutor(target_url=target).login(alias="owner", signal=signal, credentials={"username": "alice", "password": "correct", "protected_url": "/private"})
        assert result.success is True
        assert result.material is not None
        assert result.material.kind == "cookie"
        redacted = result.as_dict()
        assert "session-value" not in json.dumps(redacted)
        assert "correct" not in json.dumps(redacted)
        assert redacted["material"]["digest"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_api_login_executor_sends_json_email_password_shape_without_values(monkeypatch):
    captured = {}

    def handler(request):
        body = json.loads(request.content.decode("utf-8"))
        captured.update({"method": request.method, "path": request.url.path, "content_type": request.headers.get("content-type"), "keys": sorted(body), "value_lengths": {key: len(str(value)) for key, value in body.items()}})
        return httpx.Response(200, json={"authentication": {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"}})

    monkeypatch.setattr(login_executor_module, "make_safe_httpx_client", lambda **_kwargs: httpx.Client(transport=httpx.MockTransport(handler)))
    signal = AuthSignal(auth_type="api_jwt", login_url="http://example.test/rest/user/login", login_fields={"username_field": "email", "password_field": "password"}, token_type="jwt", token_capture="JSON token field")
    result = LoginExecutor(target_url="http://example.test").login(alias="owner", signal=signal, credentials={"username": "operator-email", "password": "operator-password"})
    assert result.success is True
    assert captured == {"method": "POST", "path": "/rest/user/login", "content_type": "application/json", "keys": ["email", "password"], "value_lengths": {"email": 14, "password": 17}}


def test_m4_attaches_basic_and_api_key_material_and_overwrites_forged_headers():
    authority = ContextAuthority(engagement_id="m4-prefix-test", target_fingerprint="target123")
    principal = PrincipalRef(principal_alias="owner", engagement_id="m4-prefix-test", target_fingerprint="target123", role=PrincipalRole.OWNER)
    context = AuthContextRef(context_ref="ctx_prefix", principal_ref=principal, decision_token_digest="digest", vault_bound_alias="owner")
    authority._vault_unseal = lambda _key: "basic:YWxpY2U6c2VjcmV0"  # type: ignore[method-assign]
    attached = authority.attach(context, {"headers": {"Authorization": "Bearer forged"}})
    assert attached["headers"]["Authorization"] == "Basic YWxpY2U6c2VjcmV0"
    authority._vault_unseal = lambda _key: "api-key:X-Test-Key=secret-value"  # type: ignore[method-assign]
    attached = authority.attach(context, {"headers": {"X-Test-Key": "forged"}})
    assert attached["headers"]["X-Test-Key"] == "secret-value"
    assert attached["_m4_vault_bound"] is True


def test_replan_is_explicit_and_capped_at_three_after_inconclusive():
    hypothesis = {
        "hypothesis": "bounded test",
        "target_endpoint": "/items/1",
        "attack_type": "IDOR",
        "priority": 90,
        "reasoning": "existing catalog route",
        "expected_behavior": "controlled differential",
    }
    attempts = []

    def exploit(h, _state):
        attempts.append(h.attempt)
        return ExploitationResult(h.hypothesis_id, HunterStatus.VALIDATING, True, True, evidence={"status_code": 401})

    def validate(h, _result, _state):
        return ValidationVerdict(h.hypothesis_id, Verdict.INCONCLUSIVE, 0.1, reason="candidate status category 401")

    hunter = HunterState(
        surface_data={"candidate_hypotheses": [hypothesis], "candidate_catalog": [{"route": "/items/1", "vulnerability_class": "IDOR"}]},
        budget=BudgetState(max_llm_calls=50, max_replans_per_hypothesis=3),
    )
    final = run_hunter_graph(hunter=hunter, exploiter=exploit, validator=validate)
    assert attempts == [0, 1, 2, 3]
    assert sum(event["node"] == "replan" for event in final.graph_events) == 3
    assert len(final.validation_verdicts) == 4
    assert all(
        "401" not in json.dumps({key: value for key, value in event.items() if key not in {"detail_digest", "at_monotonic"}})
        for event in final.graph_events
    )


def test_detector_exposes_generic_registration_route():
    detected = AuthDetector(target_url="http://example.test").detect({
        "target_url": "http://example.test",
        "routes": [{"route": "/account/registration", "method": "POST", "forms": [], "auth_mechanisms": []}],
    })
    assert detected.registration_urls == ("http://example.test/account/registration",)


def test_registration_executor_sends_bounded_json_without_serializing_values(monkeypatch):
    captured = {}

    def handler(request):
        body = json.loads(request.content.decode("utf-8"))
        captured.update({"method": request.method, "path": request.url.path, "keys": sorted(body), "lengths": {key: len(str(value)) for key, value in body.items()}})
        return httpx.Response(201, json={"status": "created"})

    monkeypatch.setattr(login_executor_module, "make_safe_httpx_client", lambda **_kwargs: httpx.Client(transport=httpx.MockTransport(handler)))
    executor = LoginExecutor(target_url="http://example.test")
    result = executor.register(
        alias="foreign",
        registration_url="http://example.test/api/register",
        credentials={"username": "operator-email", "password": "operator-password"},
        extra_fields={"role": "customer"},
    )
    assert result.success is True
    assert result.status_code == 201
    assert captured == {"method": "POST", "path": "/api/register", "keys": ["email", "password", "passwordRepeat", "role"], "lengths": {"email": 14, "password": 17, "passwordRepeat": 17, "role": 8}}
    assert "operator-password" not in json.dumps(result.as_dict())


def test_concrete_hydration_preserves_three_request_roles_and_redacts_auth_headers():
    from webpent.agents.hunter_contracts import PlannerHypothesis
    from webpent.agents.hunter_runner import (
        _hydrate_concrete_hypothesis,
        _normalize_family,
        _redacted_request_specs,
    )

    hypothesis = PlannerHypothesis("h1", "IDOR", "/api/items/1", "INFORMATION DISCLOSURE (ADMIN)", 90, "r", "e")
    candidate = {
        "hypothesis_id": "h_catalog",
        "vulnerability_class": "IDOR",
        "route": "/api/items/1",
        "parameter": "id",
        "metadata": {"owner_value": "1", "foreign_value": "2", "expected_success": "200 owner data"},
        "requests": {
            "baseline": {"method": "GET", "path": "/api/items/1", "principal_alias": "owner", "principal_role": "owner", "headers": {"Authorization": "Bearer secret"}},
            "candidate": {"method": "GET", "path": "/api/items/1", "principal_alias": "foreign", "principal_role": "foreign-user", "headers": {"Authorization": "Bearer secret"}},
            "negative_control": {"method": "GET", "path": "/api/items/999", "principal_alias": "foreign", "principal_role": "foreign-user"},
        },
    }
    concrete = _hydrate_concrete_hypothesis(hypothesis, candidate)
    assert _normalize_family("INFORMATION DISCLOSURE (ADMIN)") == "INFO_DISCLOSURE"
    assert concrete.method == "GET"
    assert set(concrete.requests) == {"baseline", "candidate", "negative_control"}
    redacted = _redacted_request_specs(concrete.requests)
    assert "Authorization" not in json.dumps(redacted)
    assert redacted["candidate"]["principal_alias"] == "foreign"


def test_decision_status_categories_do_not_turn_known_auth_failures_into_inconclusive():
    from webpent.agents.hunter_runner import _decision_verdict

    blocked, blocked_reason, *_ = _decision_verdict({"vulnerability_class": "IDOR", "proof_bundle": {"causal_oracle": {"baseline_access_result": 401, "candidate_access_result": 200, "negative_control_result": 404}}})
    refuted, refuted_reason, *_ = _decision_verdict({"vulnerability_class": "BOLA", "proof_bundle": {"causal_oracle": {"baseline_access_result": 200, "candidate_access_result": 403, "negative_control_result": 404}}})
    inconclusive, inconclusive_reason, *_ = _decision_verdict({"vulnerability_class": "IDOR", "proof_bundle": {"causal_oracle": {"baseline_access_result": 200, "candidate_access_result": 200, "negative_control_result": 200}}})
    assert blocked.value == "blocked" and "baseline" in blocked_reason
    assert refuted.value == "refuted" and "candidate" in refuted_reason
    assert inconclusive.value == "inconclusive" and "negative_control" in inconclusive_reason


def test_principal_target_fingerprint_matches_avi_canonical_binding():
    from webpent.models.evidence import sha256_text
    from webpent.recon.principal_provisioning import _target_fingerprint

    target = "http://127.0.0.1:3000"
    assert _target_fingerprint(target) == sha256_text(target)[:16]


def test_planner_provider_failure_falls_back_to_existing_catalog():
    candidate = {
        "hypothesis_id": "catalog-idor",
        "hypothesis": "catalog IDOR",
        "target_endpoint": "/items/1",
        "route": "/items/1",
        "attack_type": "IDOR",
        "vulnerability_class": "IDOR",
        "priority": 90,
        "reasoning": "existing governed candidate",
        "expected_behavior": "owner foreign differential",
        "method": "GET",
        "parameter_to_change": "id",
        "expected_success": "owner 200, foreign 200, control 404",
        "requests": {},
        "executable": True,
    }
    attempts = []

    def broken_planner(_messages):
        raise RuntimeError("provider_unavailable")

    def exploit(h, _state):
        attempts.append(h.hypothesis_id)
        return ExploitationResult(h.hypothesis_id, HunterStatus.VALIDATING, True, True)

    def validate(h, _result, _state):
        return ValidationVerdict(h.hypothesis_id, Verdict.REFUTED, 0.9, reason="catalog fallback exercised")

    final = run_hunter_graph(
        hunter=HunterState(surface_data={"candidate_catalog": [candidate]}, budget=BudgetState(max_llm_calls=5)),
        planner_llm=broken_planner,
        exploiter=exploit,
        validator=validate,
    )
    assert attempts == ["catalog-idor"]
    assert any(event["node"] == "planner_advisory_failed" for event in final.graph_events)


def test_canonical_finding_id_is_scoped_to_engagement_and_target():
    from webpent.production.autonomous_validation_v1 import _canonical_finding_id

    base = dict(
        hypothesis_id="h1",
        experiment_id="exp_idor",
        vulnerability_class="IDOR",
    )
    first = _canonical_finding_id(engagement_id="eng-a", target_fingerprint="target-a", **base)
    same = _canonical_finding_id(engagement_id="eng-a", target_fingerprint="target-a", **base)
    other_engagement = _canonical_finding_id(engagement_id="eng-b", target_fingerprint="target-a", **base)
    other_target = _canonical_finding_id(engagement_id="eng-a", target_fingerprint="target-b", **base)
    assert first == same
    assert first != other_engagement
    assert first != other_target
    assert first.startswith("finding_idor_")


def test_replan_replaces_actual_catalog_request_triple():
    first = {
        "hypothesis_id": "catalog-idor-1",
        "hypothesis": "first catalog IDOR",
        "target_endpoint": "/items/1",
        "route": "/items/1",
        "attack_type": "IDOR",
        "vulnerability_class": "IDOR",
        "priority": 90,
        "reasoning": "first candidate",
        "expected_behavior": "owner foreign differential",
        "method": "GET",
        "parameter_to_change": "id",
        "expected_success": "owner 200, foreign 200, control 404",
        "requests": {
            "baseline": {"method": "GET", "path": "/items/1", "principal_alias": "owner"},
            "candidate": {"method": "GET", "path": "/items/1", "principal_alias": "foreign"},
            "negative_control": {"method": "GET", "path": "/items/999", "principal_alias": "foreign"},
        },
        "executable": True,
    }
    second = {
        **first,
        "hypothesis_id": "catalog-idor-2",
        "hypothesis": "second catalog IDOR",
        "target_endpoint": "/items/2",
        "route": "/items/2",
        "requests": {
            "baseline": {"method": "GET", "path": "/items/2", "principal_alias": "owner"},
            "candidate": {"method": "GET", "path": "/items/2", "principal_alias": "foreign"},
            "negative_control": {"method": "GET", "path": "/items/998", "principal_alias": "foreign"},
        },
    }
    planner_calls = []
    executed = []

    def planner(_messages):
        planner_calls.append(True)
        if len(planner_calls) == 1:
            return json.dumps({"hypotheses": [{
                "hypothesis_id": "catalog-idor-1",
                "hypothesis": "first catalog IDOR",
                "target_endpoint": "/items/1",
                "attack_type": "IDOR",
                "priority": 90,
                "reasoning": "first candidate",
                "expected_behavior": "owner foreign differential",
                "requests": first["requests"],
            }]})
        return json.dumps({
            "hypothesis_id": "catalog-idor-2",
            "target_endpoint": "/items/2",
            "attack_type": "IDOR",
            "reasoning": "use the other observed catalog request",
            "expected_behavior": "compare the second observed resource",
        })

    def exploit(h, _state):
        executed.append((h.hypothesis_id, h.target_endpoint, h.requests))
        return ExploitationResult(h.hypothesis_id, HunterStatus.VALIDATING, True, True)

    def validate(h, _result, _state):
        verdict = Verdict.INCONCLUSIVE if len(executed) == 1 else Verdict.REFUTED
        return ValidationVerdict(h.hypothesis_id, verdict, 0.8, reason="bounded replan regression")

    final = run_hunter_graph(
        hunter=HunterState(
            surface_data={"candidate_catalog": [first, second]},
            budget=BudgetState(max_llm_calls=5, max_replans_per_hypothesis=3),
        ),
        planner_llm=planner,
        exploiter=exploit,
        validator=validate,
    )
    assert [(item[0], item[1]) for item in executed] == [
        ("catalog-idor-1", "/items/1"),
        ("catalog-idor-2", "/items/2"),
    ]
    assert executed[1][2]["candidate"]["path"] == "/items/2"
    assert sum(event["node"] == "replan" for event in final.graph_events) == 1


def test_promotion_rejects_forged_serialized_proof_bundle_signature():
    from webpent.production.autonomous_validation_v1 import PromotionPipeline

    forged = {
        "engagement_id": "eng-a",
        "finding_id": "finding-a",
        "sealed": True,
        "seal_digest": "sha256:" + ("0" * 64),
        "authenticity_tag": "hmac_sha256:forged",
        "evidence_refs": ["obs-a"],
        "evidence_digests": ["sha256:" + ("1" * 64)],
    }
    result = PromotionPipeline().evaluate(
        baseline_obs={"body_fingerprint": "b"},
        candidate_obs={"body_fingerprint": "c"},
        negative_control_obs={"body_fingerprint": "n"},
        evidence_origin="target_runtime",
        validator_outcome="CONFIRMED",
        evidence_quality=4,
        proof_bundle=forged,
        replay_verified=True,
        finding_id="finding-a",
        vulnerability_class="IDOR",
    )
    assert result.decision.value == "REJECTED"
    assert "proof_bundle_signed" in result.gates_failed
