from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from webpent.live_hunter.profile import build_authorized_lab_profile
from webpent.live_hunter.tool_scope import ScopeLaw
from webpent.production.context_authority import (
    AuthContextRef,
    ContextAuthority,
    ContextLifecycle,
    PrincipalRef,
    PrincipalRole,
)
from webpent.recon.autonomous_crawler import (
    AutonomousCrawler,
    CrawlConfig,
    RouteSurface,
    SurfaceForm,
    SurfaceMap,
    SurfaceParameter,
)
from webpent.recon.hypothesis_generator import HypothesisGenerator, _score


class _RedirectFormHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/":
            body = b""
            self.send_response(302)
            self.send_header("Location", "/login.php")
            self.send_header("Set-Cookie", "PHPSESSID=masked-session; Path=/")
        elif path == "/login.php":
            body = (
                b'<html><body><form action="/login.php" method="POST">'
                b'<input name="username" type="text"><input name="password" type="password">'
                b'<button type="submit">Login</button></form></body></html>'
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        else:
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def _server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectFormHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _scope(target: str) -> ScopeLaw:
    return ScopeLaw(
            # DR-007 (TC-2): lab_fixture_mode is REQUIRED for loopback
            # authorization since the GAP-4 fail-closed design; these are
            # genuine lab-fixture tests hitting ephemeral 127.0.0.1 servers.
        profile=build_authorized_lab_profile(
            engagement_id="generalization-fix-test",
            operator_approval_at="2026-10-01T00:00:00Z",
            authorized_targets=("127.0.0.1",),
            lab_fixture_mode=True,
        ),
        engagement_id="generalization-fix-test",
    )


def test_crawler_follows_same_origin_redirect_and_discovers_form_and_cookie_signal():
    server = _server()
    try:
        target = f"http://127.0.0.1:{server.server_port}/"
        result = AutonomousCrawler(
            target_url=target,
            scope_law=_scope(target),
            engagement_id="generalization-fix-test",
            config=CrawlConfig(max_pages=5, max_depth=2, per_host_min_interval_seconds=0),
        ).crawl()
        projection = result.as_dict()
        routes = {item["route"]: item for item in projection["routes"]}
        assert "/login.php" in routes
        assert routes["/"].get("redirect_target") == "/login.php"
        assert routes["/"].get("auth_mechanisms") == ["session-cookie:phpsessid"]
        assert routes["/login.php"]["forms"]
        assert routes["/login.php"]["forms"][0]["login_signal"] is True
        assert any(event["event"] == "redirect_queued" for event in projection["events"])
        assert "masked-session" not in json.dumps(projection)
    finally:
        server.shutdown()


def test_authorized_assessment_can_explicitly_override_target_robots_rules():
    server = _server()
    try:
        target = f"http://127.0.0.1:{server.server_port}/"
        result = AutonomousCrawler(
            target_url=target,
            scope_law=_scope(target),
            engagement_id="generalization-robots-override-test",
            config=CrawlConfig(
                max_pages=5,
                max_depth=2,
                per_host_min_interval_seconds=0,
                respect_robots=False,
            ),
        ).crawl()
        projection = result.as_dict()
        routes = {item["route"]: item for item in projection["routes"]}
        assert "/login.php" in routes
        assert not any(
            event["event"] == "url_skipped" and event["reason"].startswith("robots_")
            for event in projection["events"]
        )
    finally:
        server.shutdown()


def test_authentication_form_is_deferred_from_generic_injection_candidates():
    server = _server()
    try:
        target = f"http://127.0.0.1:{server.server_port}/"
        surface = AutonomousCrawler(
            target_url=target,
            scope_law=_scope(target),
            engagement_id="generalization-form-test",
            config=CrawlConfig(max_pages=5, max_depth=2, per_host_min_interval_seconds=0),
        ).crawl().surface_map
        hypotheses = HypothesisGenerator(max_hypotheses=50).generate(surface)
        login_hypotheses = [item for item in hypotheses if item["route"] == "/login.php"]
        assert login_hypotheses
        assert all(not item["executable"] for item in login_hypotheses)
        assert all(
            item["metadata"].get("deferred_reason") == "authentication_form_requires_separate_auth_flow"
            for item in login_hypotheses
        )
        assert all(item["requests"]["candidate"]["method"] == "POST" for item in login_hypotheses)
    finally:
        server.shutdown()


def test_generic_non_auth_post_form_generates_executable_sqli_and_xss_candidates():
    target = "http://127.0.0.1:18080"
    field = SurfaceParameter("comment", "body", "text-shaped", 0, "/feedback", "text")
    form = SurfaceForm(
        action=f"{target}/feedback", method="POST", fields=(field,),
        login_signal=False, source_route="/feedback",
    )
    route = RouteSurface(
        route="/feedback", method="GET", status_code=200, content_type="text/html",
        response_digest="digest", response_length=256, depth=1, auth_required=True,
        login_signal=False, api_signal=False, forms=(form,), execution_url=f"{target}/feedback",
    )
    surface = SurfaceMap(target_url=target, target_fingerprint="target", scope_fingerprint="scope", routes={"/feedback": route})

    hypotheses = HypothesisGenerator(max_hypotheses=50).generate(surface)
    injection_hypotheses = [
        item for item in hypotheses
        if item["route"] == "/feedback" and item["vulnerability_class"] in {"SQLI", "XSS"}
    ]

    assert injection_hypotheses
    assert all(item["executable"] for item in injection_hypotheses)
    assert all(item["requests"]["candidate"]["method"] == "POST" for item in injection_hypotheses)


def test_scoring_uses_surface_structure_not_target_route_names():
    parameter = SurfaceParameter("q", "query", "query-shaped", 0, "/anything", "text")
    common = dict(
        method="GET", status_code=200, content_type="text/html", response_digest="digest",
        response_length=100, depth=1, auth_required=False, login_signal=False, api_signal=False,
        parameters=(parameter,), execution_url="http://127.0.0.1:18080/anything",
    )
    route_a = RouteSurface(route="/products/search", **common)
    route_b = RouteSurface(route="/completely-different-name", **common)

    assert _score(route_a, "XSS", parameter) == _score(route_b, "XSS", parameter)


def test_m4_attaches_vault_bound_session_cookie_and_discards_caller_cookie():
    authority = ContextAuthority(engagement_id="cookie-test", target_fingerprint="target123")
    principal = PrincipalRef(
        principal_alias="owner",
        engagement_id="cookie-test",
        target_fingerprint="target123",
        role=PrincipalRole.OWNER,
    )
    context = AuthContextRef(
        context_ref="ctx_cookie",
        principal_ref=principal,
        decision_token_digest="digest",
        vault_bound_alias="owner",
    )
    authority._vault_unseal = lambda _key: "cookie:PHPSESSID=server-session"  # type: ignore[method-assign]
    request = {"headers": {"Cookie": "forged=1", "Authorization": "Bearer forged"}}
    attached = authority.attach(context, request)
    assert attached["headers"]["Cookie"] == "PHPSESSID=server-session"
    assert "Authorization" not in attached["headers"]
    assert attached["_m4_vault_bound"] is True
