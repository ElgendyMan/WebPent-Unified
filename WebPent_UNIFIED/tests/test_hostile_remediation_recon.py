from __future__ import annotations

from webpent.recon.autonomous_crawler import RouteSurface, SurfaceForm, SurfaceMap, SurfaceParameter
from webpent.recon.hypothesis_generator import HypothesisGenerator


def _surface(route: RouteSurface) -> SurfaceMap:
    return SurfaceMap(
        target_url="http://127.0.0.1:8000/",
        target_fingerprint="sha256:" + "a" * 64,
        scope_fingerprint="scope",
        routes={route.route: route},
    )


def test_post_form_preserves_method_and_body_location() -> None:
    field = SurfaceParameter("name", "body", "text-shaped", 4, "/profile")
    form = SurfaceForm("/profile/update", "POST", (field,), False, "/profile")
    route = RouteSurface(
        route="/profile", method="GET", status_code=200, content_type="text/html",
        response_digest="sha256:" + "b" * 64, response_length=20, depth=0,
        auth_required=True, login_signal=False, api_signal=False, forms=(form,),
        execution_url="http://127.0.0.1:8000/profile",
    )
    hypotheses = HypothesisGenerator(principal_count=2).generate(_surface(route))
    xss = next(item for item in hypotheses if item["vulnerability_class"] == "XSS")
    assert xss["requests"]["candidate"]["method"] == "POST"
    assert xss["requests"]["candidate"]["parameter_location"] == "body"
    assert xss["requests"]["candidate"]["body"] == {"name": "webpent_xss_probe_7f1"}
    assert xss["requests"]["candidate"]["path"] == "/profile/update"
    # A non-login POST form is a structurally observed input surface.  Scope
    # authorization still gates runtime execution; discovery must not suppress
    # a generic candidate solely because it uses a request body.
    assert xss["executable"] is True


def test_query_url_parameter_generates_open_redirect_and_ssrf_candidates() -> None:
    parameter = SurfaceParameter("next_url", "query", "url-shaped", 20, "/redirect")
    route = RouteSurface(
        route="/redirect", method="GET", status_code=200, content_type="application/json",
        response_digest="sha256:" + "c" * 64, response_length=20, depth=0,
        auth_required=False, login_signal=False, api_signal=True, parameters=(parameter,),
        execution_url="http://127.0.0.1:8000/redirect?next_url=https%3A%2F%2Ftrusted.example",
    )
    hypotheses = HypothesisGenerator().generate(_surface(route))
    families = {item["vulnerability_class"] for item in hypotheses}
    assert "OPEN_REDIRECT" in families
    assert "SSRF" in families
    ssrf = next(item for item in hypotheses if item["vulnerability_class"] == "SSRF")
    assert ssrf["requests"]["candidate"]["method"] == "GET"
    assert "next_url=" in ssrf["requests"]["candidate"]["path"]


def test_bola_is_deferred_without_two_principals_and_executable_with_two() -> None:
    parameter = SurfaceParameter("user_id", "path", "id-shaped", 1, "/api/users/1")
    route = RouteSurface(
        route="/api/users/1", method="GET", status_code=200, content_type="application/json",
        response_digest="sha256:" + "d" * 64, response_length=20, depth=0,
        auth_required=True, login_signal=False, api_signal=True, parameters=(parameter,),
        execution_url="http://127.0.0.1:8000/api/users/1",
    )
    deferred = HypothesisGenerator(principal_count=0).generate(_surface(route))
    bola_deferred = next(item for item in deferred if item["vulnerability_class"] == "BOLA")
    assert bola_deferred["executable"] is False
    assert "two authenticated principals" in bola_deferred["generation_reason"]

    ready = HypothesisGenerator(principal_count=2).generate(_surface(route))
    bola_ready = next(item for item in ready if item["vulnerability_class"] == "BOLA")
    assert bola_ready["executable"] is True
    assert bola_ready["required_principal_mode"] == "two_principal"
