from __future__ import annotations

import inspect
import httpx

from webpent.recon.hypothesis_generator import HypothesisGenerator
from webpent.recon.identity_discovery import IdentityDiscoverer


def test_dashboard_identity_discovery_returns_runtime_id_and_derived_template(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"].startswith("Bearer ")
        if request.url.path.endswith("/me"):
            return httpx.Response(404, json={"status": 404})
        if request.url.path.endswith("/current"):
            return httpx.Response(404, json={"status": 404})
        if request.url.path.endswith("/api/me"):
            return httpx.Response(404, json={"status": 404})
        if request.url.path == "/identity/api/v2/user/42":
            return httpx.Response(200, json={"id": 42})
        assert request.url.path == "/identity/api/v2/user/dashboard"
        return httpx.Response(200, json={"id": 42, "email": "operator@example.test", "video_id": 0})

    def governed_request(url: str) -> httpx.Response:
        request = httpx.Request("GET", url, headers={"Authorization": "Bearer m4-attached"})
        return handler(request)

    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner", request_callback=governed_request
    )
    assert result.success is True
    assert result.user_id == "42"
    assert result.source_url == "/identity/api/v2/user/dashboard"
    assert result.resource_templates == ("/identity/api/v2/user/{id}",)
    serialized = result.as_dict()
    assert serialized["user_id_present"] is True
    assert "runtime-token" not in str(serialized)
    assert "operator@example.test" not in str(serialized)


def test_identity_discovery_discards_unverified_self_endpoint_template():
    def governed_request(url: str) -> httpx.Response:
        if url.endswith("/identity/api/v2/user/dashboard"):
            return httpx.Response(200, json={"id": 42, "email": "operator@example.test"})
        if url.endswith("/identity/api/v2/user/42"):
            return httpx.Response(404, json={"status": 404})
        return httpx.Response(404, json={"status": 404})

    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner", request_callback=governed_request
    )
    assert result.success is True
    assert result.resource_templates == ()
    assert {item["path_template"] for item in result.attempts if "path_template" in item} == {"/identity/api/v2/user/{id}"}
    assert "42" not in str(result.as_dict())


def test_jwt_identity_fallback_accepts_numeric_subject_without_serializing_token(monkeypatch):
    def governed_request(_url: str) -> httpx.Response:
        return httpx.Response(404, json={"status": 404})

    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="foreign", request_callback=governed_request, identity_claims={"sub": "77"}
    )
    assert result.success is True
    assert result.user_id == "77"
    assert result.source_url == "jwt://claims"
    assert "m4-attached" not in str(result.as_dict())


def test_identity_discovery_matches_principal_in_user_collection(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/users":
            return httpx.Response(200, json={"data": [{"id": 5, "email": "other@example.test"}, {"id": 8, "email": "owner@example.test"}]})
        return httpx.Response(404, json={"status": 404})

    def governed_request(url: str) -> httpx.Response:
        return handler(httpx.Request("GET", url, headers={"X-User": "owner", "Authorization": "Bearer m4-attached"}))

    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner",
        request_callback=governed_request,
        candidate_paths=("/users",),
        principal_identifier="owner@example.test",
    )
    assert result.success is True
    assert result.user_id == "8"
    assert result.source_field == "id"


def test_identity_discovery_fails_closed_without_m4_callback():
    result = IdentityDiscoverer(target_url="http://example.test").discover(alias="owner")
    assert result.success is False
    assert result.reason == "m4_request_callback_required"


def test_identity_discoverer_has_no_raw_credential_attachment_surface():
    signature = inspect.signature(IdentityDiscoverer.discover)
    assert "material" not in signature.parameters
    assert "credentials" not in signature.parameters
    assert not hasattr(IdentityDiscoverer, "_attach_material")


def test_generator_uses_discovered_owner_id_and_derived_negative_control():
    generated = HypothesisGenerator(
        max_hypotheses=20,
        principal_count=2,
        principal_ids={"owner": "42", "foreign": "77"},
        principal_resource_templates=("/identity/api/v2/user/{id}",),
    )._build_identity_template_candidates(
        type("Surface", (), {"target_url": "http://example.test", "target_fingerprint": "target"})()
    )
    assert len(generated) == 1
    candidate = generated[0].as_dict()
    assert candidate["requests"]["baseline"]["path"] == "/identity/api/v2/user/42"
    assert candidate["requests"]["candidate"]["path"] == "/identity/api/v2/user/42"
    assert candidate["requests"]["negative_control"]["path"] == "/identity/api/v2/user/78"
    assert candidate["metadata"]["owner_value"] == "42"
    assert candidate["metadata"]["foreign_value"] == "77"
    assert "/identity/api/v2/user/1" not in str(candidate)


def test_live_generator_defers_access_control_when_identity_ids_are_missing():
    from webpent.recon.autonomous_crawler import RouteSurface, SurfaceMap, SurfaceParameter

    parameter = SurfaceParameter("id", "path", "id-shaped", 1, "/api/users/1")
    route = RouteSurface(
        route="/api/users/1", method="GET", status_code=200, content_type="application/json",
        response_digest="digest", response_length=20, depth=0, auth_required=True,
        login_signal=False, api_signal=True, parameters=(parameter,),
        execution_url="http://example.test/api/users/1",
    )
    surface = SurfaceMap(
        target_url="http://example.test", target_fingerprint="target", scope_fingerprint="scope",
        routes={route.route: route}, events=[],
    )
    candidates = HypothesisGenerator(principal_count=2, principal_ids={}).generate(surface)
    access = [item for item in candidates if item["vulnerability_class"] in {"IDOR", "BOLA"}]
    assert access
    assert all(item["executable"] is False for item in access)
    assert all("discovered identity IDs" in item["generation_reason"] for item in access)


def test_identifier_replacement_can_be_normalized_to_relative_path():
    from webpent.recon.hypothesis_generator import _relative_path, _replace_identifier_slot

    full = _replace_identifier_slot("http://example.test/rest/basket/1", "9")
    assert _relative_path(full) == "/rest/basket/9"
