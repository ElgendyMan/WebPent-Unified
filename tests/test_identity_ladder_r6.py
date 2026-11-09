"""r6c identity-ladder tests (S1-S4) for the General Identity Resolution Ladder.

Gap coverage (r5 LAB evidence):
- S1 zero-network mining of login artifacts, BOTH branches always recorded,
  values never serialized (digests/names only).
- ``bid``-style short numeric resource keys become resource seeds, never
  identities.
- whoami-family conventions sit inside the bounded probe window (cap 16).
- anonymous-shape self answers fire the S3 transport self-heal; 200-HTML SPA
  catch-alls are classified (spa_catch_all_html) without starving the ladder.
- S4 records honest exhaustion; attempt records are path-only.
"""

from __future__ import annotations

import base64
import json

import httpx

from webpent.recon.identity_discovery import (
    IdentityDiscoverer,
    _decode_jwt_claims,
    decode_jwt_claims,
)


def _jwt(payload: dict) -> str:
    head = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{head}.{body}.signature"


def _all_404(url: str) -> httpx.Response:
    return httpx.Response(404, json={"status": 404})


def _exhausted_result(**kwargs) -> object:
    return IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner", request_callback=_all_404, **kwargs
    )


def test_s1_jwt_branch_resolves_and_records_attempt():
    def recorder(url: str, calls: list | None = None):
        # P2-203 triage (B006): fresh list per call instead of a shared
        # mutable default; assertions in this test read result.attempts,
        # never `calls`.
        if calls is None:
            calls = []
        calls.append(url)
        return _all_404(url)

    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner",
        request_callback=recorder,
        identity_claims={"userId": "7", "email": "owner@example.test"},
    )
    assert result.success is True
    assert result.user_id == "7"
    assert result.source_url == "jwt://claims"
    assert result.winner_strategy == "s1_jwt_claims"
    jwt_attempts = [item for item in result.attempts if item.get("branch") == "jwt_claims"]
    assert len(jwt_attempts) == 1
    assert jwt_attempts[0]["attempted"] is True
    assert jwt_attempts[0]["resolved"] is True
    assert jwt_attempts[0]["resolved_key"] == "userId"
    assert "owner@example.test" not in str(result.as_dict())
    assert result.as_dict()["user_id_present"] is True


def test_s1_records_both_branch_attempts_even_when_body_and_claims_absent():
    result = _exhausted_result()
    assert result.success is False
    assert result.reason == "identity_resolution_exhausted"
    branches = {item.get("branch"): item for item in result.attempts if item.get("stage") == "s1"}
    assert set(branches) == {"jwt_claims", "login_body"}
    assert branches["jwt_claims"]["attempted"] is False
    assert branches["jwt_claims"]["resolved"] is False
    assert branches["login_body"]["attempted"] is True
    assert branches["login_body"]["resolved"] is False
    assert branches["login_body"]["payload_type"] == "absent"


def test_s1_body_branch_records_mapping_body_and_merges_seeds_into_resource_ids():
    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner",
        request_callback=_all_404,
        login_response_body={"authentication": {"token": "RUNTIME-TOKEN-MARKER", "bid": 2}},
    )
    assert result.success is False
    assert result.reason == "identity_resolution_exhausted"
    body_attempt = next(item for item in result.attempts if item.get("branch") == "login_body")
    assert body_attempt["payload_type"] == "mapping"
    assert body_attempt["resource_seed_count"] == 1
    assert body_attempt["resource_seed_names"] == ["bid"]
    assert result.user_id is None
    assert result.resource_ids == {"bid": "2"}
    serialized = str(result.as_dict())
    assert "RUNTIME-TOKEN-MARKER" not in serialized
    assert "'bid': '2'" not in serialized  # seed names yes, seed values never


def test_s1_bid_style_key_is_resource_seed_never_identity():
    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner",
        request_callback=_all_404,
        login_response_body={"bid": 2, "cart_id": 5, "email": "owner@example.test"},
    )
    assert result.success is False
    assert result.user_id is None
    assert result.winner_strategy == ""
    assert result.resource_ids == {"bid": "2", "cart_id": "5"}
    assert result.resource_ids.get("bid") != result.user_id


def test_s1_email_matched_id_resolves_identity_with_zero_probes():
    calls: list[str] = []

    def recorder(url: str) -> httpx.Response:
        calls.append(url)
        return _all_404(url)

    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner",
        request_callback=recorder,
        principal_identifier="owner@example.test",
        login_response_body={"data": [{"id": 11, "email": "owner@example.test"}]},
    )
    assert result.success is True
    assert result.user_id == "11"
    assert result.source_field == "id"
    assert result.winner_strategy == "s1_login_body_mining"
    assert calls == []  # zero-network win path


def test_whoami_sits_inside_the_bounded_probe_window():
    junk = tuple(f"/convention/{index}" for index in range(12))
    probed: list[str] = []

    def handler(url: str) -> httpx.Response:
        probed.append(url)
        path = httpx.Request("GET", url).url.path
        if path == "/whoami":
            return httpx.Response(200, json={"user": {"id": 9, "email": "owner@example.test"}})
        return httpx.Response(404, json={"status": 404})

    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner", request_callback=handler, candidate_paths=junk
    )
    assert result.success is True
    assert result.user_id == "9"
    assert result.source_url == "/whoami"
    assert result.winner_strategy == "s2_self_endpoint_probe"
    assert any(item.get("path") == "/whoami" for item in result.attempts)
    assert len(probed) <= 17  # 12 candidates + whoami resolution, inside cap 16 window


def test_anonymous_shape_on_whoami_fires_s3_transport_self_heal():
    def handler(url: str) -> httpx.Response:
        path = httpx.Request("GET", url).url.path
        if path == "/whoami":
            return httpx.Response(200, json={"user": {}})
        if path == "/whoami/":
            return httpx.Response(200, json={"user": {"id": 9, "email": "owner@example.test"}})
        return httpx.Response(404, json={"status": 404})

    result = IdentityDiscoverer(target_url="http://example.test").discover(alias="owner", request_callback=handler)
    assert result.success is True
    assert result.user_id == "9"
    assert result.winner_strategy == "s3_transport_self_heal"
    assert result.source_url == "/whoami/"
    anonymous = [item for item in result.attempts if item.get("result") == "anonymous_shape_observed"]
    assert any(item.get("path") == "/whoami" for item in anonymous)


def test_spa_catch_all_html_is_classified_and_probing_continues():
    def handler(url: str) -> httpx.Response:
        path = httpx.Request("GET", url).url.path
        if path == "/whoami":
            return httpx.Response(200, text="<html><body>spa-shell</body></html>")
        if path == "/api/me":
            return httpx.Response(200, json={"id": 3, "email": "owner@example.test"})
        return httpx.Response(404, json={"status": 404})

    result = IdentityDiscoverer(target_url="http://example.test").discover(alias="owner", request_callback=handler)
    assert result.success is True
    assert result.user_id == "3"
    assert result.winner_strategy == "s2_self_endpoint_probe"
    catch_all = [item for item in result.attempts if item.get("result") == "spa_catch_all_html"]
    assert any(item.get("path") == "/whoami" for item in catch_all)
    assert any(
        item.get("path") == "/api/me" and item.get("result") == "json_identity_resolved" for item in result.attempts
    )


def test_s4_exhaustion_carries_all_stage_attempts_and_path_only_records():
    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner",
        request_callback=_all_404,
        identity_claims=None,
        login_response_body={"bid": 2},
    )
    assert result.success is False
    assert result.reason == "identity_resolution_exhausted"
    # Both S1 branches are present even on honest exhaustion...
    branches = {item.get("branch") for item in result.attempts if item.get("stage") == "s1"}
    assert branches == {"jwt_claims", "login_body"}
    # ...and the S2 conventions were probed with path-only records.
    s2_probes = [item for item in result.attempts if item.get("result") == "http_status"]
    assert s2_probes, "expected probed convention paths"
    assert all(set(item) == {"path", "status_code", "result"} for item in s2_probes)
    for item in result.attempts:
        assert "token" not in json.dumps(item)
        assert set(item) <= {
            "stage",
            "branch",
            "attempted",
            "resolved",
            "resolved_key",
            "payload_type",
            "resource_seed_count",
            "resource_seed_names",
            "path",
            "path_template",
            "status_code",
            "result",
        }


def test_attempt_records_never_carry_mined_values():
    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner",
        request_callback=_all_404,
        identity_claims={"sub": "77"},
        login_response_body={"token": "SUPER-SECRET-VALUE-MARKER", "user_id": 5},
    )
    serialized = str(result.as_dict())
    assert "SUPER-SECRET-VALUE-MARKER" not in serialized
    assert result.user_id == "77"  # jwt branch (A) resolves before body branch (B)
    body_attempt = next(item for item in result.attempts if item.get("branch") == "login_body")
    assert body_attempt["resolved"] is True  # body branch did resolve; jwt precedence won
    assert body_attempt["resolved_key"] == "user_id"
    assert body_attempt["resource_seed_names"] == []
    assert result.winner_strategy == "s1_jwt_claims"  # jwt branch runs first


def test_winner_strategy_is_serialized():
    def handler(url: str) -> httpx.Response:
        path = httpx.Request("GET", url).url.path
        if path == "/whoami":
            return httpx.Response(200, json={"user": {"id": 9}})
        return httpx.Response(404, json={"status": 404})

    resolved = IdentityDiscoverer(target_url="http://example.test").discover(alias="owner", request_callback=handler)
    assert resolved.as_dict()["winner_strategy"] == "s2_self_endpoint_probe"
    exhausted = _exhausted_result()
    assert exhausted.as_dict()["winner_strategy"] == ""


def test_probe_and_serialization_bounds_are_respected():
    def handler(url: str) -> httpx.Response:
        return httpx.Response(200, json={"user": {}})  # every convention anonymous

    junk = tuple(f"/convention/{index}" for index in range(40))
    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner", request_callback=handler, candidate_paths=junk
    )
    probed = [item for item in result.attempts if item.get("stage") == "s2" or ("path" in item and "stage" not in item)]
    assert len(probed) <= 16  # max_probe_paths clamp window (bounds block)
    assert len(result.attempts) <= 48  # internal attempts cap
    assert len(result.as_dict()["attempts"]) <= 32  # serialized attempts bound (was 8)


def test_seeds_flow_to_resource_ids_but_never_to_user_id():
    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner",
        request_callback=_all_404,
        login_response_body={"basket": {"bid": 2, "row_id": 9}},
    )
    assert result.user_id is None
    assert result.resource_ids == {"bid": "2", "row_id": "9"}
    assert result.as_dict()["resource_id_names"] == ["bid", "row_id"]
    assert result.as_dict()["user_id_present"] is False


def test_decode_jwt_claims_public_alias_works():
    token = _jwt({"sub": "77", "userId": "7"})
    claims = decode_jwt_claims(token)
    assert claims == {"sub": "77", "userId": "7"}
    assert _decode_jwt_claims(token) == claims
    assert decode_jwt_claims("not-a-jwt") is None
    assert decode_jwt_claims("a.b.c") is None


def test_provisioning_result_identity_resolution_block_shape():
    from webpent.recon.auth_detector import AuthDetection, AuthSignal
    from webpent.recon.identity_discovery import IdentityDiscoveryResult
    from webpent.recon.login_executor import LoginResult
    from webpent.recon.principal_provisioning import ProvisionedPrincipal, ProvisioningResult

    signal = AuthSignal(auth_type="api_jwt", login_url="/login", token_type="jwt")
    detection = AuthDetection((signal,), "http://example.test", ("owner",))
    ok_login = LoginResult("owner", True, "api_jwt", "/login", 200, "jwt_login_response_validated")
    resolved_identity = IdentityDiscoveryResult(
        "owner", True, "9", "/whoami", "id", 200, (), {}, (), "ok", "s2_self_endpoint_probe"
    )
    exhausted_identity = IdentityDiscoveryResult(
        "foreign", False, None, None, None, None, (), {}, (), "identity_resolution_exhausted", ""
    )
    result = ProvisioningResult(
        detection,
        (
            ProvisionedPrincipal(
                "owner",
                "owner",
                "cred-owner",
                ok_login,
                True,
                "digest",
                False,
                False,
                None,
                resolved_identity,
            ),
            ProvisionedPrincipal(
                "foreign",
                "foreign_user",
                "cred-foreign",
                ok_login,
                True,
                "digest",
                False,
                False,
                None,
                exhausted_identity,
            ),
        ),
        "fingerprint",
        "test",
    )
    block = result.identity_resolution
    assert block["attempted"] is True
    assert block["resolved"] == 1
    assert block["winner_strategies"] == {"owner": "s2_self_endpoint_probe", "foreign": None}
    assert block["s4_honest_exhaustion"] == 1
    assert result.as_dict()["identity_resolution"] == block
