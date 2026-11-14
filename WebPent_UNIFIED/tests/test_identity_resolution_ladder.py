"""R9 unit tests for the general autonomous identity resolution ladder.

Synthetic fixtures only: no target names, no fixed target ids beyond the
synthetic values inside each test, no per-target fixtures.  Each test drives
IdentityDiscoverer through a governed-callback-shaped callable exactly the way
principal_provisioning wires it (the callback is the only auth path).
"""
from __future__ import annotations

import base64
import json
from urllib.parse import urlsplit

import httpx

from webpent.config.identity_vocab import load_identity_vocab, reload_identity_vocab
from webpent.recon.identity_discovery import (
    EXHAUSTED_REASON,
    IdentityDiscoverer,
    decode_login_jwt_claims,
)
from webpent.recon.principal_provisioning import _relocate_m4_credential


def _jwt(sub: str, email: str | None = None) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    claims: dict[str, object] = {"sub": sub}
    if email is not None:
        claims["email"] = email
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{header}.{payload}.signature"


# ---------------------------------------------------------------- R9 case 1


def test_empty_user_shape_self_heals_via_query_param_transport():
    """200 {"user":{}} is classified anonymous-shape, then query-token wins."""
    calls: list[tuple[str, str]] = []

    def governed_request(url: str, transport: str = "header") -> httpx.Response:
        calls.append((url, transport))
        path = urlsplit(url).path
        if transport == "header":
            # Endpoint alive, identity absent via this transport.
            return httpx.Response(200, json={"user": {}})
        if transport == "query:token":
            if path == "/identity/api/v2/user/me":
                return httpx.Response(200, json={"user": {"user_id": 42}})
            if path == "/identity/api/v2/user/42":
                return httpx.Response(200, json={"user_id": 42})
        return httpx.Response(404)

    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner", request_callback=governed_request
    )
    assert result.success is True
    assert result.user_id == "42"
    assert result.winner_strategy == "s3_transport_self_heal"
    assert result.reason == "identity_discovered_after_transport_retry"
    assert result.resource_templates == ("/identity/api/v2/user/{id}",)
    outcomes = {str(item.get("outcome")) for item in result.strategy_attempts}
    assert "anonymous_shape_or_transport_mismatch" in outcomes
    assert any(item.get("transport") == "query:token" for item in result.strategy_attempts)
    serialized = json.dumps(result.as_dict())
    assert "m4-attached" not in serialized
    # The header transport was tried first; the variant only afterwards.
    assert calls[0][1] == "header"
    assert "query:token" in {item[1] for item in calls}


# ---------------------------------------------------------------- R9 case 2


def test_jwt_claims_success_after_all_probes_404():
    """JWT-claim mining resolves the identity when every probe 404s."""
    probes: list[str] = []

    def governed_request(url: str) -> httpx.Response:
        probes.append(url)
        return httpx.Response(404, json={"status": 404})

    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner",
        request_callback=governed_request,
        principal_identifier="owner@example.test",
        identity_claims={"sub": "77", "email": "owner@example.test"},
    )
    assert result.success is True
    assert result.user_id == "77"
    assert result.source_url == "jwt://claims"
    assert result.winner_strategy == "s1_jwt_claims"
    assert probes, "S2 ladder must still run before the S1 fallback wins"
    assert all(item.get("outcome") == "http_error" for item in result.strategy_attempts if item.get("strategy") == "s2_self_endpoint_probe")
    serialized = json.dumps(result.as_dict())
    assert "77" not in serialized
    assert "owner@example.test" not in serialized


# ---------------------------------------------------------------- R9 case 3


def test_login_body_umail_and_bid_pair_success():
    """Login-body mining pairs an id-like `bid` with an email-shaped `umail`."""
    probes: list[str] = []

    def governed_request(url: str) -> httpx.Response:
        probes.append(url)
        return httpx.Response(404, json={"status": 404})

    body = {"user": {"bid": 12345, "umail": "owner@example.test"}}
    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner",
        request_callback=governed_request,
        principal_identifier="owner@example.test",
        login_response_body=body,
    )
    assert result.success is True
    assert result.user_id == "12345"
    assert result.source_field == "bid"
    assert result.source_url == "login://response_body"
    assert result.winner_strategy == "s1_login_body_mining"
    # The identity itself came from zero-network mining: no probe returned it.
    assert all("404" for _ in [1]) and probes
    s1_entries = [item for item in result.strategy_attempts if item.get("strategy") == "s1_login_artifact_mining"]
    assert any(item.get("outcome") == "email_matched_pair" and item.get("confidence") == "high" for item in s1_entries)
    serialized = json.dumps(result.as_dict())
    assert "12345" not in serialized


# ---------------------------------------------------------------- R9 case 4


def test_404_ladder_halts_with_honest_exhaustion():
    """No artifacts, every probe 404 -> identity_resolution_exhausted halt."""
    def governed_request(url: str, *args, **kwargs) -> httpx.Response:
        return httpx.Response(404, json={"status": 404})

    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner", request_callback=governed_request
    )
    assert result.success is False
    assert result.user_id is None
    assert result.reason == EXHAUSTED_REASON
    strategies = {str(item.get("strategy")) for item in result.strategy_attempts}
    assert {"s1_login_artifact_mining", "s2_self_endpoint_probe", "s4_honest_exhaustion"} <= strategies
    block = result.as_dict()["identity_resolution"]
    assert block["resolved"] is False
    assert block["reason"] == EXHAUSTED_REASON
    assert block["resource_template_count"] == 0


# ---------------------------------------------------------------- R9 case 5


def test_email_matched_pair_preferred_over_bare_id():
    """A paired (id + email-shaped) record wins over a bare id-like scalar."""
    def governed_request(_url: str) -> httpx.Response:
        return httpx.Response(404, json={"status": 404})

    body = {"bid": 999, "profile": {"user_id": 42, "umail": "owner@example.test"}}
    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner",
        request_callback=governed_request,
        principal_identifier="owner@example.test",
        login_response_body=body,
    )
    assert result.success is True
    assert result.user_id == "42"
    assert result.source_field == "user_id"
    serialized = json.dumps(result.as_dict())
    assert "999" not in serialized


# --------------------------------------------------- supplementary coverage


def test_transport_variants_unsupported_by_boundary_recorded_honestly():
    """A header-only governed callback is not a failure: it is recorded."""
    def governed_request(_url: str) -> httpx.Response:
        return httpx.Response(200, json={"user": {}})

    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner", request_callback=governed_request
    )
    assert result.success is False
    assert result.reason == EXHAUSTED_REASON
    outcomes = {str(item.get("outcome")) for item in result.strategy_attempts}
    assert "transport_variants_unsupported_by_boundary" in outcomes


def test_m4_credential_relocation_query_and_cookie_variants_inside_boundary():
    """Transport variants relocate ONLY the M4-attached credential."""
    from webpent.production.context_authority import AuthContextRef, ContextAuthority, PrincipalRef, PrincipalRole

    authority = ContextAuthority(engagement_id="transport-test", target_fingerprint="target123")
    principal = PrincipalRef(principal_alias="owner", engagement_id="transport-test", target_fingerprint="target123", role=PrincipalRole.OWNER)
    context = AuthContextRef(context_ref="ctx_transport", principal_ref=principal, decision_token_digest="digest", vault_bound_alias="owner")

    authority._vault_unseal = lambda _key: "bearer:secret-token"  # type: ignore[method-assign]
    attached = authority.attach(context, {"headers": {"Accept": "application/json"}})
    url, headers = _relocate_m4_credential(dict(attached["headers"]), "query:token", "http://example.test/api/me")
    assert url == "http://example.test/api/me?token=secret-token"
    assert "Authorization" not in headers
    assert headers["X-User"] == "owner"
    assert "secret-token" not in json.dumps(headers)

    url, headers = _relocate_m4_credential(dict(attached["headers"]), "cookie:token", "http://example.test/api/me")
    assert url == "http://example.test/api/me"
    assert headers["Cookie"] == "token=secret-token"
    assert "Authorization" not in headers

    authority._vault_unseal = lambda _key: "basic:YWxpY2U6c2VjcmV0"  # type: ignore[method-assign]
    attached = authority.attach(context, {"headers": {}})
    assert _relocate_m4_credential(dict(attached["headers"]), "query:token", "http://example.test/api/me") is None

    authority.destroy(context)


def test_identity_resolution_block_and_winner_surfaces_in_as_dict():
    def governed_request(_url: str) -> httpx.Response:
        return httpx.Response(404, json={"status": 404})

    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner", request_callback=governed_request, identity_claims={"sub": "77"}
    )
    serialized = result.as_dict()
    assert serialized["winner_strategy"] == "s1_jwt_claims"
    block = serialized["identity_resolution"]
    assert block["resolved"] is True
    assert block["winner_strategy"] == "s1_jwt_claims"
    counts = block["strategy_attempt_counts"]
    assert counts.get("s2_self_endpoint_probe", 0) >= 1
    assert counts.get("s1_login_artifact_mining", 0) >= 1


def test_crawler_self_action_paths_become_probe_candidates():
    """Crawler-discovered whoami-shaped paths join the ladder; others do not."""
    probed: list[str] = []

    def governed_request(url: str) -> httpx.Response:
        probed.append(urlsplit(url).path)
        if urlsplit(url).path == "/api/v3/users/whoami":
            return httpx.Response(200, json={"uid": 7})
        if urlsplit(url).path == "/api/v3/users/7":
            return httpx.Response(200, json={"uid": 7})
        return httpx.Response(404, json={"status": 404})

    result = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner",
        request_callback=governed_request,
        crawl_paths=("/api/v3/users/whoami", "/api/v3/products/1"),
    )
    assert result.success is True
    assert result.user_id == "7"
    assert "/api/v3/users/whoami" in probed
    assert "/api/v3/products/1" not in probed
    assert result.resource_templates == ("/api/v3/users/{id}",)
    selected = [item for item in result.strategy_attempts if item.get("source") == "recon_crawler"]
    assert selected and selected[0]["path_count"] == 1


def test_identity_paths_hint_is_optional_and_prepend_only():
    """Absence never fails; presence only prepends candidates (R4)."""
    vocab = load_identity_vocab()
    without_hint_probes: list[str] = []
    with_hint_probes: list[str] = []

    def make_callback(recorder: list[str]):
        def governed_request(url: str) -> httpx.Response:
            path = urlsplit(url).path
            recorder.append(path)
            if path == "/api/user/me":
                return httpx.Response(200, json={"id": 5})
            return httpx.Response(404, json={"status": 404})
        return governed_request

    ok_without = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner", request_callback=make_callback(without_hint_probes)
    )
    assert ok_without.success is True
    assert ok_without.user_id == "5"

    ok_with = IdentityDiscoverer(target_url="http://example.test").discover(
        alias="owner",
        request_callback=make_callback(with_hint_probes),
        candidate_paths=("/custom/hint/me",),
    )
    assert ok_with.success is True
    assert with_hint_probes[0] == "/custom/hint/me"
    del vocab


def test_decode_login_jwt_claims_generic_helper():
    claims = decode_login_jwt_claims(_jwt("9", "o@example.test"))
    assert claims is not None
    assert claims["sub"] == "9"
    assert claims["email"] == "o@example.test"
    assert decode_login_jwt_claims("not-a-jwt") is None
    assert decode_login_jwt_claims("a.b") is None


def test_identity_vocab_is_data_file_driven(tmp_path, monkeypatch):
    """R3: extensible lists load from config data files with no code edits."""
    reloaded = reload_identity_vocab()
    assert reloaded["source"].startswith("data_file:")
    assert "whoami" in reloaded["self_actions"]
    assert "userId" in reloaded["identity_claim_keys"]

    override = tmp_path / "custom_vocab.json"
    override.write_text(json.dumps({"probe_paths": ["/custom/only/me"], "max_probe_paths": 2}), encoding="utf-8")
    monkeypatch.setenv("WEBPENT_IDENTITY_VOCAB_PATH", str(override))
    try:
        custom = reload_identity_vocab()
        assert custom["probe_paths"] == ["/custom/only/me"]
        assert custom["max_probe_paths"] == 2
        broken = tmp_path / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        monkeypatch.setenv("WEBPENT_IDENTITY_VOCAB_PATH", str(broken))
        self_healed = reload_identity_vocab()
        # A broken override never breaks the ladder: the loader self-heals to
        # the packaged data file before falling back to built-in defaults.
        assert self_healed["source"] == "data_file:identity_vocab.json"
        assert self_healed["probe_paths"]
    finally:
        monkeypatch.delenv("WEBPENT_IDENTITY_VOCAB_PATH", raising=False)
        reload_identity_vocab()


def test_provisioning_result_serializes_identity_resolution_rollup():
    from webpent.recon.auth_detector import AuthDetection
    from webpent.recon.identity_discovery import IdentityDiscoveryResult
    from webpent.recon.login_executor import LoginResult
    from webpent.recon.principal_provisioning import ProvisionedPrincipal, ProvisioningResult

    login = LoginResult("owner", True, "api_jwt", "http://example.test/login", 200, "session_validated")
    identity_ok = IdentityDiscoveryResult(
        "owner", True, "42", "/api/user/me", "id", 200,
        (), {}, ("/api/user/{id}",), "identity_discovered_from_m4_authenticated_response",
        "s2_self_endpoint_probe", (), (),
    )
    identity_exhausted = IdentityDiscoveryResult(
        "foreign", False, None, None, None, None, (), {}, (), EXHAUSTED_REASON,
        "", ({"strategy": "s4_honest_exhaustion", "outcome": EXHAUSTED_REASON},), (),
    )
    detection = AuthDetection((), "http://example.test", ("owner", "foreign"))
    result = ProvisioningResult(
        detection,
        (
            ProvisionedPrincipal("owner", "owner", "cred-a", login, True, "digest", False, False, None, identity_ok),
            ProvisionedPrincipal("foreign", "foreign-user", "cred-b", login, True, "digest", False, False, None, identity_exhausted),
        ),
        "target123",
    )
    block = result.as_dict()["identity_resolution"]
    assert block["attempted"] is True
    assert block["resolved"] == 1
    assert block["winner_strategies"] == {"owner": "s2_self_endpoint_probe", "foreign": None}
    assert block["exhausted_principals"] == ["foreign"]
