"""UM-DR-41 §5 (Phase 1) — P0 correctness regression tests.

Every test here reproduces a defect confirmed against the UMDR40 baseline
(86e5861) and pins the fix:

* §5.1  principal provisioning ``detected_type`` UnboundLocalError /
        stale per-iteration state.
* §5.2  OAuth ``attacker_redirect_uri.lstrip('https://')`` hostname
        corruption + missing query percent-encoding.
* §5.3  runtime annotation resolution (``get_type_hints``) failures in
        legacy_disposition / cve_advisory / generic_web_contracts /
        production_spine.
* §5.4  UnifiedLogger calling-contract integrity (custom logger, not a
        logging.Logger).

All tests are offline (no network, no provider).
"""
from __future__ import annotations

import typing
from urllib.parse import parse_qsl, urlsplit

import pytest

from webpent.recon.auth_detector import AuthDetector
from webpent.recon.principal_provisioning import PrincipalProvisioner


# ---------------------------------------------------------------------------
# §5.1 — detected_type provisioning correctness
# ---------------------------------------------------------------------------

def _form_detection() -> AuthDetector.__annotations__ and None:
    return AuthDetector(target_url="http://t.local").detect({
        "routes": [{"route": "/login",
                    "forms": [{"login_signal": True, "fields": []}]}]
    })


def test_5_1_first_principal_unsupported_auth_no_crash():
    """The original defect: first principal with an unsupported auth type
    read ``detected_type`` before assignment -> UnboundLocalError."""
    result = PrincipalProvisioner(
        target_url="http://t.local", engagement_id="umdr41-e1"
    ).provision(
        {"owner": {"auth_type": "magic_sso",
                   "username": "a", "password": "b"}},
        detection=_form_detection(),
    )
    assert result.principals, "a principal record must exist"
    record = result.principals[0]
    assert record.login.success is False
    assert record.login.reason == "unsupported_auth_type"
    assert record.requested_auth_type == "magic_sso"
    assert record.detected_auth_type == "form_session"


def test_5_1_unsupported_after_supported_keeps_own_values():
    """An unsupported principal AFTER a supported one must not inherit a
    stale loop-carried value; both record their own correct pair."""
    result = PrincipalProvisioner(
        target_url="http://t.local", engagement_id="umdr41-e2"
    ).provision(
        [
            {"name": "a", "auth_type": "form_session",
             "username": "a", "password": "b"},
            {"name": "b", "auth_type": "saml"},
        ],
        detection=_form_detection(),
    )
    assert len(result.principals) == 2
    first, second = result.principals
    assert first.requested_auth_type == "form_session"
    assert first.detected_auth_type == "form_session"
    assert second.requested_auth_type == "saml"
    assert second.detected_auth_type == "form_session"
    assert second.login.reason == "unsupported_auth_type"


def test_5_1_multiple_unsupported_principals_all_recorded():
    result = PrincipalProvisioner(
        target_url="http://t.local", engagement_id="umdr41-e3"
    ).provision(
        [
            {"name": "a", "auth_type": "magic"},
            {"name": "b", "auth_type": "saml"},
            {"name": "c", "auth_type": "webauthn"},
        ],
        detection=_form_detection(),
    )
    assert len(result.principals) == 3
    for record, expected in zip(result.principals,
                                ("magic", "saml", "webauthn")):
        assert record.requested_auth_type == expected
        assert record.login.reason == "unsupported_auth_type"
        assert record.login.success is False
        assert record.detected_auth_type == "form_session"


def test_5_1_missing_detected_auth_falls_back_to_detection_primary():
    """No detected signal at all -> the unsupported record still carries
    the detection primary (empty when the detection is empty), never an
    UnboundLocalError nor an inherited previous-iteration value."""
    detection = AuthDetector(target_url="http://t.local").detect({})
    result = PrincipalProvisioner(
        target_url="http://t.local", engagement_id="umdr41-e4"
    ).provision(
        {"owner": {"auth_type": "magic", "username": "a", "password": "b"}},
        detection=detection,
    )
    # no signals -> provisioning refuses for a different reason first
    assert result.reason in {
        "no_auth_signal_detected", "no_primary_auth_signal",
    } or result.principals
    if result.principals:
        assert result.principals[0].detected_auth_type in ("", "none")


def test_5_1_requested_vs_detected_distinction_preserved():
    """Configured type different from detected type stays distinguishable
    (r9 D3 contract preserved by the fix)."""
    result = PrincipalProvisioner(
        target_url="http://t.local", engagement_id="umdr41-e5"
    ).provision(
        {"owner": {"auth_type": "kerberos",
                   "username": "a", "password": "b"}},
        detection=_form_detection(),
    )
    record = result.principals[0]
    assert record.requested_auth_type == "kerberos"
    assert record.detected_auth_type == "form_session"
    assert record.requested_auth_type != record.detected_auth_type


# ---------------------------------------------------------------------------
# §5.2 — OAuth redirect URI construction
# ---------------------------------------------------------------------------

class _Candidate:
    """FamilyCandidate stand-in with the fields build_oauth_plan reads."""

    candidate_id = "c-umdr41"
    scenario_id = "S-umdr41"


def _plan(variant: str, uri: str):
    from webpent.families.execution_plans import build_oauth_plan
    return build_oauth_plan(
        _Candidate(),
        authorize_url="https://idp.authorize.test/authorize",
        client_id="client-«id»&x=1",  # reserved chars in OTHER params too
        attacker_redirect_uri=uri,
        bypass_variant=variant,
    )


def _redirect_param(url: str) -> str:
    query = dict(parse_qsl(urlsplit(url).query))
    return query["redirect_uri"]


def test_5_2_hostname_initial_letters_preserved():
    """h/t/p/s-prefixed hostnames: lstrip('https://') ate their first
    letters; the parsed fix must keep every hostname intact."""
    for host in ("hacker.example", "tacker.example",
                 "picker.example", "sacker.example"):
        uri = f"https://{host}/cb"
        for variant in ("suffix", "userinfo", "path_traversal"):
            redirect = _redirect_param(_plan(variant, uri).discriminator[0].url)
            assert host in redirect, (
                f"{variant}: hostname {host} corrupted in {redirect!r}")
            # the composed host component must contain the FULL hostname
            # (an lstrip-corrupted 'hacker.example' would appear as
            # 'acker.example' — a proper subset missing its first char)
            composed_host = urlsplit(redirect).hostname or ""
            assert host in composed_host or host in (
                urlsplit(redirect).path or "")


def test_5_2_http_and_https_origins_supported():
    for scheme in ("http", "https"):
        redirect = _redirect_param(
            _plan("suffix", f"{scheme}://evil.example/cb").discriminator[0].url)
        assert redirect.startswith("https://legit.com.evil.example")


def test_5_2_ports_and_paths_round_trip():
    redirect = _redirect_param(
        _plan("suffix", "http://evil.example:8080/a/b?k=v").discriminator[0].url)
    assert redirect == "https://legit.com.evil.example:8080/a/b"
    redirect = _plan(
        "userinfo", "https://evil.example:9443/x").discriminator[0].url
    assert _redirect_param(redirect) == "https://legit.com@evil.example:9443/x"


def test_5_2_ipv4_ipv6_representations():
    from webpent.families.execution_plans import _attacker_origin
    assert _attacker_origin("http://192.168.1.5:9000/x") == "192.168.1.5:9000"
    # RFC 3986: bracketed IPv6 literal survives into the composed origin
    assert _attacker_origin("https://[2001:db8::1]/cb") == "[2001:db8::1]"


def test_5_2_invalid_schemes_and_missing_host_rejected():
    from webpent.families.execution_plans import _attacker_origin
    for bad in ("file:///etc/passwd", "ftp://x/y", "not a url",
                "https://", "", "https:///cb"):
        assert _attacker_origin(bad) == "", f"{bad!r} must not yield an origin"


def test_5_2_userinfo_does_not_leak_into_composed_origin():
    from webpent.families.execution_plans import _attacker_origin
    origin = _attacker_origin("https://user:pass@evil.example/cb")
    assert "user" not in origin and "pass" not in origin
    assert origin == "evil.example"


def test_5_2_query_parameters_percent_encoded_once():
    """A redirect_uri containing reserved query characters must survive
    as ONE parameter value (no query splitting, no double encoding)."""
    plan = _plan("subdomain", "https://evil.example/cb?next=/a&b=c")
    url = plan.discriminator[0].url
    params = dict(parse_qsl(urlsplit(url).query))
    # the attacker URI's own query is intentionally NOT carried into the
    # composed redirect (only origin+path are), and the reserved chars
    # "&b=c" must not split the AUTHORIZE query — exactly one
    # redirect_uri key exists.
    assert list(params).count("redirect_uri") == 1
    assert params["redirect_uri"] == "https://evil.example.legit.com/cb"
    assert params["response_type"] == "code"
    assert params["scope"] == "openid"
    # the attacker-controlled client_id is encoded too
    assert params["client_id"] == "client-«id»&x=1"


def test_5_2_negative_control_semantics_unchanged():
    plan = _plan("prefix", "https://evil.example/cb")
    negative = plan.negative_control[0]
    # the negative's redirect_uri is percent-encoded now (the fix); parse
    # the query and compare the decoded value instead of the raw substring
    n_params = dict(parse_qsl(urlsplit(negative.url).query))
    assert n_params["redirect_uri"] == (
        "https://registered-callback.legit.com/callback")
    # state round-trips identically between discriminator and control
    d_state = dict(parse_qsl(urlsplit(plan.discriminator[0].url).query))["state"]
    n_state = dict(parse_qsl(urlsplit(negative.url).query))["state"]
    assert d_state == n_state
    assert plan.post_state_check is not None
    assert plan.post_state_check.url == "https://evil.example/cb"


# ---------------------------------------------------------------------------
# §5.3 — runtime annotation resolution
# ---------------------------------------------------------------------------

def test_5_3_legacy_disposition_annotations_resolve():
    import webpent.shared.legacy_disposition as ld
    typing.get_type_hints(ld.classify)
    typing.get_type_hints(ld.archive_plan)


def test_5_3_cve_advisory_hypothesis_forward_ref_resolves():
    import webpent.shared.cve_advisory as ca
    hints = typing.get_type_hints(ca.advisory_hypothesis_to_state_hypothesis)
    assert hints["return"] is not None


def test_5_3_generic_web_contracts_lifecycle_resolves():
    import webpent.shared.generic_web_contracts as g
    typing.get_type_hints(g.LifecycleStageResult)


def test_5_3_production_trace_class_hints_resolve():
    import webpent.production.production_spine as ps
    typing.get_type_hints(ps.ProductionTrace)
    assert ps.ProductionTrace.MAX_STAGES == 50


def test_5_3_no_import_cycle_introduced():
    """The direct imports added for resolution must not create cycles."""
    import webpent.shared.cve_advisory  # noqa: F401
    import webpent.shared.generic_web_contracts  # noqa: F401
    import webpent.shared.verifier  # noqa: F401
    import webpent.models.hypothesis  # noqa: F401


# ---------------------------------------------------------------------------
# §5.4 — UnifiedLogger calling convention
# ---------------------------------------------------------------------------

def test_5_4_logger_warn_error_log_contract():
    from webpent.verification.robust import UnifiedLogger
    logger = UnifiedLogger()
    entry = logger.warn("mod", "something")
    assert entry == "[WARN] mod: something"
    assert logger.entries[-1] == entry
    assert logger.error("mod", "bad") == "[ERROR] mod: bad"
    assert logger.log("info", "m", "x") == "[INFO] m: x"
    # unknown level falls back to INFO, never raises
    assert logger.log("nope", "m", "x") == "[INFO] m: x"


def test_5_4_logger_stdlib_aliases_same_arity():
    from webpent.verification.robust import UnifiedLogger
    logger = UnifiedLogger()
    assert logger.warning("m", "x") == "[WARN] m: x"
    assert logger.critical("m", "x") == "[CRITICAL] m: x"
    assert logger.info("m", "x") == "[INFO] m: x"
    assert logger.debug("m", "x") == "[DEBUG] m: x"


def test_5_4_logger_wrong_arity_fails_loudly():
    """A caller assuming logging.Logger arity (message only, no module)
    must get a TypeError, not a silently mis-filed entry. Two positional
    args are ambiguous by design — the arity contract is exactly two."""
    from webpent.verification.robust import UnifiedLogger
    logger = UnifiedLogger()
    with pytest.raises(TypeError):
        logger.warning("just a message")          # 1 arg: missing module
    with pytest.raises(TypeError):
        logger.log("WARN", "mod", "msg", "extra")  # 4 args: too many
    # keyword misuse is equally loud
    with pytest.raises(TypeError):
        logger.warning(msg="x")                    # no module position


def test_5_4_existing_strict_py_call_site_still_valid():
    """strict.py calls LOGGER.warn(module, message) — that exact shape
    keeps working and lands in the entries list."""
    from webpent.verification import robust
    before = len(robust.LOGGER.entries)
    robust.LOGGER.warn("quality_summary", "umdr41 regression probe")
    assert robust.LOGGER.entries[before:] == [
        "[WARN] quality_summary: umdr41 regression probe"
    ]
