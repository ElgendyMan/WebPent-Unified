# tests/test_m2_adversarial_scope.py
"""M2-B acceptance — the adversarial scope corpus.

The registry's M2 scope names the corpus explicitly: DNS rebinding, TOCTOU,
redirects, proxies, encoded hosts, metadata endpoints. These tests attack
the REAL enforcement seams (no reimplementation):

* ``shared/http.py`` — the blocklist, the pinning transport (resolve-once +
  validate-every-IP + rewrite-to-literal), the redirect guard;
* ``shared/engagement_scope.py`` — the engagement host declaration and the
  F-06 admission gate;
* ``live_hunter/tool_scope.py`` — ScopeLaw's poison hard-deny (FV-1).

DNS is controlled by monkeypatching ``socket.getaddrinfo`` in the module
under test — the tests simulate the attacker's nameserver (public first
lookup, internal second lookup, multi-record mixes, encoded literals).
No real network is ever contacted.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

import httpx
import pytest

import webpent.shared.http as http_module
from webpent.shared.http import (
    SSRFRedirectBlockedError,
    _is_blocked_host,
    make_safe_httpx_client,
)
from webpent.shared.engagement_scope import (
    admission_target_check,
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)


# ---------------------------------------------------------------------------
# DNS control — simulate the attacker's resolver
# ---------------------------------------------------------------------------


def _install_resolver(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, list[str]]):
    """Replace getaddrinfo in the module under test with a fake DNS server."""

    def fake_getaddrinfo(host, port, *args, **kwargs):
        key = str(host).lower().strip(".")
        records = mapping.get(key)
        if records is None:
            raise socket.gaierror(socket.EAI_NONAME, f"no record for {key}")
        infos = []
        for record in records:
            family = (
                socket.AF_INET6 if ":" in record else socket.AF_INET
            )
            infos.append((family, socket.SOCK_STREAM, 6, "", (record, port or 0)))
        return infos

    monkeypatch.setattr(http_module.socket, "getaddrinfo", fake_getaddrinfo)


@pytest.fixture(autouse=True)
def _clean_engagement_context():
    """Force-clear the engagement context after every test (fail-closed)."""
    yield
    clear_engagement_target_hosts(None)


def _declare_engagement(*urls: str):
    """Declare engagement hosts; the autouse fixture clears the context."""
    return set_engagement_target_hosts(*urls)


# ---------------------------------------------------------------------------
# Metadata endpoints — the classic cloud SSRF target
# ---------------------------------------------------------------------------


def test_metadata_ip_literal_is_blocked_without_dns():
    assert _is_blocked_host("169.254.169.254") is True
    assert _is_blocked_host("fe80::1") is True
    # the IPv4-mapped bypass (::ffff:0:0/96) is explicitly in the blocklist
    assert _is_blocked_host("::ffff:169.254.169.254") is True
    assert _is_blocked_host("::ffff:10.0.0.7") is True


def test_metadata_hostname_resolving_to_metadata_ip_is_blocked(monkeypatch):
    _install_resolver(monkeypatch, {"metadata.cloud.internal": ["169.254.169.254"]})
    assert _is_blocked_host("metadata.cloud.internal") is True


def test_pinned_transport_refuses_metadata_target(monkeypatch):
    _install_resolver(monkeypatch, {"169.254.169.254": ["169.254.169.254"]})
    with make_safe_httpx_client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, text="metadata")
    )) as client:
        with pytest.raises(Exception) as excinfo:
            client.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    assert "169.254.169.254" in str(excinfo.value) or "blocked" in str(excinfo.value).lower()


# ---------------------------------------------------------------------------
# Encoded / exotic host literals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "encoded,resolved",
    [
        ("0x7f000001", "127.0.0.1"),  # hex
        ("0177.0.0.1", "127.0.0.1"),  # octal
        ("2130706433", "127.0.0.1"),  # decimal
        ("127.1", "127.0.0.1"),  # shortened
    ],
)
def test_encoded_host_literals_resolve_to_blocked_networks(
    monkeypatch, encoded, resolved
):
    # ipaddress rejects these spellings, so the guard falls through to DNS —
    # the resolver returns the real address and the blocklist must catch it
    _install_resolver(monkeypatch, {encoded: [resolved]})
    assert _is_blocked_host(encoded) is True, encoded


def test_multi_record_host_with_one_private_ip_is_blocked_fail_closed(monkeypatch):
    # rebinding mix: one public record to pass a naive allowlist check,
    # one internal record — every returned IP must be validated
    _install_resolver(
        monkeypatch,
        {"rebind.example": ["93.184.216.34", "10.0.0.5"]},
    )
    assert _is_blocked_host("rebind.example") is True


def test_dns_failure_is_fail_closed(monkeypatch):
    _install_resolver(monkeypatch, {})  # every lookup raises gaierror
    assert _is_blocked_host("unresolvable.example") is True


# ---------------------------------------------------------------------------
# Pinning transport — resolve-once, validate-every-IP, rewrite-to-literal
# ---------------------------------------------------------------------------


def _recording_transport(responses: dict[str, int] | None = None):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok")

    return httpx.MockTransport(handler), seen


def test_pinned_transport_rewrites_to_validated_ip_literal(monkeypatch):
    _install_resolver(monkeypatch, {"target.example": ["93.184.216.34"]})
    transport, seen = _recording_transport()
    with make_safe_httpx_client(transport=transport) as client:
        response = client.get("http://target.example/path")
    assert response.status_code == 200
    # the URL host was rewritten to the validated IP literal so httpx's
    # internal resolver never gets a second, poisonable lookup
    assert seen[0].url.host == "93.184.216.34"
    # the original Host header is preserved for virtual-hosted targets
    assert seen[0].headers.get("host") == "target.example"


def test_pinned_transport_blocks_host_that_resolves_private(monkeypatch):
    _install_resolver(monkeypatch, {"internal.example": ["10.0.0.9"]})
    transport, _ = _recording_transport()
    with make_safe_httpx_client(transport=transport) as client:
        with pytest.raises(Exception, match="10.0.0.9|blocked|internal"):
            client.get("http://internal.example/")


def test_rebinding_toctou_is_caught_at_use_time(monkeypatch):
    # the attacker's nameserver answers the FIRST lookup with a public IP
    # and the SECOND with an internal IP — each request re-resolves and
    # re-validates, so the poisoned lookup is refused at connection time
    # one request performs TWO internal lookups (validate + pin); the
    # attacker's nameserver flips the answer only AFTER the first request
    sequence = {"count": 0}

    def fake_getaddrinfo(host, port, *args, **kwargs):
        sequence["count"] += 1
        record = "93.184.216.34" if sequence["count"] <= 2 else "192.168.1.50"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (record, port or 0))]

    monkeypatch.setattr(http_module.socket, "getaddrinfo", fake_getaddrinfo)
    transport, seen = _recording_transport()
    with make_safe_httpx_client(transport=transport) as client:
        assert client.get("http://flip.example/").status_code == 200
        with pytest.raises(Exception, match="192.168.1.50|blocked|internal"):
            client.get("http://flip.example/second")
    assert len(seen) == 1, "the poisoned second request must never reach a socket"


def test_engagement_own_target_resolving_private_is_admitted(monkeypatch):
    # the documented carve-out: the engagement's OWN target may resolve to
    # a private/lab IP (that is the whole point of a lab run) — the pinning
    # transport pins it with allow_blocked=True for the declared host only
    _install_resolver(monkeypatch, {"lab.example": ["192.168.40.128"]})
    _declare_engagement("http://lab.example")  # same scheme+host+port as the request
    transport, seen = _recording_transport()
    with make_safe_httpx_client(transport=transport) as client:
        response = client.get("http://lab.example/dvwa/")
    assert response.status_code == 200
    assert seen[0].url.host == "192.168.40.128"


def test_non_engagement_private_target_stays_blocked(monkeypatch):
    # the carve-out is host-EXACT: another private host is still refused
    _install_resolver(monkeypatch, {"lab.example": ["192.168.40.128"], "other.example": ["192.168.40.129"]})
    _declare_engagement("https://lab.example")
    transport, _ = _recording_transport()
    with make_safe_httpx_client(transport=transport) as client:
        with pytest.raises(Exception):
            client.get("http://other.example/")


# ---------------------------------------------------------------------------
# Redirect guard — defence in depth on every 3xx
# ---------------------------------------------------------------------------


def _redirect_server(location: str, final_status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": location})
        return httpx.Response(final_status, text="landed")

    return httpx.MockTransport(handler)


def test_redirect_to_metadata_is_blocked(monkeypatch):
    _install_resolver(monkeypatch, {"169.254.169.254": ["169.254.169.254"]})
    _declare_engagement("https://target.example")
    with make_safe_httpx_client(
        transport=_redirect_server("http://169.254.169.254/latest/meta-data/"),
        follow_redirects=True,
    ) as client:
        with pytest.raises(SSRFRedirectBlockedError):
            client.get("https://target.example/start")


def test_redirect_to_out_of_scope_origin_is_blocked(monkeypatch):
    # a PUBLIC redirect target that the engagement never declared is still
    # refused — OriginPolicy is exact, not "any public host"
    _install_resolver(
        monkeypatch,
        {"target.example": ["93.184.216.34"], "elsewhere.example": ["93.184.216.99"]},
    )
    _declare_engagement("https://target.example")
    with make_safe_httpx_client(
        transport=_redirect_server("https://elsewhere.example/steal"),
        follow_redirects=True,
    ) as client:
        with pytest.raises(SSRFRedirectBlockedError, match="OriginPolicy"):
            client.get("https://target.example/start")


def test_redirect_to_own_origin_is_followed(monkeypatch):
    _install_resolver(monkeypatch, {"target.example": ["93.184.216.34"]})
    _declare_engagement("https://target.example")
    with make_safe_httpx_client(
        transport=_redirect_server("/landing"), follow_redirects=True
    ) as client:
        response = client.get("https://target.example/start")
    assert response.status_code == 200
    assert response.text == "landed"


# ---------------------------------------------------------------------------
# Engagement declaration + admission gate (F-06)
# ---------------------------------------------------------------------------


def test_engagement_declaration_refuses_link_local_unconditionally():
    with pytest.raises(ValueError, match="link_local"):
        set_engagement_target_hosts("http://169.254.169.254/")


def test_admission_gate_refuses_link_local_even_with_private_override():
    with pytest.raises(ValueError, match="link_local"):
        admission_target_check("http://169.254.169.254/latest/meta-data/", allow_private_target=True)


def test_admission_gate_private_needs_explicit_override():
    with pytest.raises(ValueError):
        admission_target_check("http://10.0.0.5/")
    admission_target_check("http://10.0.0.5/", allow_private_target=True)


# ---------------------------------------------------------------------------
# ScopeLaw — poison is a hard deny regardless of scope verdict (FV-1)
# ---------------------------------------------------------------------------


def _scopelaw():
    from webpent.live_hunter.profile import build_authorized_lab_profile
    from webpent.live_hunter.tool_scope import ScopeLaw

    profile = build_authorized_lab_profile(
        engagement_id="m2-adversarial",
        operator_approval_at="2026-01-01T00:00:00+00:00",
        authorized_targets=("lab.example",),  # bare host — profile matches hostnames
    )
    return ScopeLaw(profile=profile, engagement_id="m2-adversarial")


@pytest.mark.parametrize(
    "tool,arguments",
    [
        ("sqlmap", ["-u", "https://lab.example/x", "--os-shell"]),
        ("nuclei", ["-target", "http://169.254.169.254/latest/meta-data/"]),
        ("httpx", ["-u", "http://metadata.google.internal/computeMetadata/v1/"]),
        ("katana", ["-u", "file:///etc/passwd"]),
    ],
)
def test_scopelaw_poison_arguments_are_hard_denied(tool, arguments):
    decision = _scopelaw().authorize_invocation(
        tool_name=tool, target_url="https://lab.example", arguments=arguments
    )
    assert decision.in_scope is False or decision.poison_detected is True, (
        f"{tool} {' '.join(arguments)} must be denied"
    )
    assert decision.poison_detected is True, "the denial reason must be POISON, not scope"


def test_scopelaw_denies_unregistered_tools_and_out_of_scope_targets():
    law = _scopelaw()
    unregistered = law.authorize_invocation(
        tool_name="nc", target_url="https://lab.example", arguments=("-e", "/bin/sh")
    )
    assert unregistered.in_scope is False and "tool_not_registered" in unregistered.reason
    out_of_scope = law.authorize_invocation(
        tool_name="httpx", target_url="https://not-authorized.example", arguments=()
    )
    assert out_of_scope.in_scope is False and "out_of_scope" in out_of_scope.reason


def test_scopelaw_allows_clean_in_scope_invocation():
    decision = _scopelaw().authorize_invocation(
        tool_name="httpx", target_url="https://lab.example", arguments=("-sc",)
    )
    assert decision.in_scope is True and decision.poison_detected is False
