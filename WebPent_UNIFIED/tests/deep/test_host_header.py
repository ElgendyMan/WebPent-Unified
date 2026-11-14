"""U-DEEP-5 — Host Header Injection (8 tests per spec).

Context over content: what matters is what the application DOES with
the Host (reset links, redirects, cache keys, internal routing), not
whether the header echoes.
"""
from __future__ import annotations

import pytest

from webpent.deep.host_header import (
    HOST_HEADER_PAYLOADS,
    HostHeaderDetector,
    HostHeaderFinding,
)


class FakeResponse:
    def __init__(self, status_code=200, headers=None, body=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.body = body


def make_send(behavior="none"):
    """Fake transport keyed on the Host-family header values.

    behavior:
      none          — app ignores the Host entirely.
      password_reset — reset email link built from Host.
      redirect      — Location built from X-Forwarded-Host.
      cache_poison  — poisoned content served to later requests.
      internal      — internal Host values skip authentication.
    """
    seen_forwarded = []

    def send(method, path, headers):
        host = headers.get("Host", "target.com")
        forwarded = headers.get("X-Forwarded-Host")
        if forwarded:
            seen_forwarded.append(forwarded)

        if behavior == "password_reset" and host == "evil.com":
            return FakeResponse(200, {}, "Visit http://evil.com/reset?token=abc")
        if behavior == "redirect" and forwarded == "evil.com":
            return FakeResponse(302, {"Location": "http://evil.com/next"}, "")
        if behavior == "cache_poison":
            if forwarded == "evil.com":
                return FakeResponse(200, {}, "poisoned-key-set")
            if seen_forwarded:
                return FakeResponse(200, {}, "cached: http://evil.com/payload")
            return FakeResponse(200, {}, "clean page")
        if behavior == "internal":
            if host in ("127.0.0.1", "internal.target.com", "admin.target.com"):
                return FakeResponse(200, {}, "admin panel")
            return FakeResponse(403, {}, "forbidden")
        return FakeResponse(200, {}, "normal response")

    return send


def test_payload_corpus_matches_spec():
    assert set(HOST_HEADER_PAYLOADS) == {
        "host_override", "x_forwarded", "cache_poison", "route_based"}
    assert "Host: evil.com" in HOST_HEADER_PAYLOADS["host_override"]
    assert "X-Forwarded-Host: evil.com" in HOST_HEADER_PAYLOADS["x_forwarded"]
    assert "Forwarded: host=evil.com" in HOST_HEADER_PAYLOADS["x_forwarded"]


def test_password_reset_host_poisoning():
    detector = HostHeaderDetector(send=make_send("password_reset"))
    findings = detector.run_all()
    assert any(f.subfamily == "password_reset_poisoning" for f in findings)
    finding = next(f for f in findings
                   if f.subfamily == "password_reset_poisoning")
    assert finding.severity == "critical"


def test_redirect_host_injection():
    detector = HostHeaderDetector(send=make_send("redirect"))
    findings = detector.run_all()
    assert any(f.subfamily == "open_redirect_via_host" for f in findings)


def test_cache_poisoning():
    detector = HostHeaderDetector(send=make_send("cache_poison"))
    findings = detector.run_all()
    finding = next(f for f in findings if f.subfamily == "cache_poisoning")
    assert finding.severity == "high"


def test_internal_routing_bypass():
    detector = HostHeaderDetector(send=make_send("internal"))
    findings = detector.run_all()
    assert any(f.subfamily == "internal_routing_bypass" for f in findings)


def test_no_false_positive():
    detector = HostHeaderDetector(send=make_send("none"))
    assert detector.run_all() == []


def test_deterministic_detection():
    a = HostHeaderDetector(send=make_send("password_reset")).run_all()
    b = HostHeaderDetector(send=make_send("password_reset")).run_all()
    assert [(f.subfamily, f.severity) for f in a] == \
        [(f.subfamily, f.severity) for f in b]


def test_evidence_includes_response():
    detector = HostHeaderDetector(send=make_send("password_reset"))
    finding = detector.run_all()[0]
    assert isinstance(finding, HostHeaderFinding)
    assert any("evil.com" in e for e in finding.evidence)
    assert finding.request_header
