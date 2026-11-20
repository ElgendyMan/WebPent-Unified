"""U-DEEP-18 — Web Cache Deception (8 tests per spec).

The deception exists only when the SAME crafted path serves the
victim's sensitive body to an unauthenticated attacker — body equality
plus a documented sensitivity check, nothing less.
"""
from __future__ import annotations

import pytest

from webpent.deep.cache_deception import (
    CACHE_DECEPTION_HEADERS,
    CACHE_DECEPTION_PATHS,
    STATIC_EXTS,
    CacheDeceptionDetector,
    CacheDeceptionFinding,
)


class FakeResponse:
    def __init__(self, status_code=200, headers=None, body=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.body = body


VICTIM_BODY = '{"username":"victim","email":"victim@example.com","balance":42}'


def make_send(mode="vulnerable"):
    """Fake transport.

    vulnerable — static-looking paths are cached, so the attacker gets
                 the victim's cached body.
    cache_miss — the crafted path is NOT cached; attacker gets a login
                 page.
    benign     — crafted path serves non-sensitive content to both.
    """
    def send(path, cookies=None):
        for endpoint in ("/profile", "/api/user", "/account"):
            if path.startswith(endpoint + "/"):
                if mode == "vulnerable":
                    return FakeResponse(200, {}, VICTIM_BODY)
                if mode == "cache_miss":
                    if cookies:
                        return FakeResponse(200, {}, VICTIM_BODY)
                    return FakeResponse(200, {}, "<html>login page</html>")
                return FakeResponse(200, {}, "static asset ok")
        if cookies:
            return FakeResponse(200, {}, VICTIM_BODY)
        return FakeResponse(200, {}, "<html>login page</html>")

    return send


def test_static_extensions_match_spec():
    assert STATIC_EXTS == [".css", ".js", ".png", ".jpg", ".svg", ".ico",
                           ".woff"]


def test_sensitive_endpoints_and_headers_match_spec():
    assert CACHE_DECEPTION_PATHS == ["/profile", "/api/user", "/account"]
    assert "X-Original-URL: /profile" in CACHE_DECEPTION_HEADERS
    assert "X-Rewrite-URL: /profile" in CACHE_DECEPTION_HEADERS


def test_crafted_paths_generated():
    detector = CacheDeceptionDetector(send=make_send())
    paths = detector.crafted_paths()
    assert len(paths) == 3 * len(STATIC_EXTS)
    assert "/profile/static.css" in paths
    assert "/api/user/static.woff" in paths


def test_deception_detected_when_bodies_match():
    detector = CacheDeceptionDetector(
        send=make_send("vulnerable"), victim_cookies={"session": "s"})
    findings = detector.scan()
    assert findings
    finding = findings[0]
    assert isinstance(finding, CacheDeceptionFinding)
    assert finding.crafted_path.startswith("/")


def test_no_finding_when_attacker_gets_different_body():
    detector = CacheDeceptionDetector(
        send=make_send("cache_miss"), victim_cookies={"session": "s"})
    assert detector.scan() == []


def test_no_finding_when_body_not_sensitive():
    detector = CacheDeceptionDetector(
        send=make_send("benign"), victim_cookies={"session": "s"})
    assert detector.scan() == []


def test_deterministic_detection():
    a = CacheDeceptionDetector(
        send=make_send("vulnerable"), victim_cookies={"session": "s"}).scan()
    b = CacheDeceptionDetector(
        send=make_send("vulnerable"), victim_cookies={"session": "s"}).scan()
    assert [f.crafted_path for f in a] == [f.crafted_path for f in b]


def test_evidence_includes_endpoint_and_ext():
    detector = CacheDeceptionDetector(
        send=make_send("vulnerable"), victim_cookies={"session": "s"})
    finding = detector.scan()[0]
    assert finding.endpoint in ("/profile", "/api/user", "/account")
    assert finding.static_ext in STATIC_EXTS
    assert finding.evidence
