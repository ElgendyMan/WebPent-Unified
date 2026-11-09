"""U-DEEP-17 — Client-Side Path Traversal (red tests).

Detection principle: EFFECT OVER ECHO — a traversal is only a finding
when the SPA router actually rendered the protected route it was
supposed to guard (direct /admin is blocked, the crafted path
reached it through the router's own normalization), never when the
payload is merely reflected. Zero network: send(path, body) is
injected; no browser is driven.
"""
from __future__ import annotations

import pytest

from webpent.deep.client_path_traversal import (
    CLIENT_PATH_PAYLOADS,
    SEVERITY_BY_SUBFAMILY,
    SPAPathTraversalDetector,
)


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


from urllib.parse import unquote


class _VulnerableRouter:
    """The SPA router that normalizes crafted segments back into the
    guarded route; the guard only blocks the literal path."""

    def send(self, path, body):
        if path == "/admin":
            return _Response(403, {"route": "admin", "blocked": True})
        p = path
        for _ in range(2):
            p = unquote(p)
        p = (p.replace("/../", "/").replace("/./", "/")
              .replace("//", "/").replace("..;/", "../").replace(
                  ";/", "/"))
        if p.endswith("/admin") or p == "/admin":
            return _Response(200, {"route": "admin", "rendered": True})
        return _Response(200, {"route": p, "rendered": False})


class _StrictRouter(_VulnerableRouter):
    def send(self, path, body):
        if path == "/admin":
            return _Response(403, {"route": "admin", "blocked": True})
        return _Response(200, {"route": path, "rendered": False})


@pytest.fixture
def detector():
    return SPAPathTraversalDetector(_VulnerableRouter().send)


def test_payload_corpus_documented():
    paths = [p["path"] for p in CLIENT_PATH_PAYLOADS]
    assert paths == [
        "/app/../admin",
        "/app/./admin",
        "/app//admin",
        "/app/.%2e/admin",
        "/app/%2e%2e/admin",
        "/app/%252e%252e/admin",
        "/app/..;/admin",
    ]
    for entry in CLIENT_PATH_PAYLOADS:
        assert entry["subfamily"] in SEVERITY_BY_SUBFAMILY


def test_direct_admin_blocked(detector):
    assert detector.baseline_reaches() is False


def test_dotdot_dot_traversal_detected(detector):
    findings = [f for f in detector.scan()
                if f.payload == "/app/../admin"]
    assert findings
    assert findings[0].subfamily == "dot_segment"
    assert any("rendered" in line or "reached" in line.lower()
               for line in findings[0].evidence)


def test_empty_segment_traversal_detected(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "empty_segment"]
    assert findings


def test_double_encoding_traversal_detected(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "double_encoding"]
    assert findings
    assert findings[0].severity == "high"
    assert "%252e%252e" in findings[0].payload


def test_semicolon_traversal_detected(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "semicolon"]
    assert findings


def test_no_false_positive_on_strict_router():
    detector = SPAPathTraversalDetector(_StrictRouter().send)
    assert detector.scan() == []


def test_effect_over_echo_and_advisory(detector):
    findings = detector.scan()
    assert findings
    for finding in findings:
        assert any("blocked" in line
                   for line in finding.evidence)
        assert "advisory" in finding.statement.lower()
        assert finding.family == "CLIENT_PATH_TRAVERSAL"
    a = detector.build_plan()
    b = detector.build_plan()
    assert [(p["path"], p["subfamily"]) for p in a] == \
        [(p["path"], p["subfamily"]) for p in b]
