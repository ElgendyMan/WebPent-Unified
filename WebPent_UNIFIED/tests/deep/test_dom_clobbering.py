"""U-DEEP-16 — DOM Clobbering (red tests).

Detection principle: EFFECT OVER ECHO — a clobbering payload is only
a finding when the page's client-side behavior actually changed
(window.config was hijacked and the script followed it), never when
the injected HTML is merely reflected back. Zero network:
send(endpoint, body) is injected; no browser is driven.
"""
from __future__ import annotations

import pytest

from webpent.deep.dom_clobbering import (
    DOM_CLOBBER_PAYLOADS,
    DomClobberingDetector,
)


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def _vulnerable_send(endpoint, body):
    html = body.get("html", "")
    if 'id="config"' in html or 'name="config"' in html:
        # the client script reads window.config and follows it
        sink = "evil.com" if "evil.com" in html else "config-only"
        return _Response(200, {"ok": True, "behavior": "changed",
                               "sink": sink})
    # reflected only: no script reads the injected markup
    return _Response(200, {"ok": True, "behavior": "unchanged",
                           "reflected": html})


def _safe_send(endpoint, body):
    return _Response(200, {"ok": True, "behavior": "unchanged",
                           "reflected": body.get("html", "")})


@pytest.fixture
def detector():
    return DomClobberingDetector(_vulnerable_send)


def test_corpus_documented():
    assert set(DOM_CLOBBER_PAYLOADS) == {
        "global_vars", "attributes", "nested"}
    assert DOM_CLOBBER_PAYLOADS["global_vars"] == [
        '<a id="config">',
        '<img name="config">',
        '<form name="config">',
    ]
    assert DOM_CLOBBER_PAYLOADS["attributes"] == [
        '<a id="config" href="evil.com">',
        '<form id="config" action="evil.com">',
    ]
    assert DOM_CLOBBER_PAYLOADS["nested"] == [
        '<a id="config"><a id="config" name="url" '
        'href="evil.com"></a></a>',
    ]


def test_identify_injection_points(detector):
    page = ("<html><body><div><!--injection-point--></div>"
            "<script>var config = window.config;</script></body>"
            "</html>")
    points = detector.identify_injection_points(page)
    assert points
    assert any("injection-point" in p for p in points)


def test_global_vars_clobber_detected(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "global_vars"]
    assert findings
    assert findings[0].severity == "medium"
    assert any("behavior" in line.lower()
               for line in findings[0].evidence)


def test_attribute_sink_clobber_detected(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "attributes"]
    assert findings
    assert findings[0].severity == "high"
    assert any("evil.com" in line
               for line in findings[0].evidence)


def test_nested_clobber_detected(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "nested"]
    assert findings
    assert any("nested" in line.lower()
               for line in findings[0].evidence)


def test_no_false_positive_when_reflected_only():
    detector = DomClobberingDetector(_safe_send)
    assert detector.scan() == []


def test_deterministic_plan(detector):
    a = detector.build_plan()
    b = detector.build_plan()
    assert [(p["subfamily"], p["payload"]) for p in a] == \
        [(p["subfamily"], p["payload"]) for p in b]
    assert len(a) == 6  # 3 global_vars + 2 attributes + 1 nested


def test_effect_over_echo_and_advisory(detector):
    findings = detector.scan()
    assert findings
    for finding in findings:
        assert any("behavior" in line.lower()
                   for line in finding.evidence)
        assert "advisory" in finding.statement.lower()
        assert finding.family == "DOM_CLOBBERING"
