"""U-DEEP-4 — HTTP Request Smuggling (red tests).

Detection principle: EFFECT OVER ECHO — a desync is only a finding
when one of the three effect channels actually fires (the smuggled
canary contaminates a response it was never part of, a timing
diff against the clean baseline, or a desync-specific server error),
never because the probe merely got a 200. Zero network: send(probe)
is injected; no raw sockets are opened.
"""
from __future__ import annotations

import pytest

from webpent.deep.smuggling import (
    CANARY,
    SMUGGLING_OBFUSCATIONS,
    SMUGGLING_VARIANTS,
    SmugglingDetector,
)


class _Response:
    def __init__(self, status_code, body, elapsed_ms=50):
        self.status_code = status_code
        self.body = body
        self.elapsed_ms = elapsed_ms


def _vulnerable_send(probe):
    headers = [(k.lower(), v) for k, v in probe.get("headers", [])]
    te_values = [v for k, v in headers if k == "transfer-encoding"]
    has_cl = any(k == "content-length" for k, _ in headers)
    if probe.get("http2") and (has_cl or te_values):
        # h2 front-end, h1.1 back-end: framing divergence
        return _Response(200,
                         f"ok ... smuggled remnant: {CANARY}",
                         elapsed_ms=900)
    if has_cl and te_values:
        # CL + TE present: the two sides disagree on the boundary
        return _Response(200,
                         f"ok ... smuggled remnant: {CANARY}",
                         elapsed_ms=900)
    if te_values and any(v.lower() != "chunked" for v in te_values):
        # obfuscated TE: desync with a server-side error
        return _Response(500, f"desync error: bad transfer-encoding",
                         elapsed_ms=900)
    return _Response(200, "ok", elapsed_ms=50)


def _safe_send(probe):
    return _Response(200, "ok", elapsed_ms=50)


@pytest.fixture
def detector():
    return SmugglingDetector(_vulnerable_send)


def test_variants_documented():
    assert set(SMUGGLING_VARIANTS) == {
        "CL.TE", "TE.CL", "TE.TE", "H2.CL", "H2.TE"}
    for variant in SMUGGLING_VARIANTS.values():
        assert variant["headers"]
        assert variant["body"]


def test_cl_te_detection(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "CL.TE"]
    assert findings
    assert findings[0].severity == "critical"
    assert any(CANARY in line for line in findings[0].evidence)


def test_te_cl_detection(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "TE.CL"]
    assert findings


def test_te_te_obfuscation(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "TE.TE"]
    assert findings
    plan = detector.build_plan()
    te_te = [p for p in plan if p["variant"] == "TE.TE"][0]
    te_headers = [v for k, v in te_te["headers"]
                  if k.lower() == "transfer-encoding"]
    assert len(te_headers) >= 2  # the obfuscated duplicate


def test_h2_cl_detection(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "H2.CL"]
    assert findings
    plan = detector.build_plan()
    h2 = [p for p in plan if p["variant"] == "H2.CL"][0]
    assert h2["http2"] is True


def test_timing_based_detection(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "TE.CL"]
    assert any("elapsed" in line for line in findings[0].evidence)


def test_response_contamination(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "CL.TE"]
    assert any("contamination" in line.lower()
               for line in findings[0].evidence)


def test_no_false_positive_on_safe():
    detector = SmugglingDetector(_safe_send)
    assert detector.scan() == []


def test_waf_bypass_variant(detector):
    plans = detector.bypass_variants()
    assert plans
    # every bypass plan carries a non-canonical TE header
    for plan in plans:
        te_headers = [v for k, v in plan["headers"]
                      if k.lower() == "transfer-encoding"]
        assert any(v != "chunked" or "\t" in v or v != v.lower()
                   for v in te_headers) or len(te_headers) >= 2
    assert any("\t" in obf for obf in SMUGGLING_OBFUSCATIONS)


def test_evidence_complete_deterministic(detector):
    first = detector.scan()
    assert first
    for finding in first:
        assert any("baseline" in line for line in finding.evidence)
        assert "advisory" in finding.statement.lower()
        assert finding.family == "HTTP_SMUGGLING"
    second = detector.scan()
    assert [(f.subfamily, f.evidence) for f in first] == \
        [(f.subfamily, f.evidence) for f in second]
    a = detector.build_plan()
    b = detector.build_plan()
    assert [(p["variant"], p["headers"], p["body"]) for p in a] == \
        [(p["variant"], p["headers"], p["body"]) for p in b]
