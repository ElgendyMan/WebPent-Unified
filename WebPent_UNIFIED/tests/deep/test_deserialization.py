"""U-DEEP-15 — Deserialization (red tests).

Detection principle: EFFECT OVER ECHO — a canary is only a finding
when the target actually deserializes it (a side-effect marker that
was never echoed, a serializer-error timing profile, or a response
diff against the clean baseline), never when the input is merely
reflected. Canaries are inert: no gadget chains, no gadget class
names, no ysoserial/PHPGGC payloads. Zero network: send(endpoint,
body) is injected.
"""
from __future__ import annotations

import base64

import pytest

from webpent.deep.deserialization import (
    CANARY_MARKER,
    DESERIALIZATION_SIGNATURES,
    SEVERITY_BY_SUBFAMILY,
    DeserializationDetector,
)


class _Response:
    def __init__(self, status_code, payload, elapsed_ms=50):
        self.status_code = status_code
        self._payload = payload
        self.elapsed_ms = elapsed_ms

    def json(self):
        return self._payload


def _vulnerable_send(endpoint, body):
    data = str(body.get("data", ""))
    if data.startswith("rO0A") or data.startswith("AAEAAAD/"):
        # java/.NET: deserialization attempted, serializer error,
        # slow error path
        return _Response(500, {"error": "invalid stream"}, elapsed_ms=900)
    if data.startswith("gASV"):
        # python pickle: canary marker executed as a side effect
        return _Response(200, {"ok": True,
                               "side_effect": f"{CANARY_MARKER}-executed"})
    if data.startswith("O:") or data.startswith("a:"):
        # php: response diff — serializer error page where the
        # baseline was clean
        return _Response(500, {"error": "unserialize(): Error at offset"})
    if CANARY_MARKER in data:
        # ruby/node: marker echoed back verbatim — NOT a side effect
        return _Response(200, {"echo": data})
    return _Response(200, {"ok": True})


def _hardened_send(endpoint, body):
    return _Response(200, {"ok": True})


@pytest.fixture
def detector():
    return DeserializationDetector(_vulnerable_send)


def test_signatures_documented():
    assert set(DESERIALIZATION_SIGNATURES) == {
        "java", "php", "python", "dotnet", "ruby", "nodejs"}
    tools = {lang: sig["tool"] for lang, sig
             in DESERIALIZATION_SIGNATURES.items()}
    assert tools == {
        "java": "ysoserial", "php": "PHPGGC", "python": "pickle",
        "dotnet": "ysoserial.net", "ruby": "Marshal",
        "nodejs": "node-serialize"}


def test_magic_bytes_verbatim():
    assert DESERIALIZATION_SIGNATURES["java"]["magic_bytes"] == \
        b"\xac\xed\x00\x05"
    assert DESERIALIZATION_SIGNATURES["python"]["magic_bytes"] == \
        b"\x80\x04\x95"
    assert DESERIALIZATION_SIGNATURES["ruby"]["magic_bytes"] == \
        b"\x04\x08"
    assert DESERIALIZATION_SIGNATURES["nodejs"]["raw_magic"] == \
        "_$$ND_FUNC$$_"
    assert DESERIALIZATION_SIGNATURES["dotnet"]["base64_magic"] == \
        "AAEAAAD/"
    assert DESERIALIZATION_SIGNATURES["php"]["raw_prefixes"] == \
        ("O:", "a:")


def test_identify_by_base64_magic():
    detector = DeserializationDetector(_hardened_send)
    java_blob = base64.b64encode(b"\xac\xed\x00\x05rest").decode()
    assert detector.identify(java_blob) == ["java"]
    python_blob = base64.b64encode(b"\x80\x04\x95rest").decode()
    assert detector.identify(python_blob) == ["python"]
    dotnet_blob = "AAEAAAD/AAAAAAAA" 
    assert detector.identify(dotnet_blob) == ["dotnet"]


def test_identify_by_raw_magic():
    detector = DeserializationDetector(_hardened_send)
    assert detector.identify('O:8:" stdClass":0:{}') == ["php"]
    assert detector.identify('a:1:{s:4:"user";}') == ["php"]
    assert detector.identify('_$$ND_FUNC$$_function(){}') == ["nodejs"]
    assert detector.identify("just a string") == []


def test_canaries_inert_no_gadget_chains(detector):
    banned = ("Runtime", "exec", "CommonsCollections", "Transformer",
              "ysoserial", "PHPGGC", "system(", "passthru", "eval(")
    for lang in DESERIALIZATION_SIGNATURES:
        canary = detector.canary(lang)
        assert CANARY_MARKER in canary
        for word in banned:
            assert word not in canary


def test_rce_side_effect_detected(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "rce_side_effect"]
    assert findings
    assert findings[0].language == "python"
    assert any(f"{CANARY_MARKER}-executed" in line
               for line in findings[0].evidence)


def test_error_timing_detected(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "error_timing"]
    assert {f.language for f in findings} == {"java", "dotnet"}
    assert all(f.severity == "high" for f in findings)


def test_response_diff_detected(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "response_diff"]
    assert findings
    assert findings[0].language == "php"
    assert findings[0].severity == "medium"


def test_hardened_server_no_findings():
    detector = DeserializationDetector(_hardened_send)
    assert detector.scan() == []


def test_advisory_and_deterministic(detector):
    first = detector.scan()
    for finding in first:
        assert "advisory" in finding.statement.lower()
        assert finding.family == "DESERIALIZATION"
    second = detector.scan()
    assert [(f.subfamily, f.language, f.evidence) for f in first] == \
        [(f.subfamily, f.language, f.evidence) for f in second]
