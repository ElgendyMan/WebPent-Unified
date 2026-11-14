"""U-DEEP-12 — SAML Attacks (red tests).

Detection principle: ACCEPTANCE OVER STRUCTURE — a manipulated SAML
response is only a finding when the ACS actually accepts it (issues an
authenticated session where the baseline's identity, signature
coverage or entity handling should have prevented it). Zero network:
send(method, path, body) is injected. Enterprise-only family,
canary-modeled: no real XML-signature machinery is exercised.
"""
from __future__ import annotations

import pytest

from webpent.deep.saml import (
    ATTACKER_IDENTITY,
    SAML_ATTACKS,
    SEVERITY_BY_SUBFAMILY,
    SamlDetector,
)

BASELINE_SAML_RESPONSE = (
    "<samlp:Response>"
    "<Assertion ID='_sig1'>"
    "<Subject><NameID>victim@target</NameID></Subject>"
    "<Signature><SignedInfo><Reference URI='#_sig1'/></SignedInfo>"
    "</Signature>"
    "</Assertion>"
    "</samlp:Response>")


class _Response:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.body = body


def _vulnerable_send(method, path, body):
    xml = body.get("SAMLResponse", "")
    if "<!DOCTYPE" in xml:
        # vulnerable parser: resolves external entities
        return _Response(200, "parsed with entities resolved: "
                              "root:x:0:0:root:/root:/bin/bash")
    if "<!--" in xml:
        # vulnerable canonicalization: identity extracted with
        # comments stripped
        return _Response(200, f"authenticated as {ATTACKER_IDENTITY}")
    if xml.count("<Assertion") >= 2 and "<Signature" in xml:
        # verifies SOME assertion's signature, authenticates the FIRST
        return _Response(200, f"authenticated as {ATTACKER_IDENTITY}")
    if "<Signature" not in xml:
        # signature not required: unsigned assertion accepted
        return _Response(200, "authenticated as victim@target "
                              "(unsigned accepted)")
    if "victim@target" in xml:
        return _Response(200, "authenticated as victim@target")
    return _Response(401, "invalid signature")


def _hardened_send(method, path, body):
    xml = body.get("SAMLResponse", "")
    if "<!DOCTYPE" in xml or "<!--" in xml:
        return _Response(400, "rejected: entities/comments forbidden")
    if xml.count("<Assertion") != 1 or "<Signature" not in xml:
        return _Response(400, "rejected: unsigned or wrapped assertion")
    if "victim@target" in xml:
        return _Response(200, "authenticated as victim@target")
    return _Response(401, "invalid signature")


def _rejected_send(method, path, body):
    return _Response(401, "rejected")


@pytest.fixture
def detector():
    return SamlDetector(_vulnerable_send, BASELINE_SAML_RESPONSE)


def test_corpus_documented():
    assert set(SAML_ATTACKS) == {
        "xsw", "comment_injection", "signature_stripping", "xxe"}
    assert set(SEVERITY_BY_SUBFAMILY) == set(SAML_ATTACKS)


def test_baseline_accepted_before_probing(detector):
    findings = detector.scan()
    assert findings
    for finding in findings:
        assert any("baseline: accepted" in line
                   for line in finding.evidence)


def test_rejected_baseline_no_findings():
    detector = SamlDetector(_rejected_send, BASELINE_SAML_RESPONSE)
    assert detector.scan() == []


def test_xsw_detected(detector):
    findings = [f for f in detector.scan() if f.subfamily == "xsw"]
    assert findings
    assert ATTACKER_IDENTITY in " ".join(findings[0].evidence)


def test_xsw_payload_wraps_two_assertions(detector):
    probe = SAML_ATTACKS["xsw"]["build"](BASELINE_SAML_RESPONSE)
    assert probe.count("<Assertion") == 2
    assert ATTACKER_IDENTITY in probe
    assert "<Signature" in probe  # the signed original is preserved


def test_comment_injection_detected(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "comment_injection"]
    assert findings
    assert "<!--" in findings[0].payload


def test_signature_stripping_detected(detector):
    findings = [f for f in detector.scan()
                if f.subfamily == "signature_stripping"]
    assert findings
    assert "<Signature" not in findings[0].payload


def test_xxe_detected(detector):
    findings = [f for f in detector.scan() if f.subfamily == "xxe"]
    assert findings
    # effect over echo: the response carries file content that the
    # submitted response never contained
    assert "root:x:0:0" in " ".join(findings[0].evidence)
    assert "root:x:0:0" not in findings[0].payload


def test_hardened_server_no_findings():
    detector = SamlDetector(_hardened_send, BASELINE_SAML_RESPONSE)
    assert detector.scan() == []


def test_severity_deterministic():
    assert SEVERITY_BY_SUBFAMILY["xsw"] == "critical"
    assert SEVERITY_BY_SUBFAMILY["signature_stripping"] == "critical"
    assert SEVERITY_BY_SUBFAMILY["comment_injection"] == "high"
    assert SEVERITY_BY_SUBFAMILY["xxe"] == "critical"


def test_advisory_and_deterministic(detector):
    first = detector.scan()
    for finding in first:
        assert "advisory" in finding.statement.lower()
        assert finding.family == "SAML"
    second = detector.scan()
    assert [(f.subfamily, f.payload, f.evidence) for f in first] == \
        [(f.subfamily, f.payload, f.evidence) for f in second]
