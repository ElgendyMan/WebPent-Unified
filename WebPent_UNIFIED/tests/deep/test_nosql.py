"""U-DEEP-13 — NoSQL Injection (red tests).

Detection principle: STATE OVER STRING — a finding requires the
server's auth/business state to change (bypass where clean credentials
fail, or a blind timing change), never a mere string echo. Zero
network: send(endpoint, body) is injected.
"""
from __future__ import annotations

import pytest

from webpent.deep.nosql_injection import (
    NOSQL_INJECTION_ATTACKS,
    SEVERITY_BY_SUBFAMILY,
    NoSqlInjectionFinding,
    NoSqlInjectionDetector,
)


class _Response:
    def __init__(self, status_code, payload, elapsed_ms=50):
        self.status_code = status_code
        self._payload = payload
        self.elapsed_ms = elapsed_ms

    def json(self):
        return self._payload


def _send_vulnerable(endpoint, body):
    password = body.get("password", "")
    if isinstance(password, dict):
        operator = next(iter(password))
        if operator in ("$ne", "$gt", "$regex", "$nin", "$not"):
            return _Response(200, {"user": "victim", "role": "admin"})
        if operator == "$where":
            return _Response(200, {"user": "victim"},
                             elapsed_ms=1500)
        if operator == "$expr":
            return _Response(200, {"user": "victim", "role": "admin"})
    return _Response(401, {"error": "invalid credentials"})


def _send_hardened(endpoint, body):
    return _Response(401, {"error": "invalid credentials"})


@pytest.fixture
def detector():
    return NoSqlInjectionDetector(_send_vulnerable)


def test_corpus_documented():
    assert set(NOSQL_INJECTION_ATTACKS) == {
        "auth_bypass", "js_injection", "blind_timing"}


def test_mongo_operators_six():
    operators = NOSQL_INJECTION_ATTACKS["auth_bypass"]["operators"]
    assert set(operators) == {"$ne", "$gt", "$gte", "$regex",
                              "$where", "$expr"}


def test_auth_bypass_detected(detector):
    findings = detector.scan()
    assert any(f.subfamily == "auth_bypass" for f in findings)


def test_baseline_recorded_in_evidence(detector):
    findings = detector.scan()
    assert findings
    assert any("baseline" in line for f in findings
               for line in f.evidence)


def test_hardened_server_no_findings():
    assert NoSqlInjectionDetector(_send_hardened).scan() == []


def test_finding_carries_operator(detector):
    findings = detector.scan()
    bypass = next(f for f in findings
                  if f.subfamily == "auth_bypass")
    assert bypass.operator in ("$ne", "$gt", "$gte", "$regex",
                               "$nin", "$not", "$where", "$expr")


def test_severity_deterministic(detector):
    findings = detector.scan()
    bypass = next(f for f in findings
                  if f.subfamily == "auth_bypass")
    assert bypass.severity == \
        SEVERITY_BY_SUBFAMILY["auth_bypass"] == "critical"
    assert set(SEVERITY_BY_SUBFAMILY) == set(NOSQL_INJECTION_ATTACKS)


def test_blind_detected_on_timing(detector):
    findings = detector.scan()
    blind = next(f for f in findings
                 if f.subfamily == "blind_timing")
    assert blind.evidence
    assert any("1500" in line for line in blind.evidence)


def test_statement_advisory(detector):
    findings = detector.scan()
    assert all("advisory" in f.statement.lower() for f in findings)


def test_deterministic(detector):
    a = NoSqlInjectionDetector(_send_vulnerable).scan()
    b = NoSqlInjectionDetector(_send_vulnerable).scan()
    assert [(f.subfamily, f.payload) for f in a] == \
        [(f.subfamily, f.payload) for f in b]
