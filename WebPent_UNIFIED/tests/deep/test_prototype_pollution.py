"""U-DEEP-14 — Prototype Pollution (red tests).

Detection principle: STATE OVER STRING — a finding requires the
privileged key to actually flip (immediately or on a clean follow-up
for server-side persistence), never a mere echo of the payload. Zero
network: send(endpoint, body) is injected.
"""
from __future__ import annotations

import pytest

from webpent.deep.prototype_pollution import (
    PROTOTYPE_POLLUTION_PAYLOADS,
    SEVERITY_BY_SUBFAMILY,
    PrototypePollutionDetector,
)


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def _merge_state(body, state):
    """Apply the pollution semantics the payload asks for."""
    if "__proto__" in body and isinstance(body["__proto__"], dict):
        for key, value in body["__proto__"].items():
            state[key] = value
    if "constructor" in body:
        proto = body.get("constructor", {}).get("prototype", {})
        for key, value in proto.items():
            state[key] = value


def _send_immediate(endpoint, body):
    state = {"role": "user"}
    _merge_state(body or {}, state)
    return _Response(200, state)


class _PersistentServer:
    """Pollutes its own state: the probe's own body stays clean but
    every later request shows the polluted key."""

    def __init__(self):
        self.state = {"role": "user"}
        self.first = True

    def __call__(self, endpoint, body):
        if body:
            _merge_state(body, self.state)
            self.first = False
            return _Response(200, {"role": "user"})
        if self.first:
            return _Response(200, dict(self.state))
        return _Response(200, dict(self.state))


def _send_hardened(endpoint, body):
    return _Response(200, {"role": "user"})


@pytest.fixture
def detector():
    return PrototypePollutionDetector(_send_immediate)


def test_corpus_documented():
    assert set(PROTOTYPE_POLLUTION_PAYLOADS) == {
        "server_side", "client_query", "client_fragment", "client_json"}
    assert len(PROTOTYPE_POLLUTION_PAYLOADS["server_side"]) == 3
    assert len(PROTOTYPE_POLLUTION_PAYLOADS["client_query"]) == 3
    assert len(PROTOTYPE_POLLUTION_PAYLOADS["client_fragment"]) == 1
    assert len(PROTOTYPE_POLLUTION_PAYLOADS["client_json"]) == 1


def test_server_side_pollution_detected(detector):
    findings = detector.scan()
    assert any(f.subfamily == "server_side" for f in findings)


def test_constructor_variant_detected(detector):
    findings = PrototypePollutionDetector(_send_immediate).scan()
    payloads = [f.payload for f in findings]
    assert any("constructor" in str(p) for p in payloads)


def test_clean_baseline_no_finding():
    detector = PrototypePollutionDetector(_send_hardened)
    assert detector.scan() == []


def test_client_side_payloads_present():
    assert "__proto__" in \
        PROTOTYPE_POLLUTION_PAYLOADS["client_query"][0]
    assert PROTOTYPE_POLLUTION_PAYLOADS["client_fragment"][0] \
        .startswith("#")
    assert "__proto__" in PROTOTYPE_POLLUTION_PAYLOADS["client_json"][0]


def test_evidence_carries_baseline_and_probe(detector):
    findings = detector.scan()
    assert findings
    evidence = "\n".join(line for f in findings for line in f.evidence)
    assert "baseline" in evidence
    assert "probe" in evidence


def test_persistence_detected():
    detector = PrototypePollutionDetector(_PersistentServer())
    findings = detector.scan()
    assert any("persistent" in f.subfamily for f in findings)


def test_severity_deterministic(detector):
    findings = detector.scan()
    assert findings
    assert all(f.severity == SEVERITY_BY_SUBFAMILY[f.subfamily]
               for f in findings)


def test_statement_advisory(detector):
    findings = detector.scan()
    assert all("advisory" in f.statement.lower() for f in findings)


def test_deterministic(detector):
    a = PrototypePollutionDetector(_send_immediate).scan()
    b = PrototypePollutionDetector(_send_immediate).scan()
    assert [(f.subfamily, str(f.payload)) for f in a] == \
        [(f.subfamily, str(f.payload)) for f in b]
