"""U-DEEP-1 — Race Condition Detector (red tests).

Detection principle: EFFECT OVER STATE — a race is only a finding
when the parallel burst actually flips state more than once (N
successes where the sequential control gives exactly 1 AND the
reported state moved), never because requests merely succeeded. Zero
network: send(endpoint, body, burst_id) is injected; the burst marker
models the single-packet arrival window without any TCP control.
"""
from __future__ import annotations

import pytest

from webpent.deep.race_condition import (
    RACE_CONDITION_SUBFAMILIES,
    RaceConditionDetector,
)


class _State:
    """Vulnerable check-then-act server: within one burst the check
    is skipped (same-millisecond arrival), across bursts it applies."""

    def __init__(self, quota=1, start=1000):
        self.quota = quota
        self.balance = start
        self.uses = 0
        self._last_burst = None

    def send(self, endpoint, body, burst_id=None):
        class R:
            status_code = 200
            elapsed_ms = 4

            def __init__(self, payload):
                self._payload = payload

            def json(self):
                return self._payload

        trusted = body.get("amount", body.get("coupon_count", 1))
        within_burst = burst_id is not None and burst_id == self._last_burst
        self._last_burst = burst_id
        if endpoint.endswith("/items"):
            # idempotent read: success without any state change
            return R({"ok": True, "balance": self.balance,
                      "uses": self.uses})
        if not within_burst:
            if self.uses >= self.quota:
                return R({"ok": False, "rejected": True,
                          "balance": self.balance, "uses": self.uses})
            self.uses += 1
        self.balance -= trusted
        self.uses += 1
        return R({"ok": True, "balance": self.balance, "uses": self.uses})


class _Safe(_State):
    def send(self, endpoint, body, burst_id=None):
        response = super().send(endpoint, body, burst_id)
        if endpoint.endswith("/items"):
            return response
        # hardened: the check applies even within a burst
        if self.uses > self.quota:
            self.uses -= 1
            self.balance += body.get("amount",
                                     body.get("coupon_count", 1))
            import json as _json

            class Rejected:
                status_code = 429
                elapsed_ms = 4

                def json(self):
                    return {"ok": False, "rejected": True}

            return Rejected()
        return response


@pytest.fixture
def detector():
    return RaceConditionDetector(_State().send)


def test_detect_state_changing_endpoints(detector):
    endpoints = detector.detect_endpoints(
        ["POST /api/coupon", "GET /api/items"])
    assert endpoints == ["POST /api/coupon"]


def test_detect_trusted_fields(detector):
    assert detector.has_trusted_field({"amount": 100})
    assert detector.has_trusted_field({"quantity": 5})
    assert detector.has_trusted_field({"count": 2})
    assert not detector.has_trusted_field({"name": "x"})


def test_single_packet_execution(detector):
    result = detector.execute_attack("POST /api/coupon",
                                     {"coupon_count": 50})
    assert result.burst_size == detector.n
    assert len(result.responses) == detector.n
    assert result.successes == detector.n


def test_coupon_race_found(detector):
    finding = detector.analyze(detector.execute_attack(
        "POST /api/coupon", {"coupon_count": 50}))
    assert finding is not None
    assert finding.subfamily == "state_bypass"
    assert finding.severity == "high"


def test_balance_race_found(detector):
    finding = detector.analyze(detector.execute_attack(
        "POST /api/withdraw", {"amount": 100}))
    assert finding is not None
    assert finding.severity == "critical"
    assert "balance" in " ".join(finding.evidence)


def test_no_false_positive_on_idempotent(detector):
    result = detector.execute_attack("GET /api/items", {})
    assert detector.analyze(result) is None


def test_timing_precision_measured(detector):
    result = detector.execute_attack("POST /api/coupon",
                                     {"coupon_count": 50})
    assert len(result.elapsed_ms) == result.burst_size
    assert result.total_elapsed_ms > 0


def test_sequential_control_no_finding(detector):
    result = detector.execute_attack("POST /api/coupon",
                                     {"coupon_count": 50},
                                     burst_id=None)
    assert result.successes == 1
    assert detector.analyze(result) is None


def test_deterministic_attack_plan(detector):
    a = detector.generate_payloads("POST /api/coupon",
                                   {"coupon_count": 50})
    b = detector.generate_payloads("POST /api/coupon",
                                   {"coupon_count": 50})
    assert [(p.endpoint, p.body, p.burst_id) for p in a] == \
        [(p.endpoint, p.body, p.burst_id) for p in b]


def test_evidence_includes_timing(detector):
    finding = detector.analyze(detector.execute_attack(
        "POST /api/coupon", {"coupon_count": 50}))
    assert any("elapsed" in line for line in finding.evidence)
    assert any("state" in line for line in finding.evidence)
    for subfamily in RACE_CONDITION_SUBFAMILIES:
        assert RACE_CONDITION_SUBFAMILIES[subfamily]["severity"]
