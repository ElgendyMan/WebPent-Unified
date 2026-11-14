"""U-DEEP-3 — Business Logic Engine (red tests).

Detection principle: EFFECT OVER STATE — an assumption violation is
only a finding when the server accepts it AND the effect actually
took hold (a client price was charged, a refund exceeded the payment,
a spent coupon paid out again), never because a request merely
returned 200. Zero network: send(endpoint, body) is injected.
"""
from __future__ import annotations

import pytest

from webpent.deep.business_logic import (
    BUSINESS_LOGIC_ASSUMPTIONS,
    SEVERITY_BY_SUBFAMILY,
    BusinessLogicEngine,
)


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _VulnerableShop:
    """The modeled app: trusts client price, unbounded refunds, no
    currency check, reusable coupons, skippable workflow."""

    def __init__(self):
        self.orders = {"o1": {"paid": 100, "currency": "EGP",
                              "refunded": 0}}
        self.used_coupons: list[str] = []

    def send(self, endpoint, body):
        if endpoint == "/api/orders/o1":
            return _Response(200, dict(self.orders["o1"]))
        if endpoint == "/api/checkout":
            unit = body.get("price", 100)  # trusts the client price
            charged = unit * body.get("quantity", 1)
            return _Response(200, {"ok": True, "charged": charged})
        if endpoint == "/api/refund":
            order = self.orders[body["order_id"]]
            order["refunded"] += body.get("amount", 0)  # no cap
            return _Response(200, {
                "ok": True, "refunded": body.get("amount", 0),
                "currency": body.get("currency", order["currency"])})
        if endpoint == "/api/coupon/apply":
            code = body.get("code", "")
            if code in self.used_coupons:
                return _Response(200, {"ok": True, "discount": 50})
            self.used_coupons.append(code)
            return _Response(200, {"ok": True, "discount": 50})
        if endpoint == "/api/checkout/step/5":
            return _Response(200, {"ok": True, "step": 5,
                                   "confirmed": True})
        return _Response(404, {"ok": False})


class _HardenedShop(_VulnerableShop):
    def send(self, endpoint, body):
        if endpoint == "/api/checkout":
            if body.get("quantity", 1) <= 0:
                return _Response(400, {"ok": False,
                                       "error": "quantity must be > 0"})
            charged = 100 * body.get("quantity", 1)  # server-side price
            return _Response(200, {"ok": True, "charged": charged})
        if endpoint == "/api/refund":
            order = self.orders[body["order_id"]]
            if body.get("amount", 0) > order["paid"] - order["refunded"]:
                return _Response(400, {"ok": False,
                                       "error": "refund exceeds payment"})
            if body.get("currency", order["currency"]) != \
                    order["currency"]:
                return _Response(400, {"ok": False,
                                       "error": "currency mismatch"})
            order["refunded"] += body.get("amount", 0)
            return _Response(200, {"ok": True,
                                   "refunded": body.get("amount", 0),
                                   "currency": order["currency"]})
        if endpoint == "/api/coupon/apply":
            if body.get("code", "") in self.used_coupons:
                return _Response(409, {"ok": False,
                                       "error": "coupon already used"})
            self.used_coupons.append(body.get("code", ""))
            return _Response(200, {"ok": True, "discount": 50})
        if endpoint == "/api/checkout/step/5":
            return _Response(400, {"ok": False,
                                   "error": "steps 2-4 incomplete"})
        return super().send(endpoint, body)


@pytest.fixture
def engine():
    return BusinessLogicEngine(_VulnerableShop().send)


def test_assumption_corpus_documented():
    assert set(BUSINESS_LOGIC_ASSUMPTIONS) == {
        "server_trust", "range", "workflow", "uniqueness", "state",
        "time", "ownership"}
    for entry in BUSINESS_LOGIC_ASSUMPTIONS.values():
        assert entry["example"]


def test_map_checkout_flow(engine):
    flows = engine.map_flows()
    checkout = [f for f in flows if f.name == "checkout"][0]
    assert checkout.endpoint == "/api/checkout"
    types = engine.identify_assumptions(checkout)
    assert any(a.type == "server_trust" for a in types)
    assert any(a.type == "range" for a in types)


def test_price_override_detected(engine):
    findings = [f for f in engine.scan()
                if f.subfamily == "price_override"]
    assert findings
    assert findings[0].severity == "critical"
    # effect over state: the client price was actually charged
    assert any("charged 100->1" in line
               for line in findings[0].evidence)


def test_negative_quantity_detected(engine):
    findings = [f for f in engine.scan()
                if f.subfamily == "negative_quantity"]
    assert findings
    assert findings[0].severity == "high"
    assert any("charged" in line and "-100" in line
               for line in findings[0].evidence)


def test_refund_exceeds_payment_detected(engine):
    findings = [f for f in engine.scan()
                if f.subfamily == "refund_exceeds_payment"]
    assert findings
    assert findings[0].severity == "critical"
    assert any("200" in line and "100" in line
               for line in findings[0].evidence)


def test_currency_confusion_detected(engine):
    findings = [f for f in engine.scan()
                if f.subfamily == "currency_confusion"]
    assert findings
    assert any("EGP" in line and "USD" in line
               for line in findings[0].evidence)


def test_coupon_reuse_detected(engine):
    findings = [f for f in engine.scan()
                if f.subfamily == "coupon_reuse"]
    assert findings
    assert any("twice" in line or "reuse" in line.lower()
               for line in findings[0].evidence)


def test_workflow_skip_detection(engine):
    findings = [f for f in engine.scan()
                if f.subfamily == "workflow_skip"]
    assert findings
    assert any("step 5" in line
               for line in findings[0].evidence)


def test_no_false_positive_on_safe_app():
    engine = BusinessLogicEngine(_HardenedShop().send)
    assert engine.scan() == []


def test_evidence_state_advisory_deterministic(engine):
    first = engine.scan()
    assert first
    for finding in first:
        assert any("state:" in line for line in finding.evidence)
        assert "advisory" in finding.statement.lower()
        assert finding.family == "BUSINESS_LOGIC"
        assert finding.subfamily in SEVERITY_BY_SUBFAMILY
    second = engine.scan()
    assert [(f.subfamily, f.evidence) for f in first] == \
        [(f.subfamily, f.evidence) for f in second]
