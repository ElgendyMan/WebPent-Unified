# tests/test_v2_v3_business_logic_race.py
"""TC-3 §2 V-2/V-3 — the inferrer's generation rules and the orchestrator's
single-packet window (pure-logic tests; no live servers)."""
from __future__ import annotations

import importlib
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

bli = importlib.import_module("webpent.production.business_logic_inferrer")
po = importlib.import_module("webpent.production.parallel_orchestrator")


# ---------------------------------------------------------------------------
# V-2 — the State Machine Inferrer
# ---------------------------------------------------------------------------
def _diagram_with_guards() -> bli.StateDiagram:
    d = bli.StateDiagram()
    d.record(frm="START", to="CART", endpoint="/api/cart/items", action="add_item")
    d.record(frm="CART", to="PAYMENT_PENDING", endpoint="/api/checkout",
             action="checkout")
    d.record(frm="PAYMENT_PENDING", to="PAID", endpoint="/api/pay",
             action="pay")
    d.record_guard(state="PAID", precondition="payment settled")
    return d


def test_diagram_records_transitions_and_guards():
    d = _diagram_with_guards()
    assert {"START", "CART", "PAYMENT_PENDING", "PAID"} <= d.states
    assert len(d.transitions) == 3
    assert d.guarded_terminals() == ["PAID"]


def test_r3_generates_nothing_without_observed_guards():
    """A diagram built from POSITIVE observations alone has no guards —
    the jump rule must generate NOTHING (never a filler hypothesis)."""
    d = bli.StateDiagram()
    d.record(frm="START", to="CART", endpoint="/api/cart/items", action="add_item")
    d.record(frm="CART", to="PAID", endpoint="/api/cart/{id}/checkout",
             action="checkout")
    assert d.guarded_terminals() == []


def test_r3_generates_only_from_recorded_guards():
    class _StubOrch:
        def execute_real_request(self, **kwargs):  # pragma: no cover
            return {"status_code": 200, "response_body": "{}"}

    inferrer = bli.BusinessLogicInferrer(orchestrator=_StubOrch())
    inferrer.diagram = _diagram_with_guards()
    hyps = inferrer.generate_hypotheses(engagement_id="t")
    jumps = [h for h in hyps
             if h["business_logic_metadata"]["rule"] == "R3_state_jump"]
    assert len(jumps) == 1
    assert jumps[0]["business_logic_metadata"]["target_state"] == "PAID"


def test_r1_and_r2_hypotheses_carry_the_evidence_contract():
    class _StubOrch:
        def __init__(self) -> None:
            self.n = 0

        def execute_real_request(self, **kwargs):
            self.n += 1
            body = {"cart_id": f"CART-{self.n:04d}", "total": 100.0,
                    "state": "CART"}
            path = str(kwargs.get("target_url", ""))
            if "/coupon" in path:
                body = {"cart_id": path.rsplit("/", 1)[-1].split("?")[0],
                        "total": 50.0, "state": "COUPON_APPLIED"}
            elif "/checkout" in path:
                body = {"cart_id": "CART-x", "total": 50.0, "state": "PAID"}
            return {"status_code": 200,
                    "response_body": __import__("json").dumps(body)}

    inferrer = bli.BusinessLogicInferrer(orchestrator=_StubOrch())
    inferrer.observe_flow("http://127.0.0.1:1")
    assert inferrer.sequential_control["deterministic"] is True
    hyps = inferrer.generate_hypotheses(engagement_id="t")
    rules = {h["business_logic_metadata"]["rule"]: h for h in hyps}
    # R2: the price hypothesis carries the manipulated value for the
    # causal identity-binding gate
    assert rules["R2_value_manipulation"]["metadata"]["candidate_value"] == "0.01"
    contract_r2 = rules["R2_value_manipulation"]["business_logic_metadata"]["evidence_contract"]
    assert contract_r2["expected_flow_outcome"] == 100.0
    # R1: the stacking hypothesis predicts the manipulated flow outcome
    # with the OBSERVED multiplier and carries the sequential control
    assert rules["R1_transition_replay"]["metadata"]["candidate_value"]
    contract_r1 = rules["R1_transition_replay"]["business_logic_metadata"]["evidence_contract"]
    assert contract_r1["sequential_control"]["deterministic"] is True


# ---------------------------------------------------------------------------
# V-3 — the Parallel Request Orchestrator (the single-packet window)
# ---------------------------------------------------------------------------
def test_burst_is_bounded():
    class _Stub:
        def __init__(self) -> None:
            self.seen = 0
            self.lock = threading.Lock()

        def __call__(self, **kwargs):
            with self.lock:
                self.seen += 1
            return {"status_code": 200}

    orch = po.ParallelRequestOrchestrator(_Stub())
    assert orch.max_burst == po.ParallelRequestOrchestrator.MAX_BURST == 5
    results = orch.burst(n=99, url="http://127.0.0.1:1/x")
    assert len(results) == 5  # clamped to the bound
    assert orch.sequential(n=3, url="http://127.0.0.1:1/x") is not None


def test_barrier_releases_all_workers_inside_one_window():
    """THE single-packet property: with the barrier, every worker is
    INSIDE the window before any exits — observed max concurrency == n.
    The sequential control shows overlap 1."""
    lock = threading.Lock()
    in_flight = {"n": 0, "max": 0}

    def _recording_executor(**kwargs):
        with lock:
            in_flight["n"] += 1
            in_flight["max"] = max(in_flight["max"], in_flight["n"])
        time.sleep(0.05)
        with lock:
            in_flight["n"] -= 1
        return {"status_code": 200}

    orch = po.ParallelRequestOrchestrator(_recording_executor)
    orch.burst(n=5, url="http://127.0.0.1:1/x")
    assert in_flight["max"] == 5  # one synchronized window

    in_flight.update({"n": 0, "max": 0})
    orch.sequential(n=4, url="http://127.0.0.1:1/x")
    assert in_flight["max"] == 1  # strictly sequential control


def test_differential_report_records_the_evidence():
    def _always_ok(**kwargs):
        return {"status_code": 200}

    orch = po.ParallelRequestOrchestrator(_always_ok)
    report = orch.differential_report(url="http://127.0.0.1:1/x", n=5,
                                      expected_successes=1)
    assert report["parallel_attempts"] == 5
    assert report["parallel_successes"] == 5
    assert report["over_accepted"] is True
    assert report["pattern"] == "single_packet_barrier_window"
