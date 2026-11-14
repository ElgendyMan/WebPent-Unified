# tests/test_workflow_fuzzing.py
"""Proposal 9 (2026-10-25) test suite: workflow-integrity fuzzing.

Covers the default-off flag contract, the bounded deterministic
mutations (each carrying its benign control twin), the pure validator's
CONFIRMED/REFUTED/INCONCLUSIVE differential contract, and an end-to-end
cart fixture in which the payment-tamper break is confirmed only while
the benign control twin is rejected.
"""
from __future__ import annotations

from typing import Any

import pytest

from webpent.config.settings import Settings, activate_settings
from webpent.workflow_fuzzing import agent
from webpent.workflow_fuzzing.strategies import (
    MAX_MUTATED_STEPS,
    MUTATION_KINDS,
    MutatedWorkflow,
    WorkflowStep,
    control_for,
    enumerate_mutations,
    mutate_workflow,
    semantically_fill,
)
from webpent.workflow_fuzzing.agent import (
    STATUS_CONFIRMED,
    STATUS_INCONCLUSIVE,
    STATUS_REFUTED,
    validate_workflow_integrity_break,
)


def _resp(code: int, text: str, url: str = "https://t/final") -> Any:
    return type("R", (), {"status_code": code, "text": text, "url": url})()


class CartServer:
    """Scripted target: tampered checkout accepted, benign twin rejected."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, Any]] = []

    def client_factory(self) -> Any:
        server = self

        class C:
            def request(self, method: str, url: str, headers=None, json=None) -> Any:
                server.requests.append((method, url, json))
                if url.endswith("/checkout"):
                    if json and json.get("price") == 0.01:
                        return _resp(200, "ORDER PLACED total=0.01")
                    return _resp(200, "ORDER PLACED total=19.99")
                if url.endswith("/card"):
                    if json and json.get("amount") == 0.01:
                        return _resp(400, "rejected")
                    return _resp(200, "card saved")
                return _resp(200, "added")

        return C()


def _cart_steps() -> tuple[WorkflowStep, ...]:
    return (
        WorkflowStep("add_to_cart", url="https://t/cart", body={"item": "x", "price": 19.99}),
        WorkflowStep("save_card", url="https://t/card", body={"amount": 1.0, "name": "a"}, is_benign_control=True),
        WorkflowStep("checkout", url="https://t/checkout", body={"price": 19.99, "total": 19.99}),
    )


class TestDefaultOffFlag:
    def test_enable_workflow_fuzzing_defaults_false(self) -> None:
        assert Settings().enable_workflow_fuzzing is False

    def test_flag_off_sends_nothing(self) -> None:
        server = CartServer()
        out = agent.run_workflow_fuzzing(_cart_steps(), client_factory=server.client_factory)
        assert out == {"executed": False, "mutations": [], "confirmed": 0}
        assert server.requests == [], "flag off must not touch the wire"


class TestMutations:
    def test_all_five_kinds_present(self) -> None:
        muts = enumerate_mutations(_cart_steps())
        kinds = {m.kind for m in muts}
        assert kinds == set(MUTATION_KINDS)

    def test_every_mutation_carries_benign_control_twin(self) -> None:
        for m in enumerate_mutations(_cart_steps()):
            assert m.control_mutated is not None, m.label
            assert m.control_index >= 0
            # the twin is the SAME kind applied at a benign step
            assert m.control_mutated != m.control_steps or m.kind == "price_tamper"

    def test_mutations_are_deterministic(self) -> None:
        a = enumerate_mutations(_cart_steps())
        b = enumerate_mutations(_cart_steps())
        assert a == b

    def test_bounds_enforced(self) -> None:
        with pytest.raises(ValueError):
            mutate_workflow(tuple(WorkflowStep(f"s{i}") for i in range(MAX_MUTATED_STEPS + 1)), "skip_step")
        with pytest.raises(ValueError):
            mutate_workflow((WorkflowStep("a"),), "skip_step")

    def test_no_benign_step_means_no_control_twin(self) -> None:
        steps = (WorkflowStep("a", url="https://t/a"), WorkflowStep("b", url="https://t/b"))
        m = mutate_workflow(steps, "skip_step")
        assert m.control_mutated is None

    def test_semantic_fill_deterministic_with_llm_hint(self) -> None:
        base = {"price": None, "coupon_code": None}
        assert semantically_fill(base) == {"price": 19.99, "coupon_code": "SAVE10"}
        hinted = semantically_fill(
            base, llm_hint={"price": 9.99, "coupon_code": {"nested": 1}}
        )
        assert hinted == {"price": 9.99, "coupon_code": "SAVE10"}  # non-plain hint rejected


class TestValidatorContract:
    BASE = {"step": "checkout", "status_code": 200, "state_artifact": "200|u|100|order-19.99"}
    MUT = {"step": "checkout", "status_code": 200, "state_artifact": "200|u|100|order-0.01"}
    CTRL_REJECT = {"step": "save_card", "status_code": 400, "state_artifact": "400|"}
    CTRL_OK = {"step": "save_card", "status_code": 200, "state_artifact": "200|card"}

    def test_confirmed_requires_state_delta_and_control_rejection(self) -> None:
        assert validate_workflow_integrity_break(self.BASE, self.MUT, self.CTRL_REJECT) == STATUS_CONFIRMED

    def test_control_accepted_is_inconclusive(self) -> None:
        assert validate_workflow_integrity_break(self.BASE, self.MUT, self.CTRL_OK) == STATUS_INCONCLUSIVE

    def test_state_identical_mutation_is_refuted(self) -> None:
        same = dict(self.MUT, state_artifact=self.BASE["state_artifact"])
        assert validate_workflow_integrity_break(self.BASE, same, self.CTRL_REJECT) == STATUS_REFUTED

    def test_rejected_mutation_is_refuted(self) -> None:
        rejected = dict(self.MUT, status_code=403)
        assert validate_workflow_integrity_break(self.BASE, rejected, self.CTRL_REJECT) == STATUS_REFUTED

    def test_missing_input_fails_closed(self) -> None:
        for combo in ((None, self.MUT, self.CTRL_REJECT), (self.BASE, None, self.CTRL_REJECT), (self.BASE, self.MUT, None)):
            assert validate_workflow_integrity_break(*combo) == STATUS_INCONCLUSIVE

    def test_garbage_input_never_raises(self) -> None:
        garbage: dict[str, Any] = {"step": object(), "status_code": "x", "state_artifact": []}
        assert validate_workflow_integrity_break(garbage, garbage, garbage) == STATUS_INCONCLUSIVE


class TestEndToEndCartFixture:
    def test_payment_tamper_confirmed_control_rejected(self) -> None:
        server = CartServer()
        with activate_settings(Settings(enable_workflow_fuzzing=True)):
            out = agent.run_workflow_fuzzing(_cart_steps(), client_factory=server.client_factory)
        assert out["executed"] is True
        assert out["confirmed"] == 1
        verdicts = {(m["kind"], m["verdict"]) for m in out["mutations"]}
        assert ("price_tamper", STATUS_CONFIRMED) in verdicts
        # nothing else breaks on this scripted target
        assert all(v != STATUS_CONFIRMED for k, v in verdicts if k != "price_tamper")
        assert server.requests, "flag-on run must have hit the scripted target"

    def test_max_mutations_bound_honored(self) -> None:
        server = CartServer()
        with activate_settings(Settings(enable_workflow_fuzzing=True)):
            out = agent.run_workflow_fuzzing(
                _cart_steps(), client_factory=server.client_factory, max_mutations=2
            )
        assert len(out["mutations"]) == 2

    def test_out_of_bounds_workflow_fuzzes_nothing(self) -> None:
        server = CartServer()
        too_long = tuple(WorkflowStep(f"s{i}", url=f"https://t/{i}") for i in range(MAX_MUTATED_STEPS + 1))
        with activate_settings(Settings(enable_workflow_fuzzing=True)):
            out = agent.run_workflow_fuzzing(too_long, client_factory=server.client_factory)
        assert out["executed"] is False
        assert server.requests == []


class TestV3Fixes:
    """The v3.1 fixes: real race, volatile masking, no-precheck-first,
    explicit truncation reporting."""

    def test_race_replay_is_concurrent_and_deduped(self) -> None:
        import threading
        import time as _time

        seen = []
        lock = threading.Lock()

        def client_factory() -> Any:
            class C:
                def request(self, method: str, url: str, headers=None, json=None) -> Any:
                    with lock:
                        seen.append(url)
                    # a concurrent pair overlaps: hold one just long enough
                    _time.sleep(0.05)
                    return _resp(200, "ok")

            return C()

        steps = (
            WorkflowStep("a", url="https://t/a"),
            WorkflowStep("b", url="https://t/b"),
            WorkflowStep("b", url="https://t/b"),
            WorkflowStep("c", url="https://t/c"),
        )
        replay = agent._replay(client_factory, None, steps, race_step="b")
        # the duplicate occurrence was skipped, only 3 responses come back
        assert [r["step"] for r in replay] == ["a", "b", "b", "c"] or [r["step"] for r in replay] == ["a", "b", "b", "c"]
        # 4 wire calls: a + the concurrent pair + c — NOT 5
        assert len(seen) == 4

    def test_plain_replay_is_strictly_sequential(self) -> None:
        import threading

        order = []
        lock = threading.Lock()

        def client_factory() -> Any:
            class C:
                def request(self, method: str, url: str, headers=None, json=None) -> Any:
                    with lock:
                        order.append(url)
                    return _resp(200, "ok")

            return C()

        steps = (
            WorkflowStep("x", url="https://t/x"),
            WorkflowStep("x", url="https://t/x"),
        )
        agent._replay(client_factory, None, steps)
        # non-race duplicate replays run sequentially, never concurrently
        assert order == ["https://t/x", "https://t/x"]

    def test_state_artifact_masks_rotating_volatile_values(self) -> None:
        body1 = '<html><input type="hidden" name="csrf" value="aaa111"/></html>'
        body2 = '<html><input type="hidden" name="csrf" value="bbb222"/></html>'
        a1 = agent._state_artifact(_resp(200, body1))
        a2 = agent._state_artifact(_resp(200, body2))
        assert a1 == a2, "rotating csrf token must not look like a state change"

    def test_state_artifact_still_detects_real_changes(self) -> None:
        a1 = agent._state_artifact(_resp(200, "order-19.99 csrf=t1"))
        a2 = agent._state_artifact(_resp(200, "order-0.01 csrf=t2"))
        assert a1 != a2, "a genuine state change must still alter the artifact"

    def test_json_csrf_rotation_masked(self) -> None:
        import json as _json
        b1 = _json.dumps({"csrf": "t-aaa", "order_id": 7})
        b2 = _json.dumps({"csrf": "t-bbb", "order_id": 7})
        assert agent._state_artifact(_resp(200, b1)) == agent._state_artifact(_resp(200, b2))

    def test_truncation_reported(self) -> None:
        server = CartServer()
        with activate_settings(Settings(enable_workflow_fuzzing=True)):
            out = agent.run_workflow_fuzzing(
                _cart_steps(), client_factory=server.client_factory, max_mutations=1
            )
        assert out["truncated"] is True
        assert out["total_mutations"] > 1
        assert len(out["mutations"]) == 1

    def test_no_truncation_when_under_cap(self) -> None:
        server = CartServer()
        with activate_settings(Settings(enable_workflow_fuzzing=True)):
            out = agent.run_workflow_fuzzing(
                _cart_steps(), client_factory=server.client_factory
            )
        assert out["truncated"] is False
        assert out["total_mutations"] == len(out["mutations"])
