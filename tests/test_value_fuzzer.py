# tests/test_value_fuzzer.py
"""PROPOSALS_ULTIMATE_V3 §2 (2026-10-31) test suite: logic value fuzzer.

Covers the documented manual mutation lists per value kind (money,
count, id — identity never included), the flag gate (off = run_plan
raises with zero executor/ledger/scope touches), the mandatory
per-request safety path (scope refusal BEFORE send, ledger refusal =
not sent), the mutation budget bound across the whole plan,
unexpected-success labeling as candidate-only (needs_verification,
never confirmed), baseline flows never producing observations, and
real-ledger contract compatibility. All executors here are fakes —
the module owns no network.
"""

from __future__ import annotations

import pytest

from webpent.business_logic.value_fuzzer import (
    ART_LOGIC_MUTATION,
    FlowPlan,
    FlowStep,
    LogicFuzzError,
    ResponseOutcome,
    count_mutations,
    id_mutations,
    logic_fuzz_refusal,
    make_value,
    money_mutations,
    run_plan,
)
from webpent.business_logic.value_fuzzer import (
    Mutation as M,
)

OUT_OF_SCOPE_URL = "https://evil.example.com/api/checkout"


def _step(**overrides) -> FlowStep:
    base = dict(
        step_id="s1",
        method="POST",
        url="https://shop.example.com/api/checkout",
        field="price",
        kind="money",
        original="100",
    )
    base.update(overrides)
    return FlowStep(**base)


def _plan(*steps: FlowStep) -> FlowPlan:
    return FlowPlan(plan_id="p1", steps=list(steps))


# --- executors / fakes -------------------------------------------------------


class FakeLedger:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.recorded: list[tuple[str, str, str]] = []

    def record(self, method, url, *, engagement_id="", flags=""):
        if not self.ok:
            return False
        self.recorded.append((method, url, flags))
        return True


class FakeScope:
    def __init__(self, allowed_urls=("shop.example.com",)):
        self.allowed = allowed_urls
        self.checked: list[str] = []

    def check_url(self, url, *, method=""):
        self.checked.append(url)
        host = url.split("/")[2] if "://" in url else url
        if host in self.allowed:
            return SimpleDecision(allowed=True)
        return SimpleDecision(allowed=False, reason="out_of_scope")


class SimpleDecision:
    def __init__(self, allowed: bool, reason: str = ""):
        self.allowed = allowed
        self.reason = reason


def _activated():
    from webpent.config.settings import Settings, activate_settings

    return activate_settings(Settings(enable_logic_fuzzing=True))


# ---------------------------------------------------------------------------
# Documented mutation lists.
# ---------------------------------------------------------------------------


class TestMutationLists:
    def test_money_set_is_documented_manual_list(self):
        labels = [m.label for m in money_mutations("price", "100")]
        assert labels == [
            "zero",
            "negative",
            "tiny_fraction",
            "scientific",
            "precision_spoof",
            "string_injection",
        ]
        values = {m.label: m.value for m in money_mutations("price", "100")}
        assert values["zero"] == "0.00"
        assert values["negative"] == "-100.0"
        assert values["tiny_fraction"] == "0.01"
        assert values["precision_spoof"] == "1000000001"
        assert "price 0" in values["string_injection"]

    def test_money_negative_derived_from_original(self):
        values = {m.label: m.value for m in money_mutations("total", "49.99")}
        assert values["negative"] == "-49.99"

    def test_count_set_is_documented_manual_list(self):
        labels = [m.label for m in count_mutations("qty", "5")]
        assert labels == [
            "zero",
            "negative",
            "one_less",
            "one_more",
            "huge",
            "overflow_string",
            "float",
        ]
        values = {m.label: m.value for m in count_mutations("qty", "5")}
        assert values["one_less"] == "4"
        assert values["one_more"] == "6"
        assert values["huge"] == str(10**9)

    def test_id_set_is_documented_manual_list(self):
        labels = [m.label for m in id_mutations("user_id", "42")]
        assert labels == ["zero", "negative", "empty", "off_by_one_up", "huge"]
        values = {m.label: m.value for m in id_mutations("user_id", "42")}
        assert values["off_by_one_up"] == "43"
        assert values["empty"] == ""

    def test_identity_never_included_and_make_value_dispatch(self):
        for maker in (money_mutations, count_mutations, id_mutations):
            for m in maker("f", "10"):
                assert m.value != "10" or m.label == "off_by_one_up"
        assert make_value("f", "1", "money").kind == "money"
        with pytest.raises(LogicFuzzError, match="logic_fuzz_unknown_kind"):
            make_value("f", "1", "sql")


# ---------------------------------------------------------------------------
# Flag gate: off = zero touches anywhere.
# ---------------------------------------------------------------------------


class TestGate:
    def test_flag_off_refuses(self):
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_logic_fuzzing=False)):
            assert logic_fuzz_refusal() == "logic_fuzzing_flag_off"

    def test_flag_off_zero_io(self):
        from webpent.config.settings import Settings, activate_settings

        ledger = FakeLedger()
        scope = FakeScope()
        calls = []

        def executor(step, value):
            calls.append(value)
            return ResponseOutcome(status=200, accepted=True)

        with activate_settings(Settings(enable_logic_fuzzing=False)):
            with pytest.raises(LogicFuzzError, match="logic_fuzzing_flag_off"):
                run_plan(
                    _plan(_step()),
                    executor,
                    ledger,
                    scope,
                    max_mutations=10,
                )
        assert calls == []
        assert ledger.recorded == []
        assert scope.checked == []

    def test_flag_on_allows(self):
        with _activated():
            assert logic_fuzz_refusal() is None


# ---------------------------------------------------------------------------
# Mandatory safety path: scope then ledger, before send.
# ---------------------------------------------------------------------------


class TestSafetyPath:
    def test_out_of_scope_refused_before_send(self):
        with _activated():
            ledger = FakeLedger()
            scope = FakeScope()  # only shop.example.com allowed
            sent = []

            def executor(step, value):
                sent.append(value)
                return ResponseOutcome(status=200, accepted=True)

            plan = _plan(_step(url=OUT_OF_SCOPE_URL))
            obs = run_plan(plan, executor, ledger, scope, max_mutations=10)
            assert sent == []
            assert ledger.recorded == []
            assert all(o.inconclusive == "out_of_scope" for o in obs)
            assert all(o.request_sent is False for o in obs)
            assert len(scope.checked) == len(obs)

    def test_ledger_refusal_means_not_sent(self):
        with _activated():
            ledger = FakeLedger(ok=False)
            scope = FakeScope()
            sent = []

            def executor(step, value):
                sent.append(value)
                return ResponseOutcome(status=200, accepted=True)

            obs = run_plan(_plan(_step()), executor, ledger, scope, max_mutations=10)
            assert sent == []
            assert all(o.inconclusive == "ledger_refused" for o in obs)

    def test_missing_ledger_or_scope_is_fail_closed(self):
        with _activated():
            with pytest.raises(LogicFuzzError, match="logic_fuzz_ledger_required"):
                run_plan(_plan(_step()), lambda s, v: ResponseOutcome(), None, FakeScope())
            with pytest.raises(LogicFuzzError, match="logic_fuzz_scope_required"):
                run_plan(_plan(_step()), lambda s, v: ResponseOutcome(), FakeLedger(), None)


# ---------------------------------------------------------------------------
# Budget bound across the whole plan.
# ---------------------------------------------------------------------------


class TestBudget:
    def test_budget_bounds_total_mutations(self):
        with _activated():
            ledger = FakeLedger()
            scope = FakeScope()

            def executor(step, value):
                return ResponseOutcome(status=200, accepted=False)

            plan = _plan(
                _step(step_id="s1"),
                _step(step_id="s2", field="qty", kind="count", original="5"),
                _step(step_id="s3", field="user_id", kind="id", original="42"),
            )
            obs = run_plan(plan, executor, ledger, scope, max_mutations=8)
            assert len(obs) == 8  # 6 money + 7 count + 5 id would be 18

    def test_settings_default_used_when_not_given(self):
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_logic_fuzzing=True, logic_fuzz_max_mutations=3)):
            ledger = FakeLedger()
            obs = run_plan(
                _plan(_step()),
                lambda s, v: ResponseOutcome(),
                ledger,
                FakeScope(),
            )
            assert len(obs) == 3

    def test_invalid_budget_refused(self):
        with _activated():
            with pytest.raises(LogicFuzzError, match="logic_fuzz_invalid_max_mutations"):
                run_plan(
                    _plan(_step()),
                    lambda s, v: ResponseOutcome(),
                    FakeLedger(),
                    FakeScope(),
                    max_mutations=0,
                )


# ---------------------------------------------------------------------------
# Candidate labeling: success despite the mutation.
# ---------------------------------------------------------------------------


class TestCandidateLabeling:
    def test_success_despite_mutation_needs_verification(self):
        with _activated():
            ok_values = {"0.00"}  # flow succeeds only with zeroed price
            ledger = FakeLedger()

            def executor(step, value):
                return ResponseOutcome(
                    status=200, accepted=step.original == "100" and value in ok_values
                )

            obs = run_plan(_plan(_step()), executor, FakeLedger(), FakeScope())
            zero = [o for o in obs if o.label == "zero"][0]
            assert zero.request_sent and zero.accepted
            assert zero.needs_verification is True
            assert zero.to_dict()["verified"] is False  # never confirmed here
            others = [o for o in obs if o.label != "zero"]
            assert all(o.needs_verification is False for o in others)

    def test_executor_error_is_inconclusive_not_fatal(self):
        with _activated():
            def executor(step, value):
                raise RuntimeError("boom")

            obs = run_plan(_plan(_step()), executor, FakeLedger(), FakeScope())
            assert all(o.inconclusive and o.inconclusive.startswith("executor_error") for o in obs)

    def test_artifact_shape(self):
        with _activated():
            obs = run_plan(
                _plan(_step()),
                lambda s, v: ResponseOutcome(status=200, accepted=True),
                FakeLedger(),
                FakeScope(),
            )[0]
            artifact = obs.to_artifact()
            assert artifact["type"] == ART_LOGIC_MUTATION
            assert artifact["verified"] is False
            assert artifact["needs_verification"] is True

    def test_baseline_flow_never_observed(self):
        # The plan contains only mutated replays; nothing is emitted for
        # the untouched original value, so a normally succeeding flow
        # cannot be flagged by this module.
        with _activated():
            obs = run_plan(
                _plan(_step()),
                lambda s, v: ResponseOutcome(status=200, accepted=False),
                FakeLedger(),
                FakeScope(),
            )
            assert all(o.mutated != "100" for o in obs)


# ---------------------------------------------------------------------------
# Real RequestLedger contract compatibility.
# ---------------------------------------------------------------------------


class TestRealLedger:
    def test_records_through_real_ledger(self, tmp_path):
        from webpent.safety.request_ledger import RequestLedger

        with _activated():
            ledger = RequestLedger(db_path=str(tmp_path / "requests.db"))
            scope = FakeScope()
            obs = run_plan(
                _plan(_step()),
                lambda s, v: ResponseOutcome(status=200, accepted=False),
                ledger,
                scope,
            )
            assert obs and all(o.request_sent for o in obs)
            rows = ledger.entries(limit=100)
            assert rows, "real ledger must hold the mutated requests"
            assert all("logic_fuzz" in (r.get("flags") or "") for r in rows)
