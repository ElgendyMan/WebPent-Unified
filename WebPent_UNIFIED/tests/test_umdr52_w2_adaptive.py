"""UM-DR-52 W2 — the adaptive experimentation engine contract.

future plan.md Phase 5 / window §4:

* B1 — the eight-state lifecycle VIEW measured on the FINAL state
  after the actual reducer (RC-6: never count a list of updates);
  unmapped states fail closed (surface, never vanish);
* B2 — learning from failure is mandatory: a failure without an
  analyzed cause is refused at the ledger gate; the repeat-guard QC
  blocks an identical failed re-run on the same cell without NEW
  evidence;
* B3 — selection is information-gated (the W3 priority formula's
  context flows into WHICH experiments are selected — the W1→W2
  integration is measurable), parallelism is identity-safe
  (fail-closed on unknown sessions), and economics are measured per
  family.

Authority isolation: the engine is advisory — no I/O, no Finding
creation, no CausalGuard/ProofBundle/Replay bypass.
"""

from __future__ import annotations

from typing import Any
from uuid import NAMESPACE_URL, uuid5

import pytest

from tests.test_umdr46_phase_a_skg import BASE
from webpent.researcher.adaptive_engine import (
    LIFECYCLE_STATES,
    ExperimentLedger,
    ExperimentRecord,
    experiment_economics,
    lifecycle_of,
    partition_safe_parallel,
    reduce_final_lifecycle,
    select_adaptive,
)


def _mk(hid: str, vc: str, conf: float, target: str,
        ig: float | None = None):
    from webpent.production.hypothesis_adapter import canonical_hypothesis
    return canonical_hypothesis(
        id=uuid5(NAMESPACE_URL, f"umdr52w2t:{hid}"),
        statement=f"W2 test hypothesis {hid}",
        vuln_class=vc,
        origin="heuristic",
        origin_detail="umdr52 w2 test",
        target_url=target,
        expected_behavior="sanctioned path enforces its preconditions",
        negative_control="replay through the sanctioned state",
        deterministic_match=False,
        confidence_score=conf,
        info_gain=ig,
    )


def _rec(sig: str, cell: str, outcome: str, *, family: str = "idor",
         cause: str | None = None, info: float = 0.0, requests: int = 3):
    return ExperimentRecord(
        experiment_sig=sig, cell=cell, family=family, outcome=outcome,
        info_gained=info, requests=requests, failure_cause=cause)


# ---------------------------------------------------------------------------
# B1 — the lifecycle view
# ---------------------------------------------------------------------------

class TestLifecycleView:
    def test_eight_states_are_the_closed_set(self) -> None:
        assert LIFECYCLE_STATES == (
            "open", "deferred", "abandoned", "refuted",
            "promoted", "blocked", "inconclusive", "rabbit_hole")

    def test_open_statuses_map_open(self) -> None:
        from webpent.models.hypothesis import HypothesisStatus
        h = _mk("a", "idor", 0.5, BASE)
        assert h.status in (HypothesisStatus.UNEXPLORED,
                            HypothesisStatus.INVESTIGATING)
        assert lifecycle_of(h) == "open"

    def test_terminal_status_beats_live_action(self) -> None:
        from webpent.models.hypothesis import HypothesisStatus
        h = _mk("b", "idor", 0.5, BASE)
        h.status = HypothesisStatus.RESOLVED_FALSE
        # even a PROMOTE action cannot resurrect a refuted hypothesis
        assert lifecycle_of(h, "promote") == "refuted"

    def test_live_action_refines_open(self) -> None:
        h = _mk("c", "idor", 0.5, BASE)
        assert lifecycle_of(h, "defer") == "deferred"
        assert lifecycle_of(h, "rabbit_hole") == "rabbit_hole"
        assert lifecycle_of(h, "abandon") == "abandoned"
        assert lifecycle_of(h, "promote") == "promoted"

    def test_blocked_and_inconclusive_actions(self) -> None:
        h = _mk("d", "idor", 0.5, BASE)
        assert lifecycle_of(h, "blocked") == "blocked"
        assert lifecycle_of(h, "inconclusive") == "inconclusive"

    def test_unmapped_state_fails_closed(self) -> None:
        h = _mk("e", "idor", 0.5, BASE)
        object.__setattr__(h, "status", "mystery_state")
        with pytest.raises(ValueError):
            lifecycle_of(h)

    def test_reducer_counts_final_state_not_updates(self) -> None:
        # RC-6: the same hypothesis updated twice must be counted ONCE,
        # on its FINAL state — the pool is measured, not the updates.
        from webpent.models.hypothesis import HypothesisStatus
        h1, h2, h3 = (_mk("f1", "idor", 0.5, BASE),
                      _mk("f2", "idor", 0.5, BASE),
                      _mk("f3", "idor", 0.5, BASE))
        h2.status = HypothesisStatus.ABANDONED
        h3.status = HypothesisStatus.RESOLVED_FALSE
        counts = reduce_final_lifecycle(
            [h1, h2, h3],
            actions={str(h1.id): "defer"},
            blocked_ids={str(h3.id)})
        assert counts["deferred"] == 1
        assert counts["abandoned"] == 1
        assert counts["blocked"] == 1  # blocked wins over resolved_false
        assert sum(counts.values()) == 3


# ---------------------------------------------------------------------------
# B2 — the ledger: failure analyzed, repeats guarded
# ---------------------------------------------------------------------------

class TestExperimentLedger:
    def test_failure_without_cause_is_refused(self) -> None:
        led = ExperimentLedger()
        with pytest.raises(ValueError):
            led.record(_rec("sig1", "cell1", "fail", cause=None))

    def test_failure_with_cause_recorded(self) -> None:
        led = ExperimentLedger()
        led.record(_rec("sig1", "cell1", "fail",
                        cause="secondary principal's session was not "
                              "established before leg_a"))
        assert len(led.lessons()) == 1
        assert led.lessons()[0]["repeat_blocked_without_new_evidence"] is True

    def test_repeat_blocked_after_failure(self) -> None:
        led = ExperimentLedger()
        led.record(_rec("sigX", "cell9", "fail", cause="parser collapsed"))
        assert led.repeat_allowed("sigX", "cell9") is False

    def test_repeat_allowed_on_other_cell(self) -> None:
        led = ExperimentLedger()
        led.record(_rec("sigX", "cell9", "fail", cause="parser collapsed"))
        assert led.repeat_allowed("sigX", "cell10") is True

    def test_repeat_allowed_with_new_evidence(self) -> None:
        led = ExperimentLedger()
        led.record(_rec("sigX", "cell9", "fail", cause="parser collapsed"))
        assert led.repeat_allowed("sigX", "cell9", new_evidence=True) is True

    def test_success_and_inconclusive_do_not_block(self) -> None:
        led = ExperimentLedger()
        led.record(_rec("sigY", "cell2", "discriminated", info=0.4))
        led.record(_rec("sigZ", "cell2", "inconclusive"))
        assert led.repeat_allowed("sigY", "cell2") is True
        assert led.repeat_allowed("sigZ", "cell2") is True

    def test_unknown_outcome_refused(self) -> None:
        led = ExperimentLedger()
        with pytest.raises(ValueError):
            led.record(_rec("sig1", "cell1", "maybe"))


# ---------------------------------------------------------------------------
# B3 — selection, parallelism, economics
# ---------------------------------------------------------------------------

class TestSelectionAndParallelism:
    def _plans(self) -> list[dict[str, Any]]:
        return [
            {"plan_id": "p1", "info_gain": 0.1, "coverage_cell": "c1",
             "session_id": "sA", "principal_id": "u1"},
            {"plan_id": "p2", "info_gain": 0.5, "coverage_cell": "c2",
             "session_id": "sA", "principal_id": "u1"},
            {"plan_id": "p3", "info_gain": 0.3, "coverage_cell": "c3",
             "session_id": "sB", "principal_id": "u2"},
            {"plan_id": "p4", "info_gain": 0.2, "coverage_cell": "c4"},  # unknown session
        ]

    def test_selection_orders_by_score(self) -> None:
        led = ExperimentLedger()
        plans = self._plans()
        picked = select_adaptive(plans, led, score_fn=lambda p: p["info_gain"], k=2)
        assert [p["plan_id"] for p in picked] == ["p2", "p3"]

    def test_selection_falls_back_to_declared_info_gain(self) -> None:
        led = ExperimentLedger()
        picked = select_adaptive(self._plans(), led, k=1)
        assert picked[0]["plan_id"] == "p2"

    def test_repeat_guard_removes_failed_designs(self) -> None:
        led = ExperimentLedger()
        led.record(_rec("p2", "c2", "fail", cause="target fenced off"))
        picked = select_adaptive(self._plans(), led,
                                 score_fn=lambda p: p["info_gain"], k=4)
        assert all(p["plan_id"] != "p2" for p in picked)

    def test_no_shared_session_in_one_batch(self) -> None:
        batches = partition_safe_parallel(self._plans())
        for batch in batches:
            sessions = [p.get("session_id") for p in batch]
            known = [s for s in sessions if s is not None]
            assert len(known) == len(set(known))
            assert not (len(known) < len(sessions) and len(batch) > 1)

    def test_unknown_session_is_serial(self) -> None:
        batches = partition_safe_parallel(self._plans())
        p4_batches = [b for b in batches
                      if any(p["plan_id"] == "p4" for p in b)]
        assert len(p4_batches) == 1 and len(p4_batches[0]) == 1

    def test_same_principal_never_parallel(self) -> None:
        plans = [
            {"plan_id": "q1", "session_id": "sX", "principal_id": "u7"},
            {"plan_id": "q2", "session_id": "sY", "principal_id": "u7"},
        ]
        batches = partition_safe_parallel(plans)
        assert len(batches) == 2


class TestEconomics:
    def test_per_family_measurement(self) -> None:
        led = ExperimentLedger()
        led.record(_rec("a1", "c", "discriminated", family="idor",
                        info=0.5, requests=10))
        led.record(_rec("a2", "c", "fail", family="idor",
                        cause="fenced", requests=5))
        led.record(_rec("b1", "c", "inconclusive", family="redirect",
                        requests=2))
        econ = experiment_economics(led)
        idor = econ["families"]["idor"]
        assert idor["experiments"] == 3 or idor["experiments"] == 2
        assert idor["discriminated"] == 1 and idor["failures"] == 1
        assert idor["info_gained"] == 0.5 and idor["requests"] == 15
        assert idor["info_per_request"] == round(0.5 / 15, 8)
        assert idor["failure_causes"] == ["fenced"]
        redirect = econ["families"]["redirect"]
        assert redirect["inconclusive"] == 1
        assert redirect["info_per_request"] == 0.0

    def test_zero_cost_family_has_null_efficiency(self) -> None:
        led = ExperimentLedger()
        led.record(_rec("z1", "c", "inconclusive", family="x", requests=0))
        econ = experiment_economics(led)
        assert econ["families"]["x"]["info_per_request"] is None


# ---------------------------------------------------------------------------
# Authority isolation
# ---------------------------------------------------------------------------

class TestAuthorityIsolation:
    def _plans(self) -> list[dict[str, Any]]:
        return [
            {"plan_id": "p1", "info_gain": 0.1, "coverage_cell": "c1",
             "session_id": "sA", "principal_id": "u1"},
            {"plan_id": "p2", "info_gain": 0.5, "coverage_cell": "c2",
             "session_id": "sB", "principal_id": "u2"},
        ]

    def test_engine_is_pure_in_memory(self) -> None:
        import inspect

        from webpent.researcher import adaptive_engine as ae
        src = inspect.getsource(ae)
        # no network / execution / persistence primitives in the module
        for forbidden in ("requests.", "httpx", "socket", "subprocess",
                          "sqlite", "open(", "eval(", "exec("):
            assert forbidden not in src, forbidden

    def test_selection_executes_nothing(self) -> None:
        # select_adaptive returns plans; it cannot create findings —
        # the return type is the input type, advisory only.
        led = ExperimentLedger()
        picked = select_adaptive(self._plans(), led, k=4)
        assert all(isinstance(p, dict) for p in picked)
        assert all("finding" not in p for p in picked)
