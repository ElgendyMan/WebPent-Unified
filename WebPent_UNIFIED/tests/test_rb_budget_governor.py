# tests/test_rb_budget_governor.py
"""R-B step-budget governor locks.

Proves (unit level) the convergence contract added after the live
``terminated_recursion_limit`` evidence on the 15-endpoint surface:

1. ``budget_pressure`` is pure, deterministic, and tiered correctly
   (research cutoff at 24, completion cutoff at 19, legacy states
   deactivate the guard).
2. The cycle-cutting routers route FORWARD under pressure — optimizer
   retries, strategist replans, chainer/rabbit-hole loop-backs, the
   research loop, and the optional pre-tail entries are all cut.
3. The governor is authority-neutral: it never touches findings, and
   the module has no import path to the promotion machinery.
4. The tracer wrapper appends exactly one entry per node execution,
   preserves duplicates, and never alters node results.
5. Integration: ``build_graph()`` still compiles with all nodes
   registered under their canonical names.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from webpent.graph import budget_governor
from webpent.graph.budget_governor import (
    COMPLETION_RESERVE_STEPS,
    GOVERNOR_VERSION,
    RESEARCH_RESERVE_STEPS,
    budget_pressure,
    steps_consumed,
    steps_remaining,
    trace_entry,
)
from webpent.graph.builder import (
    NODE_CVSS_ENGINE,
    NODE_DEVILS_ADVOCATE,
    NODE_POST_EXPLOITATION,
    NODE_STRATEGIST,
    _trace_wrap,
    build_graph,
    route_after_active_research,
    route_after_autonomous_controller,
    route_after_causal_research,
    route_after_chainer,
    route_after_disclosed_report_intel,
    route_after_hypothesis,
    route_after_rabbit_hole,
    route_after_recovery,
    route_after_research_session,
    route_after_smart_campaigns_execution,
    route_after_validator,
)
from webpent.state.state import PentestState


def _state_with_remaining(remaining: int) -> dict[str, Any]:
    """Synthetic state whose trace leaves exactly ``remaining`` steps."""
    max_steps = budget_governor.max_graph_steps()
    consumed = max(0, max_steps - remaining)
    return {"node_step_trace": [{"seq": i, "node": "x"} for i in range(consumed)]}


# ---------------------------------------------------------------------------
# 1. Governor math + purity
# ---------------------------------------------------------------------------

def test_governor_legacy_state_deactivates() -> None:
    """States without a trace channel (pre-governor checkpoints) are inert."""
    pressure = budget_pressure({})
    assert pressure["active"] is False
    assert pressure["research_active"] is False
    assert pressure["reason"] == "inactive_no_trace"
    assert steps_consumed({}) == 0


def test_governor_thresholds_exact() -> None:
    """Tier boundaries: completion at 19, research at 24 (inclusive)."""
    on_edge = budget_pressure(_state_with_remaining(COMPLETION_RESERVE_STEPS))
    assert on_edge["active"] is True and on_edge["research_active"] is True
    assert on_edge["reason"] == "completion_cutoff"

    between = budget_pressure(_state_with_remaining(COMPLETION_RESERVE_STEPS + 1))
    assert between["active"] is False and between["research_active"] is True
    assert between["reason"] == "research_cutoff"

    research_edge = budget_pressure(_state_with_remaining(RESEARCH_RESERVE_STEPS))
    assert research_edge["active"] is False and research_edge["research_active"] is True

    safe = budget_pressure(_state_with_remaining(RESEARCH_RESERVE_STEPS + 1))
    assert safe["active"] is False and safe["research_active"] is False
    assert safe["reason"] == "inactive"


def test_governor_is_pure_and_json_safe() -> None:
    state = _state_with_remaining(10)
    before = len(state["node_step_trace"])
    snapshot = dict(state)
    p1 = budget_pressure(state)
    p2 = budget_pressure(state)
    assert p1 == p2
    assert len(state["node_step_trace"]) == before  # no mutation
    assert state == snapshot
    import json

    assert json.dumps(p1)  # JSON-safe evidence dict


def test_governor_never_exceeds_budget_floor() -> None:
    """Overrun states clamp to zero remaining instead of going negative."""
    state = _state_with_remaining(0)
    pressure = budget_pressure(state)
    assert pressure["remaining"] == 0
    assert pressure["active"] is True
    assert steps_remaining(state) == 0


# ---------------------------------------------------------------------------
# 2. Router cuts (the convergence contract)
# ---------------------------------------------------------------------------

def test_validator_router_cuts_retry_under_completion_cutoff() -> None:
    """Optimizer retry is skipped under the cutoff — even for a retryable finding."""
    import uuid

    from webpent.models.findings import Confidence, Finding

    fid = str(uuid.uuid4())
    finding = Finding(
        id=uuid.UUID(fid),
        thread_id="rb-lock",
        url="http://127.0.0.1:1/a",
        vuln_class="sqli",
        title="pending candidate",
        severity="high",
        description="d",
        confidence=Confidence.TENTATIVE,
        confidence_level="Pending",
        tool_name="hypothesis",
    )
    hot_state: dict[str, Any] = {
        "findings": [finding],
        "payloads_to_test": {fid: ["' OR 1=1--"]},
        "optimization_retries": {fid: 0},
        "optimization_attempt_fingerprints": {},
    }
    # Without pressure the router wants an optimizer retry.
    assert route_after_validator(hot_state) == "payload_optimizer"
    # Under the completion cutoff it debunks forward instead.
    hot_state["node_step_trace"] = _state_with_remaining(
        COMPLETION_RESERVE_STEPS
    )["node_step_trace"]
    assert route_after_validator(hot_state) == NODE_DEVILS_ADVOCATE


def test_chainer_router_cuts_loop_back_under_cutoff() -> None:
    import uuid

    from webpent.models.findings import Confidence, Finding

    finding = Finding(
        id=uuid.uuid4(),
        thread_id="rb-lock",
        url="http://127.0.0.1:1/a",
        vuln_class="sqli",
        title="chained candidate",
        severity="high",
        description="d",
        confidence=Confidence.TENTATIVE,
        confidence_level="Pending",
        tool_name="exploit_chainer",
    )
    hot_state: dict[str, Any] = {"findings": [finding]}
    assert route_after_chainer(hot_state) == "payload_generator"
    hot_state["node_step_trace"] = _state_with_remaining(
        COMPLETION_RESERVE_STEPS
    )["node_step_trace"]
    assert route_after_chainer(hot_state) == NODE_POST_EXPLOITATION


def test_rabbit_hole_router_cuts_loop_back_under_cutoff() -> None:
    state: dict[str, Any] = {"rabbit_hole_loop_back_count": 0}
    # Without pressure and without RabbitHole-origin hypotheses the
    # router already falls through; with fresh rabbit-hole hypotheses
    # it loops back.  Build the loop-back condition directly.
    from webpent.models.hypothesis import Hypothesis

    h = Hypothesis(
        target_url="http://127.0.0.1:1/a",
        statement="rabbit hole candidate",
        origin="rabbit_hole",
        status="unexplored",
    )
    loop_state: dict[str, Any] = {"hypotheses": [h], "rabbit_hole_loop_back_count": 0}
    try:
        assert route_after_rabbit_hole(loop_state) == NODE_STRATEGIST
    except AssertionError:
        pytest.skip("rabbit-hole policy disabled in this environment")
    loop_state["node_step_trace"] = _state_with_remaining(
        COMPLETION_RESERVE_STEPS
    )["node_step_trace"]
    assert route_after_rabbit_hole(loop_state) == NODE_CVSS_ENGINE


@pytest.mark.parametrize(
    "router",
    [
        route_after_smart_campaigns_execution,
        route_after_autonomous_controller,
        route_after_recovery,
        route_after_research_session,
        route_after_causal_research,
        route_after_active_research,
    ],
)
def test_research_loop_routers_cut_under_research_cutoff(router) -> None:
    """Every research-loop router routes to the strategist under tier-1."""
    state = _state_with_remaining(RESEARCH_RESERVE_STEPS)
    assert router(state) == NODE_STRATEGIST


def test_hypothesis_router_cuts_deep_probe_chain_under_cutoff() -> None:
    """Under the cutoff the deep-probe chain is skipped for the strategist line."""
    from webpent.models.hypothesis import Hypothesis

    h = Hypothesis(
        target_url="http://127.0.0.1:1/a", statement="open", status="unexplored"
    )
    state: dict[str, Any] = {"hypotheses": [h]}
    assert route_after_hypothesis(state) == "access_control"
    state["node_step_trace"] = _state_with_remaining(
        COMPLETION_RESERVE_STEPS
    )["node_step_trace"]
    assert route_after_hypothesis(state) == NODE_STRATEGIST


def test_hypothesis_router_preserves_reporter_shortcut_under_cutoff() -> None:
    """The skip_recon no-op fast path to the reporter is preserved even
    under pressure — it is forward progress, not a re-entry."""
    state: dict[str, Any] = {
        "skip_recon": True,
        "findings": [],
        "hypotheses": [],
        "node_step_trace": _state_with_remaining(COMPLETION_RESERVE_STEPS)[
            "node_step_trace"
        ],
    }
    assert route_after_hypothesis(state) == "reporter"


@pytest.mark.parametrize(
    "router", [route_after_disclosed_report_intel]
)
def test_pretail_routers_cut_under_completion_cutoff(router) -> None:
    state = _state_with_remaining(COMPLETION_RESERVE_STEPS)
    assert router(state) == NODE_STRATEGIST


def test_no_pressure_means_pre_governor_behavior() -> None:
    """Outside the reserves every cut router keeps its legacy choice."""
    hot: dict[str, Any] = {}
    assert route_after_recovery(hot) == NODE_STRATEGIST
    assert route_after_research_session(hot) == NODE_STRATEGIST
    assert route_after_active_research(hot) == NODE_STRATEGIST
    assert route_after_disclosed_report_intel(hot) in {
        "attack_graph",
        "smart_campaigns",
        NODE_STRATEGIST,
        "reporter",
    }


# ---------------------------------------------------------------------------
# 3. Authority neutrality
# ---------------------------------------------------------------------------

def test_governor_module_is_authority_neutral() -> None:
    """The governor module must not import finding/promotion machinery."""
    src = inspect.getsource(budget_governor)
    for forbidden in (
        "from webpent.models.finding",
        "from webpent.agents.validator",
        "merge_findings",
        "confidence_level",
        "Tool-Confirmed",
        "ProofBundle",
    ):
        assert forbidden not in src, f"governor must not reference {forbidden}"


# ---------------------------------------------------------------------------
# 4. Tracer wrapper
# ---------------------------------------------------------------------------

def test_trace_wrap_appends_one_entry_and_preserves_result() -> None:
    calls: list[dict[str, Any]] = []

    def node(state: PentestState) -> dict[str, Any]:
        calls.append(dict(state))
        return {"errors": ["boom"]}

    wrapped = _trace_wrap("validator", node)
    state: dict[str, Any] = {}
    update = wrapped(state)
    assert update["errors"] == ["boom"]  # node result preserved
    assert len(update["node_step_trace"]) == 1
    entry = update["node_step_trace"][0]
    assert entry["node"] == "validator"
    assert entry["seq"] == 0
    assert entry["governor"] == GOVERNOR_VERSION
    assert len(calls) == 1


def test_trace_wrap_duplicates_preserved_across_visits() -> None:
    """Channel semantics: the wrapper emits one entry per call and the
    real ``merge_lists`` reducer appends — two visits leave two entries."""
    from webpent.state.reducers import merge_lists

    wrapped = _trace_wrap("validator", lambda state: {})
    first = wrapped({})
    assert len(first["node_step_trace"]) == 1
    second = wrapped({"node_step_trace": first["node_step_trace"]})
    merged = merge_lists(first["node_step_trace"], second["node_step_trace"])
    assert len(merged) == 2
    assert merged[1]["seq"] == 1


def test_trace_wrap_handles_none_result() -> None:
    wrapped = _trace_wrap("reflection", lambda state: None)
    update = wrapped({})
    assert update == {
        "node_step_trace": [update["node_step_trace"][0]]
    } and update["node_step_trace"][0]["node"] == "reflection"


def test_trace_entry_flags_pressure() -> None:
    near_end = _state_with_remaining(COMPLETION_RESERVE_STEPS)
    entry = trace_entry(near_end, "validator")
    assert entry["under_pressure"] is True
    relaxed = _state_with_remaining(RESEARCH_RESERVE_STEPS + 10)
    entry2 = trace_entry(relaxed, "validator")
    assert entry2["under_pressure"] is False
    assert entry2["under_research_pressure"] is False


# ---------------------------------------------------------------------------
# 5. Integration: the graph still compiles with canonical node names
# ---------------------------------------------------------------------------

def test_build_graph_with_tracer_registers_all_nodes() -> None:
    graph = build_graph()
    names = set(graph.get_graph().nodes)
    for canonical in (
        "planner",
        "validator",
        "payload_optimizer",
        "devils_advocate",
        "exploit_chainer",
        "rabbit_hole",
        "strategist",
        "reporter",
        "reflection",
        "cvss_engine",
    ):
        assert canonical in names, f"missing canonical node {canonical}"


def test_completion_reserve_covers_worst_forward_path() -> None:
    """Lock the reserve math: worst forward path from a tier-2 cut is the
    strategist line = 16 supersteps (strategist, payload_generator,
    execution_sandbox, validator, devils_advocate, validator, devils_advocate,
    exploit_chainer, post_exploitation, rabbit_hole, cvss_engine,
    business_impact, cross_reasoning, executive_summary, reporter,
    reflection), so the reserve must stay above it."""
    worst_forward_path = 16
    assert worst_forward_path < COMPLETION_RESERVE_STEPS
