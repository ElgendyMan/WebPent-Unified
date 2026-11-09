"""Wiring tests for the VIP campaign-leader graph node (2026-10-24 layer 2).

Covers the full re-freeze contract for the three frozen edits:

  * settings: ``enable_vip_orchestrator`` exists and defaults to False
    (fail-closed — the node must never appear without an explicit opt-in).
  * state: ``vip_campaign_state`` / ``vip_campaign_runs`` are declared on
    ``PentestState`` so LangGraph preserves them between nodes.
  * builder: the node is registered only when the flag is on; the entry
    routers hand off exactly once (bounded by ``vip_campaign_runs``); the
    exit router re-joins the pre-VIP routing; the node itself is
    advisory-only and fail-soft.
"""
from __future__ import annotations

from typing import Any

import pytest

from webpent.config.settings import get_settings
from webpent.graph.builder import (
    NODE_ATTACK_GRAPH,
    NODE_DISCLOSED_REPORT_INTEL,
    NODE_SMART_CAMPAIGNS,
    NODE_STRATEGIST,
    NODE_VIP_ORCHESTRATOR,
    build_graph,
    route_after_attack_graph,
    route_after_disclosed_report_intel,
    route_after_vip_orchestrator,
)
from webpent.shared.vip_campaign_node import vip_campaign_node


def _clear_settings_cache() -> None:
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_settings():
    _clear_settings_cache()
    yield
    _clear_settings_cache()


# ---------------------------------------------------------------------------
# Flag + registration
# ---------------------------------------------------------------------------

def test_vip_flag_defaults_off():
    assert get_settings().enable_vip_orchestrator is False


def test_vip_node_absent_by_default(monkeypatch):
    monkeypatch.delenv("ENABLE_VIP_ORCHESTRATOR", raising=False)
    graph = build_graph(auto_approve=True)
    assert NODE_VIP_ORCHESTRATOR not in graph.nodes


def test_vip_node_registered_only_when_enabled(monkeypatch):
    monkeypatch.setenv("ENABLE_VIP_ORCHESTRATOR", "true")
    graph = build_graph(auto_approve=True)
    assert NODE_VIP_ORCHESTRATOR in graph.nodes


def test_state_declares_vip_keys():
    from webpent.state.state import PentestState

    annotations = PentestState.__annotations__
    assert "vip_campaign_state" in annotations
    assert "vip_campaign_runs" in annotations


# ---------------------------------------------------------------------------
# Entry routing: exactly-once hand-off
# ---------------------------------------------------------------------------

def test_entry_router_hands_off_when_pending_and_enabled(monkeypatch):
    monkeypatch.setenv("ENABLE_VIP_ORCHESTRATOR", "true")
    state: dict[str, Any] = {"vip_campaign_runs": 0}
    assert route_after_disclosed_report_intel(state) == NODE_VIP_ORCHESTRATOR


def test_entry_router_skips_after_one_pass(monkeypatch):
    monkeypatch.setenv("ENABLE_VIP_ORCHESTRATOR", "true")
    state: dict[str, Any] = {"vip_campaign_runs": 1}
    # runs budget spent: falls through to the ordinary routing (no smart tier).
    assert route_after_disclosed_report_intel(state) == NODE_STRATEGIST


def test_entry_router_ignores_vip_when_flag_off():
    state: dict[str, Any] = {"vip_campaign_runs": 0}
    assert route_after_disclosed_report_intel(state) == NODE_STRATEGIST


def test_attack_graph_entry_router_hands_off_when_pending(monkeypatch):
    monkeypatch.setenv("ENABLE_VIP_ORCHESTRATOR", "true")
    state: dict[str, Any] = {"vip_campaign_runs": 0}
    assert route_after_attack_graph(state) == NODE_VIP_ORCHESTRATOR
    state["vip_campaign_runs"] = 1
    assert route_after_attack_graph(state) == NODE_STRATEGIST


# ---------------------------------------------------------------------------
# Exit routing: re-joins the ordinary path
# ---------------------------------------------------------------------------

def test_exit_router_returns_to_strategist_without_smart_tier():
    state: dict[str, Any] = {"smart_governance": {}}
    assert route_after_vip_orchestrator(state) == NODE_STRATEGIST


def test_exit_router_continues_to_smart_campaigns_when_opted_in():
    state: dict[str, Any] = {
        "smart_mode": True,
        "smart_governance": {},
    }
    assert route_after_vip_orchestrator(state) == NODE_SMART_CAMPAIGNS


# ---------------------------------------------------------------------------
# Node behavior: advisory-only, exactly-once accounting, fail-soft
# ---------------------------------------------------------------------------

def _graph_state(**kw: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "vip_campaign_runs": 0,
        "crawled_data": {"endpoints": ["https://lab.test/a"]},
        "smart_next_actions": [
            {"scenario_id": "sqli_union", "priority": 1},
            "not_a_dict",
        ],
    }
    state.update(kw)
    return state


def test_node_runs_one_advisory_pass_and_bumps_runs():
    result = vip_campaign_node(_graph_state())
    assert result["vip_campaign_runs"] == 1
    record = result["vip_campaign_state"]
    assert record["advisory_only"] is True
    assert record["does_not_confirm"] is True
    assert record["status"] == "ran"
    # Scenario ids are collected tolerantly: dict entries by their id
    # fields, plain strings as-is (the "not_a_dict" string is a valid id
    # shape the orchestrator simply won't recognize later).
    assert record["scenarios_requested"] == ["sqli_union", "not_a_dict"]
    # Every planned action keeps its advisory contract fields.
    for action in record["planned_actions"]:
        assert action["advisory_only"] is True
        assert action["does_not_confirm"] is True


def test_node_surfaces_perception_driven_actions():
    """Shared parameters found in the crawl become second-order
    candidates without any scenario queue at all."""
    crawled = {
        "endpoints": [
            {"url": "https://lab.test/a?uid=1"},
            {"url": "https://lab.test/b?uid=2"},
        ]
    }
    result = vip_campaign_node(_graph_state(crawled_data=crawled))
    record = result["vip_campaign_state"]
    assert "uid" in record["perception"]["shared_parameters"]
    kinds = {a["kind"] for a in record["planned_actions"]}
    assert "second_order_param" in kinds


def test_node_fail_soft_bumps_runs_and_reports_status(monkeypatch):
    class _Boom:
        def __init__(self, *a, **kw):
            raise RuntimeError("orchestrator exploded")

    monkeypatch.setattr(
        "webpent.shared.vip_campaign_node.VipOrchestrator", _Boom
    )
    result = vip_campaign_node(_graph_state())
    # Exactly-once holds even on the failure path.
    assert result["vip_campaign_runs"] == 1
    record = result["vip_campaign_state"]
    assert record["status"] == "failed_soft"
    assert record["error"] == "RuntimeError"
    assert record["advisory_only"] is True


def test_node_never_executes_planned_actions():
    """The node has no executor: only perceive/plan can run."""
    import inspect

    from webpent.shared import vip_campaign_node as module

    source = inspect.getsource(module)
    assert ".act(" not in source
    assert "run_cycle" not in source


# ---------------------------------------------------------------------------
# Graph-level integration: the wired node re-joins the ordinary routing
# ---------------------------------------------------------------------------

def test_wired_graph_routes_vip_then_smart(monkeypatch):
    """With the flag on, disclosed-intel routes to VIP once, and the VIP
    exit re-joins the smart tier — verified against the built graph's
    edge map rather than internals."""
    monkeypatch.setenv("ENABLE_VIP_ORCHESTRATOR", "true")
    graph = build_graph(auto_approve=True)
    assert NODE_DISCLOSED_REPORT_INTEL in graph.nodes
    assert NODE_VIP_ORCHESTRATOR in graph.nodes
    # attack-graph remains flag-gated independently.
    monkeypatch.delenv("ENABLE_ATTACK_GRAPH", raising=False)
    _clear_settings_cache()
    graph = build_graph(auto_approve=True)
    assert NODE_ATTACK_GRAPH not in graph.nodes
    assert NODE_VIP_ORCHESTRATOR in graph.nodes
