"""One-shot VIP campaign pass as a production-graph node (2026-10-24 layer 2).

This module is the ONLY new runtime surface of the VIP wiring: the frozen
``graph/builder.py`` imports :func:`vip_campaign_node` and registers it as
``vip_orchestrator`` behind the settings flag ``enable_vip_orchestrator``
(default off). Keeping the node body here (outside the frozen manifest)
means future changes to the pass never require another re-freeze.

Contract (mirrors the autonomous-controller node discipline):

  * ONE bounded pass per scan: the builder's router only enters this node
    while ``state["vip_campaign_runs"] < 1``, and every return bumps the
    counter — including the fail-soft path — so a crash cannot loop.
  * In-process only: the node runs the orchestrator's ``perceive`` and
    ``plan`` over data already in state (crawled surface records, the
    operator's CVE feed catalog, existing smart actions). It never calls
    ``act`` — there is no executor inside the graph — so it never sends
    requests, never executes payloads, and never promotes findings.
  * Advisory output: everything lands in ``vip_campaign_state`` with
    ``advisory_only`` / ``does_not_confirm`` preserved on every action.
    No findings, no smart_next_actions, no execution authority.
  * Fail-soft: exactly one broad containment around the whole pass; any
    exception degrades to a recorded ``failed_soft`` status.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from webpent.autonomous import CampaignInput, VipOrchestrator, VipOrchestratorConfig
from webpent.state.state import PentestState

# Ledger line cap parity: bound how many planned actions are copied into
# state so a pathological plan cannot bloat every checkpoint.
_MAX_RECORDED_ACTIONS = 50
_MAX_RECORDED_PARAMS = 50


def _scenario_ids(state: Mapping[str, Any]) -> list[str]:
    """Collect bounded scenario candidates already known to the graph.

    Reads only ids from ``smart_next_actions`` entries (the Smart Hunter
    task queue); tolerant of dict or string shapes, de-duplicated, and
    capped. Never invents scenario ids.
    """
    ids: list[str] = []
    for raw in (state.get("smart_next_actions") or [])[:200]:
        if isinstance(raw, Mapping):
            value = raw.get("scenario_id") or raw.get("scenario") or raw.get("id")
        else:
            value = raw
        if isinstance(value, str) and value and value not in ids:
            ids.append(value)
        if len(ids) >= _MAX_RECORDED_ACTIONS:
            break
    return ids


def _target_str(state: Mapping[str, Any]) -> str:
    """Best-effort canonical target string; empty when unavailable."""
    target = state.get("target")
    if isinstance(target, Mapping):
        return str(target.get("url") or target.get("base_url") or "")
    if isinstance(target, str):
        return target
    url = getattr(target, "url", None)
    return str(url) if isinstance(url, str) else ""


def _campaign_input(state: Mapping[str, Any]) -> CampaignInput:
    crawled = state.get("crawled_data")
    feed = state.get("cve_feed_catalog")
    return CampaignInput(
        crawled_data=crawled if isinstance(crawled, Mapping) else {},
        scenarios=_scenario_ids(state),
        target=_target_str(state),
        cve_feed=feed if isinstance(feed, (list, tuple)) else None,
    )


def vip_campaign_node(state: PentestState) -> dict[str, Any]:
    """Run one advisory VIP perceive->plan pass; return partial state."""
    runs = int(state.get("vip_campaign_runs", 0) or 0)
    record: dict[str, Any] = {
        "advisory_only": True,
        "does_not_confirm": True,
        "status": "ran",
    }
    try:
        orchestrator = VipOrchestrator(VipOrchestratorConfig())
        campaign_input = _campaign_input(state)
        perception = orchestrator.perceive(campaign_input)
        actions = orchestrator.plan(campaign_input, perception)
        record["perception"] = {
            "shared_parameters": [
                p.get("name")
                for p in perception.get("shared_parameters", [])[:_MAX_RECORDED_PARAMS]
            ],
            "cve_correlations": len(perception.get("cve_correlations", [])),
            "has_drift": bool(perception.get("has_drift")),
            "drift_high_priority": perception.get("drift_high_priority", 0),
        }
        planned_scenarios = {
            action.scenario_id
            for action in actions
            if action.kind == "scenario" and action.scenario_id
        }
        record["scenarios_requested"] = list(campaign_input.scenarios)
        record["scenarios_skipped"] = [
            sid for sid in campaign_input.scenarios if sid not in planned_scenarios
        ]
        record["planned_actions"] = [
            {
                "kind": action.kind,
                "target": action.target,
                "scenario_id": action.scenario_id,
                "priority": action.priority,
                "rationale": action.rationale,
                "advisory_only": action.advisory_only,
                "does_not_confirm": action.does_not_confirm,
            }
            for action in actions[:_MAX_RECORDED_ACTIONS]
        ]
    except Exception as exc:  # single fail-soft containment (residual risk 9)
        record["status"] = "failed_soft"
        record["error"] = f"{type(exc).__name__}"
        return {"vip_campaign_runs": runs + 1, "vip_campaign_state": record}
    return {"vip_campaign_runs": runs + 1, "vip_campaign_state": record}


__all__ = ["vip_campaign_node"]
