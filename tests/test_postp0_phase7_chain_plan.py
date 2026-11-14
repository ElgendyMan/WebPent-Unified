"""POST-P0 Phase 7 — limited chain execution v1 (chain plan).

Pins:
  * chain_plan is derived from EXISTING attack-graph output ONLY when the
    fail-closed enable_attack_graph flag is on,
  * every plan step is a Tool-Confirmed finding; AI-Assessed/Pending
    findings never enter the plan,
  * chain length is bounded to 3 steps,
  * artifact hand-off keys are present per step (artifact_keys),
  * the plan parks as "pending" — steps execute only via the existing
    HITL sandbox/validator pipeline; an unconfirmed step can never make
    the chain Confirmed,
  * no speculative exploit codegen: the chainer emits plans and bounded
    candidate findings through the standard pipeline only.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from webpent.agents.exploit_chainer.agent import (
    _MAX_CHAIN_PLAN_STEPS,
    build_chain_plan_from_attack_graph,
)
from webpent.models.findings import Confidence, Finding
from webpent.models.targets import Target
from webpent.state.initial_state import build_initial_state


def _finding(confidence_level: str, severity: str = "high") -> Finding:
    return Finding(
        id=uuid.uuid4(),
        title=f"fixture {confidence_level}",
        severity=severity,
        description="chain plan fixture",
        tool_name="validator",
        url="http://lab.local/a",
        confidence=Confidence.CONFIRMED
        if confidence_level == "Tool-Confirmed"
        else Confidence.TENTATIVE,
        confidence_level=confidence_level,
        # M1-B/E-1 provenance contract: a Tool-Confirmed finding must name
        # its confirming gate; the fixture predates that hardening.
        evidence={"tool_confirmed_by": "validator"} if confidence_level == "Tool-Confirmed" else {},
        reasoning="fixture",
        vuln_class="open_redirect",
        created_at=datetime.now(timezone.utc),
        thread_id="t",
    )


def _graph_for(*findings: Finding) -> dict:
    nodes = {
        f"finding:{f.id}": {
            "id": f"finding:{f.id}",
            "kind": "finding",
            "label": "finding",
            "status": f.confidence_level,
            "criticality": f.severity,
        }
        for f in findings
    }
    return {"nodes": nodes, "edges": []}


def _state(*findings: Finding, graph: dict | None = None) -> dict:
    state = build_initial_state(target=Target(url="http://lab.local"), thread_id="t")
    state["findings"] = list(findings)
    if graph is not None:
        state["attack_graph"] = graph
    return state


def _flag_on(monkeypatch) -> None:
    import webpent.config.settings as settings_mod

    monkeypatch.setattr(
        settings_mod, "get_settings",
        lambda: settings_mod.Settings(enable_attack_graph=True),
    )


def _flag_off(monkeypatch) -> None:
    import webpent.config.settings as settings_mod

    monkeypatch.setattr(
        settings_mod, "get_settings",
        lambda: settings_mod.Settings(enable_attack_graph=False),
    )


def test_flag_off_never_builds_plan(monkeypatch) -> None:
    _flag_off(monkeypatch)
    f1, f2 = _finding("Tool-Confirmed"), _finding("Tool-Confirmed")
    state = _state(f1, f2, graph=_graph_for(f1, f2))
    assert build_chain_plan_from_attack_graph(state) is None


def test_plan_requires_two_tool_confirmed_steps(monkeypatch) -> None:
    _flag_on(monkeypatch)
    confirmed = _finding("Tool-Confirmed")
    assessed = _finding("AI-Assessed")
    # One confirmed + one AI-Assessed: no chain (steps < 2).
    state = _state(confirmed, assessed, graph=_graph_for(confirmed, assessed))
    assert build_chain_plan_from_attack_graph(state) is None
    # Two confirmed: plan built.
    f2 = _finding("Tool-Confirmed")
    state2 = _state(confirmed, f2, graph=_graph_for(confirmed, f2))
    plan = build_chain_plan_from_attack_graph(state2)
    assert plan is not None
    assert len(plan["steps"]) == 2
    # AI-Assessed finding is NOT in the plan.
    step_ids = {s["finding_id"] for s in plan["steps"]}
    assert str(assessed.id) not in step_ids


def test_plan_is_bounded_to_three_steps_and_parks_pending(monkeypatch) -> None:
    _flag_on(monkeypatch)
    findings = [_finding("Tool-Confirmed", severity="high") for _ in range(5)]
    state = _state(*findings, graph=_graph_for(*findings))
    plan = build_chain_plan_from_attack_graph(state)
    assert plan is not None
    assert len(plan["steps"]) == _MAX_CHAIN_PLAN_STEPS == 3
    assert plan["status"] == "pending"
    assert plan["max_steps"] == 3
    # Artifact hand-off: every step carries artifact_keys and the plan
    # aggregates them.
    for step in plan["steps"]:
        assert step["artifact_keys"] == [f"findings.{step['finding_id']}.evidence_bundle"]
        assert step["execution_status"] == "pending_hitl"
    assert len(plan["artifact_keys"]) == len(plan["steps"])


def test_plan_absent_without_attack_graph_state(monkeypatch) -> None:
    _flag_on(monkeypatch)
    f1, f2 = _finding("Tool-Confirmed"), _finding("Tool-Confirmed")
    state = _state(f1, f2, graph=None)
    assert build_chain_plan_from_attack_graph(state) is None


def test_node_emits_chain_plan_when_available(monkeypatch) -> None:
    from webpent.agents.exploit_chainer.agent import exploit_chainer_node

    _flag_on(monkeypatch)
    f1, f2 = _finding("Tool-Confirmed"), _finding("Tool-Confirmed")
    state = _state(f1, f2, graph=_graph_for(f1, f2))
    result = exploit_chainer_node(state)
    plan = result.get("chain_plan")
    assert plan is not None
    assert plan["status"] == "pending"
    # The plan is an operator artifact: no execution fields that could
    # bypass the HITL sandbox interrupt.
    assert "execute" not in plan
    assert "pending_hitl" in plan["steps"][0]["execution_status"]
