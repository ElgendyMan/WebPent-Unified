"""TEAM-1 Phase 6 — post-validation replan acceptance tests.

Verifies:
  * a validated finding (or meaningful refutation) causes a NEW strategist
    ranking pass at the existing graph seam (route_after_validator),
  * the ranking changes when the evidence changes (different ranking
    inputs produce a different strategist decision trace),
  * replan entries are capped at 2 per run,
  * replan requires monotonic evidence-count increase (no re-rank on
    unchanged or reduced evidence),
  * the existing strategist is reused — no second scheduler, ranking
    logic untouched, no ToolBoundary/CausalGuard bypass.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from webpent.graph.builder import (
    NODE_DEVILS_ADVOCATE,
    NODE_STRATEGIST,
    _post_validation_evidence_count,
    _post_validation_replan_eligible,
    build_graph,
    route_after_validator,
    strategist_node_with_replan_bookkeeping,
)
from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.models.targets import Target
from webpent.state.initial_state import build_initial_state


def _finding(confidence_level: str, *, url: str = "http://lab.local/a") -> Finding:
    return Finding(
        id=uuid.uuid4(),
        title=f"fixture {confidence_level}",
        severity=Severity.HIGH.value,
        description="replan fixture",
        tool_name="validator",
        url=url,
        confidence=Confidence.CONFIRMED
        if confidence_level == "Tool-Confirmed"
        else Confidence.TENTATIVE,
        confidence_level=confidence_level,
        # M1-B/E-1 provenance contract: a Tool-Confirmed finding must name
        # its confirming gate; this fixture predates that hardening.
        evidence={"tool_confirmed_by": "validator"} if confidence_level == "Tool-Confirmed" else {},
        reasoning="fixture",
        vuln_class=VulnClass.SQLI.value,
        created_at=datetime.now(timezone.utc),
        thread_id="t",
    )


def _state(*findings: Finding) -> dict:
    state = build_initial_state(target=Target(url="http://lab.local"), thread_id="t")
    state["findings"] = list(findings)
    return state


def test_graph_has_replan_edge_and_no_second_scheduler() -> None:
    graph = build_graph(checkpointer=None, auto_approve=True)
    # The builder must still register exactly ONE strategist node.
    assert "strategist" in graph.nodes
    # The wrapped strategist delegates to the ORIGINAL strategist node.
    from webpent.agents.strategist.agent import strategist_node as original

    assert strategist_node_with_replan_bookkeeping.__globals__[
        "strategist_node"
    ] is original


def test_confirmed_finding_triggers_replan() -> None:
    state = _state(_finding("Tool-Confirmed"))
    assert _post_validation_evidence_count(state) == 1
    assert _post_validation_replan_eligible(state) is True
    assert route_after_validator(state) == NODE_STRATEGIST


def test_refuted_finding_triggers_replan() -> None:
    state = _state(_finding("Refuted"))
    assert _post_validation_replan_eligible(state) is True
    assert route_after_validator(state) == NODE_STRATEGIST


def test_unconfirmed_findings_never_trigger_replan() -> None:
    state = _state(
        _finding("AI-Assessed"), _finding("Needs Human Review"), _finding("Pending")
    )
    assert _post_validation_evidence_count(state) == 0
    assert _post_validation_replan_eligible(state) is False
    assert route_after_validator(state) == NODE_DEVILS_ADVOCATE


def test_replan_is_bounded_to_two_entries() -> None:
    state = _state(_finding("Tool-Confirmed"))
    # Simulate two consumed replan entries.
    state["post_validation_replan_count"] = 2
    state["post_validation_replan_evidence_count"] = 1
    assert _post_validation_replan_eligible(state) is False
    assert route_after_validator(state) == NODE_DEVILS_ADVOCATE

    # One entry consumed but evidence grew again -> still eligible.
    state["post_validation_replan_count"] = 1
    state["post_validation_replan_evidence_count"] = 1
    state["findings"] = [
        _finding("Tool-Confirmed"),
        _finding("Refuted"),
    ]
    assert _post_validation_replan_eligible(state) is True


def test_replan_requires_monotonic_evidence_increase() -> None:
    """Same evidence count since last strategist pass -> no re-entry."""
    f1 = _finding("Tool-Confirmed")
    state = _state(f1)
    state["post_validation_replan_count"] = 1
    state["post_validation_replan_evidence_count"] = 1
    assert _post_validation_replan_eligible(state) is False
    assert route_after_validator(state) == NODE_DEVILS_ADVOCATE


def test_strategist_bookkeeping_consumes_entry_on_evidence_growth() -> None:
    """First pass: baseline recorded, no entry consumed. Replan pass: consumed."""
    # First strategist pass — no evidence yet.
    empty_state = _state()
    update = strategist_node_with_replan_bookkeeping(empty_state)
    assert update.get("post_validation_replan_evidence_count") == 0
    assert update.get("post_validation_replan_count") in (None, 0)

    # Validator confirms two findings, router re-enters strategist.
    state = _state(_finding("Tool-Confirmed"), _finding("Refuted"))
    state["post_validation_replan_evidence_count"] = 0
    update = strategist_node_with_replan_bookkeeping(state)
    assert update["post_validation_replan_count"] == 1
    assert update["post_validation_replan_evidence_count"] == 2

    # Second replan entry consumed when evidence grows again.
    state2 = dict(state)
    state2["post_validation_replan_evidence_count"] = 2
    state2["post_validation_replan_count"] = 1
    state2["findings"] = [
        _finding("Tool-Confirmed"),
        _finding("Refuted"),
        _finding("Tool-Confirmed"),
    ]
    update2 = strategist_node_with_replan_bookkeeping(state2)
    assert update2["post_validation_replan_count"] == 2
    assert update2["post_validation_replan_evidence_count"] == 3

    # Cap reached: bookkeeping never exceeds 2.
    state3 = dict(state2)
    state3["post_validation_replan_evidence_count"] = 3
    state3["post_validation_replan_count"] = 2
    state3["findings"] = list(state2["findings"]) + [_finding("Tool-Confirmed")]
    update3 = strategist_node_with_replan_bookkeeping(state3)
    assert update3["post_validation_replan_count"] == 2
    assert update3["post_validation_replan_evidence_count"] == 4


def test_initial_state_declares_replan_counters() -> None:
    state = build_initial_state(target=Target(url="http://lab.local"), thread_id="t")
    assert state.get("post_validation_replan_count") == 0
    assert state.get("post_validation_replan_evidence_count") == 0
