"""POST-P0 Phase 1 — post-validation replan hardening acceptance tests.

Pins:
  * replan decisions are recorded in the operator-visible decision_log
    (decision_type "replan") with reason + budget metadata,
  * baseline (non-evidence-triggered) strategist passes do NOT emit
    replan decisions,
  * the third replan entry is blocked (budget = 2, unchanged),
  * new Tool-Confirmed evidence changes hypothesis ranking (ranks up),
  * new REFUTED evidence changes hypothesis ranking (ranks DOWN — a
    refuted claim must not outrank an untouched heuristic even when it
    carries an evidence bundle),
  * the graph still compiles with the replan seam in place (no second
    scheduler; run stays within the existing recursion structure).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from webpent.graph.builder import (
    NODE_DEVILS_ADVOCATE,
    build_graph,
    route_after_validator,
    strategist_node_with_replan_bookkeeping,
)
from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.models.hypothesis import Hypothesis
from webpent.models.targets import Target
from webpent.shared.prioritization import rank_open_hypotheses
from webpent.state.initial_state import build_initial_state


def _finding(confidence_level: str, *, url: str = "http://lab.local/a") -> Finding:
    bundle = None
    evidence_hash = None
    canary = None
    if confidence_level == "Refuted":
        # Refuted findings carry a negative-control bundle in real runs.
        bundle = {"baseline": {"status_code": 200}, "candidate": {"status_code": 200}}
    elif confidence_level == "Tool-Confirmed":
        # A realistically-confirmed finding: mini-HAR bundle, matching
        # hash, matched canary (bare tool-confirmed without bundle is a
        # pre-existing scoring path out of scope here).
        from webpent.utils.crypto import hash_evidence_bundle

        bundle = {
            "baseline": {"status_code": 200, "body": "ok"},
            "candidate": {"status_code": 200, "body": "ok<marker>"},
        }
        evidence_hash = hash_evidence_bundle(bundle)
        canary = "canary-marker"
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
        reasoning="fixture",
        vuln_class=VulnClass.SQLI.value,
        created_at=datetime.now(timezone.utc),
        thread_id="t",
        evidence_bundle=bundle,
        evidence_hash=evidence_hash,
        canary_token=canary,
    )


def _hypothesis(statement: str, *, evidence_refs: list | None = None) -> Hypothesis:
    return Hypothesis(
        target_url="http://lab.local/a",
        statement=statement,
        vuln_class=VulnClass.SQLI.value,
        origin="heuristic",
        confidence_score=0.5,
        evidence_refs=evidence_refs or [],
    )


def _state(*findings: Finding) -> dict:
    state = build_initial_state(target=Target(url="http://lab.local"), thread_id="t")
    state["findings"] = list(findings)
    return state


def test_replan_decision_logged_on_evidence_growth() -> None:
    state = _state(_finding("Tool-Confirmed"))
    update = strategist_node_with_replan_bookkeeping(state)
    replan_entries = [
        e for e in (update.get("decision_log") or [])
        if e.get("decision_type") == "replan"
    ]
    assert len(replan_entries) == 1
    entry = replan_entries[0]
    assert entry["metadata"]["evidence_before"] == 0
    assert entry["metadata"]["evidence_after"] == 1
    assert entry["metadata"]["replan_budget_used"] == 1
    assert entry["metadata"]["replan_budget_max"] == 2
    assert "evidence_monotonic_growth" in entry["rule_fired"]
    assert update["post_validation_replan_count"] == 1


def test_no_replan_decision_on_baseline_pass() -> None:
    # First strategist pass: no deterministic evidence yet -> baseline
    # recording only, no replan decision, no budget consumption.
    state = _state()
    update = strategist_node_with_replan_bookkeeping(state)
    replan_entries = [
        e for e in (update.get("decision_log") or [])
        if e.get("decision_type") == "replan"
    ]
    assert replan_entries == []
    assert update.get("post_validation_replan_count") in (None, 0)


def test_third_replan_blocked() -> None:
    finding = _finding("Tool-Confirmed")
    state = _state(finding)
    state["post_validation_replan_count"] = 2
    state["post_validation_replan_evidence_count"] = 0
    # Budget exhausted -> no further strategist re-entry even though
    # evidence grew from 0 to 1.
    assert route_after_validator(state) == NODE_DEVILS_ADVOCATE


def test_confirmed_evidence_improves_ranking() -> None:
    confirmed = _finding("Tool-Confirmed")
    hyp_hit = _hypothesis("sqli at /a", evidence_refs=[str(confirmed.id)])
    hyp_plain = _hypothesis("sqli at /b")
    state = _state(confirmed)
    state["hypotheses"] = [hyp_plain, hyp_hit]
    ranked = rank_open_hypotheses(list(state["hypotheses"]), state)
    assert [h.id for h, _ in ranked][0] == hyp_hit.id


def test_refuted_evidence_demotes_below_untouched_heuristic() -> None:
    refuted = _finding("Refuted")
    hyp_refuted = _hypothesis("sqli at /a", evidence_refs=[str(refuted.id)])
    hyp_plain = _hypothesis("sqli at /b")
    state = _state(refuted)
    state["hypotheses"] = [hyp_plain, hyp_refuted]
    ranked = rank_open_hypotheses(list(state["hypotheses"]), state)
    # The refuted hypothesis must rank BELOW the untouched heuristic.
    assert [h.id for h, _ in ranked][-1] == hyp_refuted.id


def test_graph_still_compiles_with_replan_seam() -> None:
    graph = build_graph(checkpointer=None, auto_approve=True)
    assert "strategist" in graph.nodes
    # Exactly one strategist entry point — no second scheduler.
    assert list(graph.nodes).count("strategist") == 1
