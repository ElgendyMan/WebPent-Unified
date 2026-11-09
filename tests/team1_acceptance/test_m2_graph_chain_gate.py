# tests/team1_acceptance/test_m2_graph_chain_gate.py
"""M2-impl WP-G — THE WINDOW EXIT GATE (Dispatch #009, R8 of Ruling M2-001).

The gate: a graph-level chain test proving a NON-EMPTY research loop through
the COMPILED production graph:

    test-only fixture producer -> intake -> registration -> rehydration ->
    campaign lane executes >= 1 candidate -> non-empty research loop

RED-2 P-6 proved the through-graph path had ZERO genuine coverage: one
"graph" test swallowed invoke exceptions and proved activation via a direct
node call; the other monkeypatched a fake. Both are fixed (test honesty);
this module adds the genuine through-graph chain the window exits on.
"""
from __future__ import annotations

import logging

import pytest


def _authorized_env(monkeypatch) -> None:
    """Operator flag authorization posture (WP-F): the chain exercises the
    fixture path, which the fail-closed flag gates govern."""
    monkeypatch.setenv("WEBPENT_EXPLORATION_INGRESS_ENABLED", "true")
    monkeypatch.setenv("WEBPENT_STATIC_FIXTURE_SOURCE_ENABLED", "true")
    monkeypatch.setenv("WEBPENT_MULTI_PRINCIPAL_EXECUTION_ENABLED", "true")


def _chain_fixture(engagement_id: str = "e_gate") -> dict:
    """TEST-ONLY fixture producer (the M2-impl-without-M5 validation path:
    the admission layer stays unwired; the test itself produces the admitted
    fixture with a binding matching the active engagement)."""
    return {
        "fixture_id": "fx_gate",
        "content_digest": "sha256:" + "f" * 64,
        "source_type": "static_json",
        "engagement_id": engagement_id,
        "engagement_instance_id": "inst_" + engagement_id[2:],
        "target_fingerprint": "tgtfp_" + engagement_id,
        "secret_scan_result": {"categories": []},
        "route_shape": {
            "endpoint_template": "/api/invoices/{id}",
            "method": "GET",
            "parameter_names": ["id"],
            "response_shape": "redacted",
            "authorization_hints": "pb",
            "candidate_rationale": "adv",
            "defect_family_hint": "IDOR",
        },
        "object_reference_plan": {
            "owner_object_ref": "INV-B-204",
            "candidate_object_ref": "INV-B-204",
            "negative_control_object_ref": "INV-X-000",
        },
        "baseline_candidate_control_plan": {},
    }


def _run_chain(monkeypatch, engagement_id: str = "e_gate") -> dict:
    """Stream the REAL compiled graph through the chain and collect the
    watched markers from the node updates (no exception swallowing, no
    direct node calls)."""
    _authorized_env(monkeypatch)
    from webpent.graph.builder import build_graph
    from webpent.models.targets import Target

    graph = build_graph()
    state = {
        "engagement_id": engagement_id,
        "target": Target(url="http://127.0.0.1:9301"),
        "target_url": "http://127.0.0.1:9301",
        "engagement_instance_id": "inst_" + engagement_id[2:],
        "target_fingerprint": "tgtfp_" + engagement_id,
        "admitted_fixtures": [_chain_fixture(engagement_id)],
        "campaign_budget_remaining": 20,
        "skip_recon": False,
        "auto_approve": False,
        "observed_preconditions": (),
        "blocked_preconditions": (),
    }
    watched = (
        "modern_spine_active", "advisory_registered_count",
        "advisory_hypotheses_published", "advisory_registered",
        "_hypotheses_registered", "research_campaign_skipped",
        "research_campaign_executed", "research_campaign_result",
        "research_loop_rehydrated", "research_loop_rehydrated_failed",
        "research_loop_active_candidates", "avi_production_dispatch",
        "fabric_dispatch_trace", "_modern_orchestrator", "_audit_chain",
        "research_campaign_hypotheses_rejected",
    )
    seen: dict = {}
    for chunk in graph.stream(state, config={"recursion_limit": 40},
                              stream_mode="updates"):
        for _node, update in chunk.items():
            if isinstance(update, dict):
                seen.update({k: v for k, v in update.items() if k in watched})
        if seen.get("research_campaign_executed") or seen.get("research_campaign_skipped"):
            break
    return seen


def test_exit_gate_nonempty_research_loop_through_graph(monkeypatch):
    """THE WINDOW EXIT GATE (charter G4/WP-G): fixture -> intake ->
    registration -> rehydration -> campaign executes >= 1 candidate ->
    non-empty research loop — ALL through the compiled graph, with the
    prohibited object transport absent."""
    seen = _run_chain(monkeypatch)
    # modern spine really ran
    assert seen.get("modern_spine_active") is True
    # intake + registration produced a candidate (M2 -> M6 chain alive)
    assert seen.get("advisory_registered_count", 0) >= 1
    assert seen.get("advisory_hypotheses_published", 0) >= 1
    # rehydration recovered it into the re-derived loop (R3)
    assert seen.get("research_loop_rehydrated", 0) >= 1
    assert seen.get("research_loop_rehydrated_failed", 0) == 0
    assert seen.get("research_loop_active_candidates", 0) >= 1
    # the campaign lane EXECUTED (no skip — NF-M2-01 fixed end-to-end)
    assert seen.get("research_campaign_executed") is True
    assert "research_campaign_skipped" not in seen
    # a real dispatch happened (fabric trace carries the advisory candidate)
    trace = seen.get("fabric_dispatch_trace") or []
    assert isinstance(trace, list) and len(trace) >= 1
    assert any("adv_" in str(step.get("candidate_id", "")) for step in trace
               if isinstance(step, dict))
    # R2: the orchestrator object never rode the state
    assert "_modern_orchestrator" not in seen
    # WP-A: the audit descriptor travelled (real chain fired at the seam)
    assert isinstance(seen.get("_audit_chain"), dict)


def test_exit_gate_reruns_deterministically(monkeypatch):
    """The gate is a standing test: a second engagement id produces the same
    chain outcome (fresh durable state — no dedupe cross-talk)."""
    seen = _run_chain(monkeypatch, engagement_id="e_gate_rerun")
    assert seen.get("research_campaign_executed") is True
    assert seen.get("research_loop_rehydrated", 0) >= 1


def test_recon_to_campaign_edge_wired_gap_r2():
    """WP-H / GAP-R2 disposition: `verify_research_campaign_edge` had ZERO
    callers (a dead advertised protection). It is now wired as this test
    helper — asserting the compiled graph really routes recon ->
    research_campaign."""
    from webpent.graph.builder import build_graph
    from webpent.production.advisory_registration import (
        verify_research_campaign_edge,
    )
    graph = build_graph()
    raw = graph.get_graph().edges
    edges: dict[str, set[str]] = {}
    for edge in raw:
        src = getattr(edge, "source", None)
        dst = getattr(edge, "target", None)
        if src and dst:
            edges.setdefault(src, set()).add(dst)
    assert verify_research_campaign_edge(edges) is True


def test_skip_is_operator_visible(monkeypatch, caplog):
    """WP-E (R7): a campaign-lane skip is LOUD — the marker persists to
    state AND a named warning reaches the operator log. RED-2 P-1.4 proved
    the as-shipped skip was fully silent."""
    _authorized_env(monkeypatch)
    from webpent.graph.builder import build_graph
    from webpent.models.targets import Target

    graph = build_graph()
    state = {
        "engagement_id": "e_silent",
        "target": Target(url="http://127.0.0.1:9302"),
        "target_url": "http://127.0.0.1:9302",
        "skip_recon": False,
        "auto_approve": False,
        "observed_preconditions": (),
        "blocked_preconditions": (),
    }
    seen: dict = {}
    with caplog.at_level(logging.WARNING, logger="webpent.graph.builder"):
        for chunk in graph.stream(state, config={"recursion_limit": 40},
                                  stream_mode="updates"):
            for _node, update in chunk.items():
                if isinstance(update, dict):
                    seen.update(update)
            if seen.get("research_campaign_skipped") or seen.get("research_campaign_executed"):
                break
    assert seen.get("research_campaign_skipped") == "no_hypotheses"
    assert any("RESEARCH CAMPAIGN SKIPPED" in rec.message for rec in caplog.records)
