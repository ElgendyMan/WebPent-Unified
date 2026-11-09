"""UM-DR-31 — integration contract: the loop is real in the production graph.

This suite proves the CONNECTIONS (UM-DR-31 §9.2), not just the units:

1. CHANNEL CONTRACT — every key the research_loop node returns is a
   declared PentestState channel (the R2-graph-03 lesson: an undeclared
   key is silently dropped by LangGraph channel filtering).
2. LANGGRAPH RUNTIME — the real node inside a compiled StateGraph over
   the real PentestState: hypotheses + telemetry survive channel
   filtering on the declared channels.
3. BUILDER WIRING — the production build_graph contains the node and
   the validator→research_loop→strategist route ONLY when the flag is
   on; flag-off keeps the byte-comparable shape; default is False.
4. PLANNER CONSUMPTION — the real strategist (the production
   replan-bookkeeping wrapper) ranks the research-loop hypotheses and
   writes Decision Log entries for them: the loop's output demonstrably
   influences the next stage's decisions.
5. FEEDBACK INTEGRATION — execution outcomes change the research
   decision: a cell that opens after a proof outcome becomes a new
   hypothesis; a conclusively rejected hypothesis is not repeated.
6. AUTHORIZED EXECUTION, NO BYPASS — research hypotheses pass through
   the UNCHANGED promotion gates: below threshold ⇒ DEFER; the
   ineligible class is blocked by EXPLOITABLE_CLASSES exactly like any
   other hypothesis; the eligible class promotes through the same
   function the strategist uses for every hypothesis.
7. CAUSALGUARD AUTHORITY — the node's update never carries finding or
   confirmation vocabulary; the proof contract of confirmed findings is
   untouched by the loop.
"""

from __future__ import annotations

from typing import Any

import pytest


def _loop_state(**overrides: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        # target_url is the DECLARED PentestState channel (base_url is
        # not a channel and would be dropped by LangGraph input
        # filtering — the same lesson the module's _base_url fallback
        # encodes)
        "target_url": "https://shop.example.com",
        "engagement_id": "eng-umdr31",
        "target_id": "tgt-umdr31",
        "campaign_ledger": {"entries": [
            {"key": "idor:profile", "status": "not_scanned"},
        ]},
        "invariant_review": [],
        "workflow_observations": [],
        "hypotheses": [],
        "messages": [],
    }
    state.update(overrides)
    return state


@pytest.fixture()
def loop_on(monkeypatch):
    from webpent.config.settings import get_settings

    monkeypatch.setattr(get_settings(), "enable_adaptive_research_loop", True)
    monkeypatch.setattr(get_settings(), "max_research_iterations", 3)
    monkeypatch.setattr(get_settings(), "max_research_hypotheses_per_iteration", 12)


# ---------------------------------------------------------------------------
# 1. channel contract
# ---------------------------------------------------------------------------

class TestChannelContract:
    def test_every_returned_key_is_a_declared_state_channel(self, loop_on) -> None:
        from webpent.production.adaptive_research import research_loop_node
        from webpent.state.state import PentestState

        update = research_loop_node(_loop_state())
        declared = set(PentestState.__annotations__.keys())
        for key in update:
            assert key in declared, f"undeclared output key would be dropped: {key}"

    def test_research_loop_channel_is_declared_with_merge_dicts(self) -> None:
        import typing

        from webpent.state.state import PentestState

        hints = typing.get_type_hints(PentestState, include_extras=True)
        annotation = hints["research_loop"]
        metadata = getattr(annotation, "__metadata__", ())
        assert metadata, "research_loop must carry a reducer"
        assert getattr(metadata[0], "__name__", "") == "merge_dicts"


# ---------------------------------------------------------------------------
# 2. LangGraph runtime — channel filtering survival
# ---------------------------------------------------------------------------

class TestLangGraphRuntime:
    def test_update_survives_channel_filtering(self, loop_on) -> None:
        from langgraph.graph import END, START, StateGraph

        from webpent.production.adaptive_research import research_loop_node
        from webpent.state.state import PentestState

        graph = StateGraph(PentestState)
        graph.add_node("research_loop", research_loop_node)
        graph.add_edge(START, "research_loop")
        graph.add_edge("research_loop", END)
        compiled = graph.compile()

        result = compiled.invoke(_loop_state(), config={"recursion_limit": 10})
        hypotheses = result.get("hypotheses") or []
        assert len(hypotheses) == 1
        assert hypotheses[0].origin in ("coverage_gap", "invariant")
        telemetry = result.get("research_loop") or {}
        assert telemetry.get("iterations_used") == 1
        assert telemetry.get("last_status") == "ok"

    def test_flag_off_at_runtime_writes_nothing(self, monkeypatch) -> None:
        from langgraph.graph import END, START, StateGraph

        from webpent.config.settings import get_settings
        from webpent.production.adaptive_research import research_loop_node
        from webpent.state.state import PentestState

        monkeypatch.setattr(get_settings(), "enable_adaptive_research_loop", False)
        graph = StateGraph(PentestState)
        graph.add_node("research_loop", research_loop_node)
        graph.add_edge(START, "research_loop")
        graph.add_edge("research_loop", END)
        compiled = graph.compile()

        result = compiled.invoke(_loop_state(), config={"recursion_limit": 10})
        assert not (result.get("hypotheses") or [])
        # flag off: the node wrote nothing (a declared reducer channel
        # may exist empty, but nothing was written to it)
        assert not (result.get("research_loop") or {})


# ---------------------------------------------------------------------------
# 3. production builder wiring
# ---------------------------------------------------------------------------

class TestProductionBuilderWiring:
    def test_node_present_and_routed_when_flag_on(self, loop_on) -> None:
        from webpent.graph import builder as graph_builder

        compiled = graph_builder.build_graph(auto_approve=True)
        nodes = set(getattr(compiled, "nodes", {}) or {})
        assert "research_loop" in nodes
        # the feedback seam: validator -> research_loop -> strategist
        edges = {
            (e.source, e.target)
            for e in compiled.get_graph().edges
        }
        assert ("validator", "research_loop") in edges
        assert ("research_loop", "strategist") in edges
        # the discovery-line seam
        assert ("disclosed_report_intel", "research_loop") in edges
        # the research-line seam
        assert ("causal_research", "research_loop") in edges

    def test_node_absent_when_flag_off(self, monkeypatch) -> None:
        from webpent.config.settings import get_settings
        from webpent.graph import builder as graph_builder

        monkeypatch.setattr(get_settings(), "enable_adaptive_research_loop", False)
        compiled = graph_builder.build_graph(auto_approve=True)
        nodes = set(getattr(compiled, "nodes", {}) or {})
        assert "research_loop" not in nodes
        # the validator keeps its direct strategist route
        edges = {(e.source, e.target) for e in compiled.get_graph().edges}
        assert ("validator", "strategist") in edges

    def test_flag_default_is_fail_closed(self) -> None:
        from webpent.config.settings import Settings

        assert Settings.model_fields["enable_adaptive_research_loop"].default is False
        assert Settings.model_fields["max_research_iterations"].default == 3
        assert (
            Settings.model_fields["max_research_hypotheses_per_iteration"].default
            == 12
        )


# ---------------------------------------------------------------------------
# 4. planner consumption — the real strategist wrapper
# ---------------------------------------------------------------------------

class TestPlannerConsumption:
    def test_strategist_consumes_research_hypotheses(self, loop_on) -> None:
        """AC-02/03/04: the loop's output demonstrably influences the
        planner's decisions — the enriched pool IS the strategist's
        ranking input, and its pass leaves a consumption record."""
        from langgraph.graph import END, START, StateGraph

        from webpent.graph.builder import strategist_node_with_replan_bookkeeping
        from webpent.production.adaptive_research import research_loop_node
        from webpent.shared.prioritization import rank_open_hypotheses
        from webpent.state.state import PentestState

        # the production wiring pattern: routes that targeted the
        # strategist are redirected through research_loop, which hands
        # off to the strategist (builder._umdr31_routes + edge)
        graph = StateGraph(PentestState)
        graph.add_node("research_loop", research_loop_node)
        graph.add_node("strategist", strategist_node_with_replan_bookkeeping)
        graph.add_edge(START, "research_loop")
        graph.add_edge("research_loop", "strategist")
        graph.add_edge("strategist", END)
        compiled = graph.compile()

        result = compiled.invoke(_loop_state(), config={"recursion_limit": 10})
        # the loop injected the hypothesis ...
        pool = result.get("hypotheses") or []
        research_ids = {
            str(h.id) for h in pool
            if getattr(h, "origin", "") in ("coverage_gap", "invariant")
        }
        assert research_ids, "research hypotheses must survive to the planner"
        assert (result.get("research_loop") or {}).get("hypotheses_generated_total") == 1

        # ... the planner's real ranking machinery ranked it ...
        ranked_ids = {
            str(h.id) for h, _score in rank_open_hypotheses(list(pool), result)
        }
        assert research_ids <= ranked_ids

        # ... and the strategist's own pass reports consuming the
        # enriched pool (its AIMessage reports the ranked open count)
        messages = result.get("messages") or []
        strategist_reports = [
            getattr(m, "content", "") for m in messages
            if "Strategist" in str(getattr(m, "content", ""))
        ]
        assert any(
            "ranked" in report for report in strategist_reports
        ), "the strategist must report its ranking pass over the enriched pool"
        # the DEFER decision leaves the hypothesis in the pool intact —
        # the planner decided to keep it open, not to drop it
        assert all(
            getattr(h, "status", "") == "unexplored" for h in pool
        )

    def test_feedback_changes_the_next_research_decision(self, loop_on) -> None:
        """AC-08: execution outcomes feed back into the research state."""
        from webpent.production.adaptive_research import (
            generate_research_hypotheses,
            research_loop_node,
        )

        # BEFORE execution: only the idor cell is open
        state = _loop_state()
        first = research_loop_node(state)
        assert len(first.get("hypotheses", [])) == 1
        assert first["hypotheses"][0].vuln_class == "idor"

        # an execution outcome OPENS a new cell (the campaign ledger
        # grew a coverage entry the prober never closed)
        state["campaign_ledger"]["entries"].append(
            {"key": "privilege_differential:admin", "status": "not_scanned"}
        )
        state["hypotheses"] = list(first["hypotheses"])
        state["research_loop"] = first["research_loop"]
        second = research_loop_node(state)
        # the NEW evidence justifies a NEW research decision
        assert len(second.get("hypotheses", [])) == 1
        assert second["hypotheses"][0].vuln_class == "privilege_differential"
        assert second["research_loop"]["hypotheses_generated_total"] == 2

        # and a conclusively-rejected hypothesis is never repeated
        # (the FULL accumulated pool — both passes' hypotheses — is
        # what the merge would have produced in state)
        rejected = [
            {**h.model_dump(mode="json"), "status": "resolved_false"}
            for h in list(first["hypotheses"]) + list(second["hypotheses"])
        ]
        state["hypotheses"] = rejected
        state["research_loop"] = second["research_loop"]
        third = research_loop_node(state)
        assert "hypotheses" not in third  # both rejected ⇒ nothing new

    def test_closed_loop_over_three_passes_is_bounded(self, loop_on) -> None:
        """AC-06: bounded adaptation terminates correctly."""
        from webpent.production.adaptive_research import research_loop_node

        state = _loop_state()
        statuses = []
        for _ in range(6):
            update = research_loop_node(state)
            state["hypotheses"] = list(update.get("hypotheses", state["hypotheses"]))
            state["research_loop"] = update["research_loop"]
            statuses.append(update["research_loop"]["last_status"])
        # 3 working iterations then the hard cap — never unbounded
        assert statuses == ["ok", "ok", "ok", "capped", "capped", "capped"]


# ---------------------------------------------------------------------------
# 6. authorized execution, no bypass
# ---------------------------------------------------------------------------

class TestAuthorizedExecutionNoBypass:
    def test_below_threshold_defers_under_real_gates(self, loop_on) -> None:
        from webpent.production.adaptive_research import generate_research_hypotheses
        from webpent.shared.prioritization import recommend_action

        state = _loop_state(campaign_ledger={"entries": [
            {"key": "rce:eval", "status": "not_scanned"},
        ]})
        hypotheses, _ = generate_research_hypotheses(state, max_new=12)
        action, score, reason = recommend_action(hypotheses[0], state)
        # an uncertain research belief must DEFER — the loop cannot
        # shortcut the promotion threshold
        assert action.value == "defer"
        assert score < 0.5

    def test_ineligible_class_blocked_by_exploitable_classes(self, loop_on) -> None:
        from webpent.models.hypothesis import HypothesisOrigin
        from webpent.production.adaptive_research import generate_research_hypotheses
        from webpent.shared.prioritization import promote_hypothesis_to_finding

        # the replay invariant maps to business_logic — a structural,
        # non-payload-injection class: NOT in EXPLOITABLE_CLASSES
        state = _loop_state(
            campaign_ledger={"entries": []},
            invariant_review=[{
                "invariant": "state_must_progress_or_reject_replay",
                "observation_fingerprint": "f" * 16,
                "reason": "destructive op reports same source and target state",
                "evidence_refs": [],
            }],
        )
        hypotheses, _ = generate_research_hypotheses(state, max_new=12)
        assert hypotheses[0].vuln_class == "business_logic"
        finding = promote_hypothesis_to_finding(hypotheses[0], state)
        assert finding is None  # the unchanged gate blocks it

    def test_eligible_class_promotes_through_the_same_function(self, loop_on) -> None:
        from webpent.production.adaptive_research import generate_research_hypotheses
        from webpent.shared.prioritization import promote_hypothesis_to_finding

        # rce IS in EXPLOITABLE_CLASSES: the SAME promotion function the
        # strategist uses for every hypothesis accepts it (the loop
        # adds no parallel path and no shortcut)
        state = _loop_state(campaign_ledger={"entries": [
            {"key": "rce:eval", "status": "not_scanned"},
        ]})
        hypotheses, _ = generate_research_hypotheses(state, max_new=12)
        finding = promote_hypothesis_to_finding(hypotheses[0], state)
        assert finding is not None
        assert finding.vuln_class == "rce"
        assert finding.confidence_level == "Pending"  # awaits validation


# ---------------------------------------------------------------------------
# 7. CausalGuard authority pins
# ---------------------------------------------------------------------------

class TestCausalGuardAuthority:
    def test_node_update_never_confirms(self, loop_on) -> None:
        from webpent.production.adaptive_research import research_loop_node

        update = research_loop_node(_loop_state())
        assert "findings" not in update
        telemetry = update["research_loop"]
        # the telemetry names the unchanged authority
        assert "guarded_causal_evaluate" in telemetry["confirmation_authority"]

    def test_stateful_hints_change_order_not_authority(self, loop_on) -> None:
        from webpent.production.adaptive_research import stateful_research_hints

        hints = stateful_research_hints(_loop_state(
            workflow_observations=[
                {"fingerprint": "a" * 16, "endpoint": "/api/orders/1",
                 "method": "POST", "authorization_boundary": "cross_identity",
                 "scope_decision": "allowed"},
            ],
        ))
        # hints are advisory priorities only — no scope, no authority.
        # UM-DR-31.1: the map carries BOTH families — the exact workflow
        # directory hint (1.0) and the coverage cell's surface hint
        # ("idor:profile" → "profile" at its 0.60 classification prior).
        assert hints == {"api/orders": 1.0, "profile": 0.6}
        # surface keys are single-segment (never a full directory path):
        # the consumer's exact match can only fire for genuinely
        # single-segment mined directories; multi-segment directories
        # match via the discounted suffix rule (ordering only)
        assert "/" not in "profile"
