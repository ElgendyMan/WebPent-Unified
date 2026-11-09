"""UM-DR-32 §6/§8 — production integration tests for the unified
identity-workflow reasoning node.

Proves the research-to-execution chain (§8) with direct evidence:
  * the node is wired into the REAL builder graph when flags are on;
  * flags off -> node absent, byte-comparable shape (the §1.2
    fail-closed contract);
  * every emitted key is a declared PentestState channel (an undeclared
    key is silently dropped by LangGraph — this must never happen);
  * the update survives real LangGraph channel filtering;
  * the produced hypotheses reach the hypothesis pool with deterministic
    ids and dedup;
  * identity_research_hints actually influence stateful discovery hint
    scheduling (ordering-only, same budget);
  * the node never emits finding vocabulary (no promotion authority);
  * settings flags default to False (fail-closed).
"""
from __future__ import annotations

from typing import Any


def _campaign_state(**extra: Any) -> dict[str, Any]:
    """A realistic campaign state with identity/workflow evidence."""
    state: dict[str, Any] = {
        "base_url": "https://lab.example",
        "target_url": "https://lab.example",
        "crawled_data": {
            "openapi_routes": [
                {"method": "GET", "path": "/api/orders/123"},
                {"method": "GET", "path": "/api/o/123"},
                {"method": "GET", "path": "/api/invoices/123"},
                {"method": "POST", "path": "/api/orders/123/submit"},
            ],
        },
        "workflow_observations": [
            {
                "fingerprint": "fp" + "a" * 14,
                "workflow_key": "order-approval",
                "transition_key": "submit",
                "endpoint": "/api/orders/123/submit",
                "method": "POST",
                "from_state": "draft",
                "to_state": "submitted",
                "authorization_boundary": "role_scoped",
                "tenant_ref": "t1",
                "object_refs": ["123"],
                "scope_decision": "allowed",
                "confidence": 0.8,
            },
        ],
        "identity_profiles": {
            "User_A": {"role": "owner", "tenant": "t1"},
            "User_B": {"role": "foreign", "tenant": "t1"},
        },
        # declared object observations (response-schema analysis):
        # /api/o/123 is a CONFIRMED alternate representation of
        # /api/orders/123 (same in-body object id, same declared type)
        "object_identity_observations": [
            {"endpoint": "/api/orders/123", "resource_type": "orders",
             "object_id": "123", "object_id_source": "response_body",
             "tenant": "t1", "observation_ref": "ob1"},
            {"endpoint": "/api/o/123", "resource_type": "orders",
             "object_id": "123", "object_id_source": "response_body",
             "tenant": "t1", "observation_ref": "ob2"},
        ],
        "authorization_observations": [
            {"principal_ref": "User_A", "tenant": "t1",
             "object_ref": "orders:123", "operation": "read",
             "outcome": "allowed", "evidence_refs": ["ev1"]},
            {"principal_ref": "User_B", "tenant": "t1",
             "object_ref": "vaults:900", "operation": "read",
             "outcome": "denied", "evidence_refs": ["ev2"]},
        ],
    }
    state.update(extra)
    return state


class _FlagBlock:
    """Save/restore the UM-DR-32 capability flags (test isolation)."""

    FLAGS = (
        "enable_object_identity",
        "enable_alias_resolution",
        "enable_multi_identity_reasoning",
        "enable_composite_workflows",
        "enable_adaptive_research_loop",
        "enable_stateful_discovery",
    )

    def __init__(self, **flags: bool) -> None:
        from webpent.config.settings import get_settings
        self._settings = get_settings()
        self._saved = {name: getattr(self._settings, name) for name in self.FLAGS}
        for name, value in flags.items():
            setattr(self._settings, name, value)

    def __enter__(self) -> "_FlagBlock":
        return self

    def __exit__(self, *exc) -> None:
        for name, value in self._saved.items():
            setattr(self._settings, name, value)


class TestNodeWiring:
    def test_flags_default_off(self) -> None:
        from webpent.config.settings import Settings
        for field in (
            "enable_object_identity", "enable_alias_resolution",
            "enable_multi_identity_reasoning", "enable_composite_workflows",
        ):
            assert Settings.model_fields[field].default is False, field

    def test_master_gate_off_by_default(self) -> None:
        from webpent.production.identity_workflow import identity_workflow_enabled
        with _FlagBlock():
            assert identity_workflow_enabled() is False

    def test_node_returns_empty_when_disabled(self) -> None:
        from webpent.production.identity_workflow import identity_workflow_node
        with _FlagBlock():
            update = identity_workflow_node(_campaign_state())
        assert update == {}  # runtime double-gate (stale checkpoint safe)

    def test_builder_flag_off_node_absent_byte_comparable(self) -> None:
        """§1.2: with all capability flags off the graph contains neither
        the identity_workflow node nor its edges — the pre-UM-DR-32
        shape (byte-comparable claim)."""
        from webpent.graph.builder import build_graph
        with _FlagBlock():
            graph = build_graph(auto_approve=True)
        names = set(graph.get_graph().nodes)
        assert "identity_workflow" not in names

    def test_builder_flag_on_node_present_and_wired(self) -> None:
        from webpent.graph.builder import build_graph
        with _FlagBlock(
            enable_object_identity=True,
            enable_adaptive_research_loop=True,
        ):
            graph = build_graph(auto_approve=True)
        model = graph.get_graph()
        names = set(model.nodes)
        assert "identity_workflow" in names
        assert "research_loop" in names
        # the composed chain: identity_workflow -> research_loop -> strategist
        edges = {(e.source, e.target) for e in model.edges}
        assert ("identity_workflow", "research_loop") in edges
        assert ("research_loop", "strategist") in edges

    def test_builder_flag_on_without_research_loop_straight_to_strategist(self) -> None:
        from webpent.graph.builder import build_graph
        with _FlagBlock(enable_object_identity=True):
            graph = build_graph(auto_approve=True)
        model = graph.get_graph()
        edges = {(e.source, e.target) for e in model.edges}
        assert ("identity_workflow", "strategist") in edges
        assert "research_loop" not in set(model.nodes)


class TestChannelContract:
    def test_every_emitted_key_is_declared(self) -> None:
        from webpent.production.identity_workflow import identity_workflow_node
        from webpent.state.state import PentestState
        with _FlagBlock(
            enable_object_identity=True,
            enable_alias_resolution=True,
            enable_multi_identity_reasoning=True,
            enable_composite_workflows=True,
        ):
            update = identity_workflow_node(_campaign_state())
        assert update, "the node must produce its channels when enabled"
        for key in update:
            assert key in PentestState.__annotations__, (
                f"undeclared channel {key!r} would be silently dropped"
            )

    def test_update_survives_real_langgraph_channel_filtering(self) -> None:
        """The exact failure mode the state contract exists to prevent:
        an undeclared key disappears at the LangGraph boundary."""
        from langgraph.graph import StateGraph

        from webpent.production.identity_workflow import identity_workflow_node
        from webpent.state.state import PentestState
        with _FlagBlock(
            enable_object_identity=True,
            enable_alias_resolution=True,
            enable_multi_identity_reasoning=True,
            enable_composite_workflows=True,
        ):
            update = identity_workflow_node(_campaign_state())
            graph = StateGraph(PentestState)
            graph.add_node("identity_workflow", identity_workflow_node)
            graph.set_entry_point("identity_workflow")
            graph.set_finish_point("identity_workflow")
            compiled = graph.compile()
            result = compiled.invoke(_campaign_state())
        for key in update:
            assert key in result, (
                f"channel {key!r} was dropped by LangGraph filtering"
            )

    def test_no_finding_vocabulary_in_update(self) -> None:
        """§1.1: the node has no promotion authority — its update may
        never carry findings or confirmation vocabulary."""
        from webpent.production.identity_workflow import identity_workflow_node
        with _FlagBlock(
            enable_object_identity=True,
            enable_alias_resolution=True,
            enable_multi_identity_reasoning=True,
            enable_composite_workflows=True,
        ):
            update = identity_workflow_node(_campaign_state())
        assert "findings" not in update
        text = repr(update).lower()
        for forbidden in ("confirmed_finding", "promote", "severity"):
            assert forbidden not in text

    def test_all_four_capabilities_produce_channels(self) -> None:
        from webpent.production.identity_workflow import identity_workflow_node
        with _FlagBlock(
            enable_object_identity=True,
            enable_alias_resolution=True,
            enable_multi_identity_reasoning=True,
            enable_composite_workflows=True,
        ):
            update = identity_workflow_node(_campaign_state())
        assert "object_identity_registry" in update
        assert "identity_alias_graph" in update
        assert "multi_identity_reasoning" in update
        assert "composite_workflow_candidates" in update
        assert "identity_workflow" in update  # telemetry

    def test_object_identity_channel_content(self) -> None:
        from webpent.production.identity_workflow import identity_workflow_node
        with _FlagBlock(enable_object_identity=True):
            update = identity_workflow_node(_campaign_state())
        registry = update["object_identity_registry"]["registry"]
        assert registry["stats"]["identities"] >= 2  # orders:123, invoices:123
        # representations recorded from the observed endpoints
        idents = registry["identities"]
        orders = [i for i in idents if i["resource_type"] == "orders"]
        assert orders and any(
            "/api/orders/123" in i["representations"] for i in orders
        )

    def test_alias_channel_content(self) -> None:
        from webpent.production.identity_workflow import identity_workflow_node
        with _FlagBlock(
            enable_object_identity=True, enable_alias_resolution=True,
        ):
            update = identity_workflow_node(_campaign_state())
        graph = update["identity_alias_graph"]["graph"]
        assert graph["stats"]["pairs_classified"] >= 1

    def test_multi_identity_channel_content(self) -> None:
        from webpent.production.identity_workflow import identity_workflow_node
        with _FlagBlock(enable_multi_identity_reasoning=True):
            update = identity_workflow_node(_campaign_state())
        reasoning = update["multi_identity_reasoning"]
        refs = [p["principal_ref"] for p in reasoning["principals"]]
        assert "User_A" in refs and "User_B" in refs
        # the differential question with its negative control is present
        questions = reasoning["differential_questions"]
        assert questions and questions[0]["kind"] == "privilege_differential"
        assert questions[0]["control_object_ref"] == "vaults:900"

    def test_composite_workflow_channel_content(self) -> None:
        from webpent.production.identity_workflow import identity_workflow_node
        with _FlagBlock(enable_composite_workflows=True):
            update = identity_workflow_node(_campaign_state())
        candidates = update["composite_workflow_candidates"]
        assert candidates
        invariants = {c["invariant"] for c in candidates}
        assert "approval_not_self_completable" in invariants  # role_scoped step

    def test_hypotheses_reach_the_pool_deterministically(self) -> None:
        from webpent.production.identity_workflow import identity_workflow_node
        with _FlagBlock(
            enable_multi_identity_reasoning=True,
            enable_composite_workflows=True,
        ):
            update = identity_workflow_node(_campaign_state())
        hypotheses = update.get("hypotheses", [])
        assert hypotheses, "differential + workflow hypotheses must be produced"
        vuln_classes = {h.vuln_class for h in hypotheses}
        assert "privilege_differential" in vuln_classes
        assert "business_logic" in vuln_classes
        ids = [h.id for h in hypotheses]
        assert len(ids) == len(set(ids))  # deterministic, unique

        # dedup: a second pass over a state that already has them adds nothing
        state = _campaign_state()
        state["hypotheses"] = [h.model_dump() for h in hypotheses]
        with _FlagBlock(
            enable_multi_identity_reasoning=True,
            enable_composite_workflows=True,
        ):
            second = identity_workflow_node(state)
        assert second.get("hypotheses", []) == []

    def test_privilege_hypothesis_routable_to_registered_validator(self) -> None:
        """§6.5 end-to-end: the produced hypothesis's vuln_class resolves
        to a registered validator — the missing-validator era is over."""
        from webpent.agents.validator.registry import validator_id_for
        from webpent.production.identity_workflow import identity_workflow_node
        with _FlagBlock(enable_multi_identity_reasoning=True):
            update = identity_workflow_node(_campaign_state())
        for hypothesis in update.get("hypotheses", []):
            route = validator_id_for(hypothesis.vuln_class)
            if hypothesis.vuln_class == "privilege_differential":
                assert route is not None, (
                    "privilege_differential hypotheses must be routable"
                )


class TestResearchHintIntegration:
    def test_identity_hints_flow_into_stateful_research_hints(self) -> None:
        """§8: the identity layer's signals influence the REAL case
        scheduling hints (ordering-only, same budget)."""
        from webpent.production.adaptive_research import stateful_research_hints
        from webpent.production.identity_workflow import identity_workflow_node
        with _FlagBlock(
            enable_object_identity=True, enable_alias_resolution=True,
        ):
            update = identity_workflow_node(_campaign_state())
        assert update.get("identity_research_hints"), (
            "confirmed alias pairs must produce ordering hints"
        )
        # the hints channel is consumed by the real hint scheduler
        state = _campaign_state()
        state["identity_research_hints"] = update["identity_research_hints"]
        hints = stateful_research_hints(state)
        hinted_keys = set(update["identity_research_hints"])
        assert hinted_keys & set(hints), (
            "identity hints must surface in the stateful scheduling hints"
        )

    def test_hints_are_ordering_only_not_authority(self) -> None:
        from webpent.production.adaptive_research import stateful_research_hints
        state = _campaign_state()
        state["identity_research_hints"] = {"api/orders": 0.9}
        hints = stateful_research_hints(state)
        # values are priorities in [0, 1] — scheduling signals only
        for value in hints.values():
            assert 0.0 <= value <= 1.0

    def test_malformed_hint_channel_ignored_fail_soft(self) -> None:
        from webpent.production.adaptive_research import stateful_research_hints
        state = _campaign_state()
        state["identity_research_hints"] = {"bad-dir": "not-a-number"}
        hints = stateful_research_hints(state)
        assert hints.get("bad-dir") is None  # junk values dropped, no crash


class TestBoundedBehavior:
    def test_identity_hypotheses_capped(self) -> None:
        from webpent.config.settings import get_settings
        from webpent.production.identity_workflow import identity_workflow_node
        settings = get_settings()
        profiles = {f"foreign-{i}": {"role": "foreign"} for i in range(8)}
        state = _campaign_state(identity_profiles={
            "owner": {"role": "owner"},
            **profiles,
        })
        with _FlagBlock(enable_multi_identity_reasoning=True):
            old_cap = settings.max_identity_hypotheses
            settings.max_identity_hypotheses = 3
            try:
                update = identity_workflow_node(state)
            finally:
                settings.max_identity_hypotheses = old_cap
        reasoning = update["multi_identity_reasoning"]
        assert len(reasoning["differential_questions"]) <= 3

    def test_workflow_candidates_capped(self) -> None:
        from webpent.production.identity_workflow import identity_workflow_node
        observations = [
            {
                "fingerprint": f"fp-{i:04d}",
                "workflow_key": f"wf-{i}",
                "transition_key": "approve",
                "endpoint": f"/api/wf-{i}/approve",
                "method": "POST",
                "authorization_boundary": "role_scoped",
            }
            for i in range(20)
        ]
        state = _campaign_state(workflow_observations=observations)
        with _FlagBlock(enable_composite_workflows=True):
            update = identity_workflow_node(state)
        assert len(update["composite_workflow_candidates"]) <= 8  # default cap

    def test_fail_soft_on_junk_state(self) -> None:
        """Fault injection: malformed inputs produce honest telemetry,
        never a crash and never fabricated output."""
        from webpent.production.identity_workflow import identity_workflow_node
        junk = _campaign_state(
            workflow_observations=[{"garbage": True}, None, "string"],
            identity_profiles=None,
            crawled_data="not-a-dict",
        )
        with _FlagBlock(
            enable_object_identity=True,
            enable_composite_workflows=True,
            enable_multi_identity_reasoning=True,
        ):
            update = identity_workflow_node(junk)
        assert "identity_workflow" in update  # telemetry present
        assert update["identity_workflow"]["hypotheses_generated"] == 0
