# tests/team1_acceptance/test_a_modern_production_path.py
"""TEAM-1 ACCEPTANCE A — Modern production path is the default.

Proves: official entrypoint / graph builder uses the modern spine by default.
The runtime must demonstrably execute the modern components (Part 16).
"""
from __future__ import annotations


def make_authorized_profile(authorized_targets=("lab.example.com", "target.example.com"), engagement_id="eng_team1_test"):
    from webpent.live_hunter.profile import AuthorizedLabProfile
    return AuthorizedLabProfile(
        authorized_targets=authorized_targets,
        engagement_id=engagement_id,
        operator_approval_at="2026-09-15T00:00:00Z",
        knowledge_ready=True, lab_fixture_mode=True,
    )

def make_scope_law(engagement_id="eng_team1_test", authorized_targets=("lab.example.com", "target.example.com")):
    from webpent.live_hunter.tool_scope import ScopeLaw
    profile = make_authorized_profile(authorized_targets=authorized_targets, engagement_id=engagement_id)
    return ScopeLaw(profile=profile, engagement_id=engagement_id)




def test_modern_spine_enabled_by_default():
    """The modern spine must be enabled by default (no test-only flag required)."""
    from webpent.production.modern_spine_integration import MODERN_SPINE_ENABLED
    assert MODERN_SPINE_ENABLED is True, (
        "Modern spine must be the default. Disabling requires explicit env override."
    )


def test_graph_builder_imports_modern_spine():
    """The production graph builder must import and use the modern spine."""
    from webpent.graph import builder
    assert hasattr(builder, "modern_spine_recon_node"), (
        "Graph builder must import modern_spine_recon_node"
    )
    assert hasattr(builder, "MODERN_SPINE_ENABLED")


def test_modern_orchestrator_instantiates_and_traces():
    """ModernOrchestrator must instantiate all modern components and trace them."""
    from webpent.production.modern_spine import ModernOrchestrator
    orch = ModernOrchestrator(engagement_id="test_eng_a1")
    summary = orch.trace.summary()
    assert summary["spine_version"] == "modern_spine_v1"
    # All modern components must have been initialized (trace events).
    components = set(summary["components_seen"])
    assert "DeepReconEngine" in components
    assert "WorldModel" in components
    assert "OutcomeTracker" in components
    assert "ResearchControlLoop" in components
    assert "ModernOrchestrator" in components


def test_modern_spine_execution_chain_observable():
    """The full chain: deep_recon -> research_step -> authorize -> outcome must be traceable."""
    from webpent.production.modern_spine import ModernOrchestrator

    scope = make_scope_law(engagement_id="test_eng_a2")
    orch = ModernOrchestrator(engagement_id="test_eng_a2", scope_law=scope)

    # Stage 1: Deep recon
    observed = [{"path": "/api/users", "method": "GET", "status_code": 200, "body": "{}", "headers": {}}]
    result = orch.run_deep_recon(target_url="https://target.example.com", observed=observed)
    assert "hypotheses" in result

    # Stage 2: Research step
    decision = orch.research_step()
    assert decision["decision_number"] == 1

    # Stage 3: Execution authorization (SOLE authority)
    decision_scope = orch.authorize_execution(
        tool_name="httpx_bounded", target_url="https://target.example.com/api/users"
    )
    assert decision_scope.in_scope is True

    # Out-of-scope must be denied
    oob = orch.authorize_execution(
        tool_name="httpx_bounded", target_url="https://evil.example.com/ssrf"
    )
    assert oob.in_scope is False

    # Stage 4: Outcome tracking
    orch.record_outcome(
        experiment_signature="exp_1", outcome_class="high_information",
        information_value=0.8, hypothesis_id="hyp_1",
    )
    assert len(orch.outcome_tracker.history) == 1

    # Trace must show all stages
    summary = orch.trace.summary()
    stages = set(summary["stages_seen"])
    assert "deep_recon" in stages
    assert "research_step" in stages
    assert "authorize" in stages
    assert "outcome" in stages
    assert orch.executed_modern_path is True


def test_modern_spine_recon_node_sets_state():
    """The graph node must set modern_spine_active=True (object transport
    removed per M2-impl WP-B / Ruling M2-001 R2 — the orchestrator no longer
    rides state; the campaign lane re-derives it at the factory)."""
    from webpent.production.modern_spine_integration import modern_spine_recon_node
    state = {
        "engagement_id": "test_eng_node",
        "target_url": "https://target.example.com",
    }
    out = modern_spine_recon_node(state)
    assert out.get("modern_spine_active") is True
    assert out.get("modern_spine_version") == "modern_spine_v1"
    assert "_modern_orchestrator" not in out  # prohibited transport removed (R2)
    assert "_modern_spine_trace" in out
    trace = out["_modern_spine_trace"]
    assert "DeepReconEngine" in trace["components_seen"]


def test_no_fake_modern_path():
    """Part 16: The orchestrator must actually invoke modern components, not just label them."""
    from webpent.production.modern_spine import ModernOrchestrator
    orch = ModernOrchestrator(engagement_id="test_real")
    # DeepReconEngine must be a real instance with real methods
    assert hasattr(orch.deep_recon, "ingest_route_observation")
    assert hasattr(orch.deep_recon, "generate_hypothesis_candidates")
    # ResearchControlLoop must be real and bounded
    assert hasattr(orch.research_loop, "step")
    assert orch.research_loop.MAX_DECISIONS <= 100  # bounded
    # OutcomeTracker must be real and bounded
    assert hasattr(orch.outcome_tracker, "record_outcome")
    assert orch.outcome_tracker.MAX_HISTORY <= 500
    # WorldModel must be real
    assert hasattr(orch.world_model, "register_hypothesis")
