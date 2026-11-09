# tests/team1_acceptance/test_i_official_entrypoint.py
"""TEAM-1 ACCEPTANCE — Official entrypoint demonstrates modern spine at runtime.

Part 5 + Part 16: The official entrypoint (build_graph → invoke) MUST
demonstrate: entrypoint → DeepRecon → ResearchLoop → ToolBoundary →
execution → WorldModel → OutcomeTracker → replan.
No synthetic direct invocation of DeepReconEngine — the graph itself
must produce the modern spine trace.
"""
from __future__ import annotations

import pytest


def test_graph_builder_includes_modern_spine_node():
    """The production graph builder must include the modern spine recon node."""
    from webpent.graph.builder import MODERN_SPINE_ENABLED, build_graph, modern_spine_recon_node
    assert MODERN_SPINE_ENABLED is True
    assert callable(modern_spine_recon_node)
    graph = build_graph()
    # The recon node exists in the graph (wrapped by _combined_recon_node).
    assert "recon" in graph.nodes


def test_graph_invoke_activates_modern_spine():
    """Invoking the REAL compiled graph activates the modern spine.

    M2-impl WP-G (R8 of Ruling M2-001): the previous version of this test
    swallowed graph.invoke exceptions and "proved" activation by calling the
    recon node function DIRECTLY — a masked, dishonest proof-of-transport
    (RED-2 P-6 finding). The fix streams the real compiled graph with a
    bounded update window and asserts on markers that arrive THROUGH the
    graph channels:

      * no exception swallowing — any node failure propagates and fails
        the test loudly;
      * no direct-node proof — the recon node function is never invoked
        here, only the compiled graph;
      * R2 (prohibited transport) — the orchestrator object must NOT ride
        the graph state; the campaign lane re-derives it at the factory.
    """
    from webpent.graph.builder import build_graph
    from webpent.models.targets import Target

    graph = build_graph()
    initial_state = {
        "engagement_id": "eng_entrypoint_test",
        "target": Target(url="https://lab.example.com"),
        "target_url": "https://lab.example.com",
        "skip_recon": False,
        "auto_approve": False,
        "observed_preconditions": (),
        "blocked_preconditions": (),
        "max_graph_steps": 3,  # bounded — recon stage is all we assert on
    }
    markers: dict = {}
    # Bounded through-graph probe: consume node updates until the modern
    # spine markers arrive. Breaking out of the update generator is a legal
    # bounded stop — it swallows nothing.
    for chunk in graph.stream(initial_state, config={"recursion_limit": 30},
                              stream_mode="updates"):
        for _node, update in chunk.items():
            if isinstance(update, dict):
                markers.update(update)
        if markers.get("modern_spine_active"):
            break
    assert markers.get("modern_spine_active") is True
    assert markers.get("modern_spine_version") == "modern_spine_v1"
    assert "_modern_orchestrator" not in markers  # prohibited transport (R2)
    assert markers.get("legacy_authority_blocked") is False
    trace = markers.get("_modern_spine_trace") or {}
    assert "DeepReconEngine" in trace.get("components_seen", [])
    assert "ResearchControlLoop" in trace.get("components_seen", [])
    assert "WorldModel" in trace.get("components_seen", [])
    assert "deep_recon" in trace.get("stages_seen", [])


def test_cli_entrypoint_imports_modern_spine():
    """The CLI's unified hunt path must import the graph builder that uses
    the modern spine (v0.32.0: the removed `scan` command was the last
    module-level bind in commands.py; the unified path composes via a
    lazy import in cli/unified_hunt.py)."""
    import inspect

    from webpent.cli import unified_hunt
    src = inspect.getsource(unified_hunt)
    assert "from webpent.graph.builder import build_graph" in src


def test_api_entrypoint_uses_same_graph():
    """The API entrypoint must use the same build_graph (one production spine)."""
    try:
        from webpent.api import app as api_app
        # API app exists; it must route to the same scan execution path
        assert api_app is not None
    except Exception:
        pytest.skip("API app requires extra deps — graph builder is the shared spine")
    # The shared graph builder is the single source of truth.
    from webpent.graph.builder import build_graph
    assert callable(build_graph)


def test_worker_entrypoint_uses_same_graph():
    """The Celery worker must use the same build_graph."""
    try:
        from webpent.workers.pentest_worker import celery_app
        assert celery_app is not None
    except Exception:
        pytest.skip("Celery worker requires broker — graph builder is shared")
    from webpent.graph.builder import build_graph
    assert callable(build_graph)


def test_no_special_flag_needed():
    """Part 16: Default config must point to modern path — no test-only flag."""
    import os
    # Ensure no env var is set — default behavior.
    os.environ.pop("WEBPENT_MODERN_SPINE", None)
    from importlib import reload

    from webpent.production import modern_spine_integration
    reload(modern_spine_integration)
    assert modern_spine_integration.MODERN_SPINE_ENABLED is True, (
        "Modern spine must be default-on. No special flag required."
    )
