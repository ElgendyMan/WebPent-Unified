"""Tests for the parallel subdomain-takeover/cloud-storage recon fan-out
(VIP speed initiative, Track 2 — see
docs/archive/2026-11-01-plan-exec-root-reports/UNFREEZE_TRACK2_PARALLEL_RECON_20261019.md).

Mirrors the structure of ``tests/test_vip_arjun_parameter_discovery.py`` and
``tests/test_v17_target_understanding.py`` (the closest existing precedent
for a settings-gated, additive graph-topology change). Covers four layers:

  1. ``_parallel_recon_enabled()`` — fail-closed settings resolution, same
     pattern as ``_target_understanding_enabled``.
  2. ``build_graph()`` topology — flag off reproduces the exact pre-Track-2
     node/edge set (48 nodes, sequential subdomain_takeover -> cloud_storage
     -> route_after_infrastructure); flag on adds exactly the
     recon_fanout/recon_join pair (50 nodes) and reroutes through them.
  3. ``_strip_current_phase`` — the wrapper that prevents the two parallel
     branches from racing on the plain (non-Annotated) ``current_phase``
     field.
  4. End-to-end real-node subgraph execution — recon_fanout -> {stripped
     subdomain_takeover, stripped cloud_storage} -> recon_join runs with NO
     ``InvalidUpdateError``, using the actual node functions (not mocks),
     and recon_join correctly re-establishes ``current_phase`` once both
     branches land.
"""

from __future__ import annotations

from types import SimpleNamespace

from langgraph.graph import END, START, StateGraph

from webpent.agents.cloud_storage.agent import cloud_storage_node
from webpent.agents.subdomain_takeover.agent import subdomain_takeover_node
from webpent.graph.builder import (
    NODE_CLOUD_STORAGE,
    NODE_RECON_FANOUT,
    NODE_RECON_JOIN,
    NODE_SUBDOMAIN_TAKEOVER,
    _parallel_recon_enabled,
    _strip_current_phase,
    build_graph,
    recon_fanout_node,
    recon_join_node,
)
from webpent.models.findings import Finding, Severity
from webpent.state.state import PentestState

# ---------------------------------------------------------------------------
# Layer 1: _parallel_recon_enabled() — fail-closed settings resolution
# ---------------------------------------------------------------------------


def test_parallel_recon_disabled_by_default(monkeypatch):
    import webpent.config.settings as settings_module

    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: SimpleNamespace(enable_parallel_recon=False),
    )
    assert _parallel_recon_enabled() is False


def test_parallel_recon_enabled_when_flag_set(monkeypatch):
    import webpent.config.settings as settings_module

    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: SimpleNamespace(enable_parallel_recon=True),
    )
    assert _parallel_recon_enabled() is True


def test_parallel_recon_fails_closed_on_settings_error(monkeypatch):
    """Any settings-resolution error must resolve to disabled, never enabled."""
    import webpent.config.settings as settings_module

    def _raise():
        raise RuntimeError("settings backend unavailable")

    monkeypatch.setattr(settings_module, "get_settings", _raise)
    assert _parallel_recon_enabled() is False


def test_parallel_recon_fails_closed_on_missing_attribute(monkeypatch):
    """A settings object with no enable_parallel_recon attribute must not crash."""
    import webpent.config.settings as settings_module

    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: SimpleNamespace(),  # no enable_parallel_recon attribute at all
    )
    assert _parallel_recon_enabled() is False


# ---------------------------------------------------------------------------
# Layer 2: build_graph() topology — flag off vs flag on
# ---------------------------------------------------------------------------


def test_build_graph_flag_off_matches_legacy_topology(monkeypatch):
    """Flag off must reproduce the exact pre-Track-2 node set — 48 nodes
    before the Ultimate plan, plus the 7 additive plan nodes (lesson
    consultation/extraction, surface sizing, four detectors) = 55: no
    recon_fanout/recon_join, sequential subdomain_takeover -> cloud_storage,
    and every plan node present (they are registered unconditionally;
    their gating is internal, per the documented wiring).
    """
    import webpent.graph.builder as builder_module

    monkeypatch.setattr(builder_module, "_parallel_recon_enabled", lambda: False)
    graph = build_graph(auto_approve=True)
    nodes = graph.get_graph().nodes

    # ULTIMATE PLAN 2026-10-27, proposals 2/3/7: 48 -> 55 (+7 additive
    # nodes; the legacy 48 are all still present).
    # RESIDUAL CLOSURE 2026-10-29: 55 -> 56 — the Track 11.5 dedup gate
    # node (enable_dedup_gate, inserted between executive_summary and
    # reporter) landed after these pins were written; the flag-off
    # topology includes it because its gating is internal, same policy
    # as the plan's own additive nodes.
    # UM-DR-36 (2026-11-12): 56 -> 57 — the appmodel semantic-model node
    # (graph/appmodel_nodes.py) wired into the production graph by the
    # corrective closure: an ADVISORY research-influence node (never a
    # confirmation/authorization authority — pinned by
    # test_semantic_model_has_no_confirmation_or_authorization_authority).
    assert len(nodes) == 57
    assert NODE_RECON_FANOUT not in nodes
    assert NODE_RECON_JOIN not in nodes
    assert NODE_SUBDOMAIN_TAKEOVER in nodes
    assert NODE_CLOUD_STORAGE in nodes


def test_build_graph_flag_on_adds_fanout_join_pair(monkeypatch):
    """Flag on must add exactly 2 nodes (recon_fanout, recon_join) on top of
    the flag-off topology — 55 total after the Ultimate plan's +7 additive
    nodes, nothing else added or removed.
    """
    import webpent.graph.builder as builder_module

    monkeypatch.setattr(builder_module, "_parallel_recon_enabled", lambda: True)
    graph = build_graph(auto_approve=True)
    nodes = graph.get_graph().nodes

    # ULTIMATE PLAN 2026-10-27: 50 -> 57 (55 flag-off base + fanout/join).
    # RESIDUAL CLOSURE 2026-10-29: 57 -> 58 (same dedup_gate +1 as the
    # flag-off case above).
    # UM-DR-36 (2026-11-12): 58 -> 59 (same appmodel +1 as the flag-off
    # case above).
    assert len(nodes) == 59
    assert NODE_RECON_FANOUT in nodes
    assert NODE_RECON_JOIN in nodes
    assert NODE_SUBDOMAIN_TAKEOVER in nodes
    assert NODE_CLOUD_STORAGE in nodes


def test_build_graph_flag_on_reroutes_through_fanout_join(monkeypatch):
    """Flag on must route the old subdomain_takeover entry edges through
    recon_fanout, and route_after_infrastructure's origin through
    recon_join instead of attaching directly to cloud_storage.
    """
    import webpent.graph.builder as builder_module

    monkeypatch.setattr(builder_module, "_parallel_recon_enabled", lambda: True)
    graph = build_graph(auto_approve=True)
    edges = graph.get_graph().edges

    sources = {e.source for e in edges if e.target == NODE_SUBDOMAIN_TAKEOVER}
    assert NODE_RECON_FANOUT in sources

    fanout_targets = {e.target for e in edges if e.source == NODE_RECON_FANOUT}
    assert fanout_targets == {NODE_SUBDOMAIN_TAKEOVER, NODE_CLOUD_STORAGE}

    join_sources = {e.source for e in edges if e.target == NODE_RECON_JOIN}
    assert join_sources == {NODE_SUBDOMAIN_TAKEOVER, NODE_CLOUD_STORAGE}


# ---------------------------------------------------------------------------
# Layer 3: _strip_current_phase
# ---------------------------------------------------------------------------


def test_strip_current_phase_removes_only_that_key():
    def fake_node(state):
        return {"current_phase": "cloud_storage", "findings": [], "errors": ["x"]}

    wrapped = _strip_current_phase(fake_node)
    result = wrapped({})

    assert "current_phase" not in result
    assert result["findings"] == []
    assert result["errors"] == ["x"]


def test_strip_current_phase_noop_when_key_absent():
    def fake_node(state):
        return {"findings": []}

    wrapped = _strip_current_phase(fake_node)
    result = wrapped({})

    assert result == {"findings": []}


def test_strip_current_phase_preserves_node_identity_for_other_kwargs():
    """The wrapper must pass state through to the wrapped fn unchanged."""
    received = {}

    def fake_node(state):
        received.update(state)
        return {"current_phase": "x"}

    wrapped = _strip_current_phase(fake_node)
    wrapped({"target": "marker", "client_id": "c1"})

    assert received == {"target": "marker", "client_id": "c1"}


# ---------------------------------------------------------------------------
# Layer 4: end-to-end real-node subgraph execution (no InvalidUpdateError)
# ---------------------------------------------------------------------------


def _build_parallel_subgraph():
    g = StateGraph(PentestState)
    g.add_node(NODE_RECON_FANOUT, recon_fanout_node)
    g.add_node(
        NODE_SUBDOMAIN_TAKEOVER, _strip_current_phase(subdomain_takeover_node)
    )
    g.add_node(NODE_CLOUD_STORAGE, _strip_current_phase(cloud_storage_node))
    g.add_node(NODE_RECON_JOIN, recon_join_node)
    g.add_edge(START, NODE_RECON_FANOUT)
    g.add_edge(NODE_RECON_FANOUT, NODE_SUBDOMAIN_TAKEOVER)
    g.add_edge(NODE_RECON_FANOUT, NODE_CLOUD_STORAGE)
    g.add_edge(NODE_SUBDOMAIN_TAKEOVER, NODE_RECON_JOIN)
    g.add_edge(NODE_CLOUD_STORAGE, NODE_RECON_JOIN)
    g.add_edge(NODE_RECON_JOIN, END)
    return g.compile()


def test_parallel_subgraph_runs_without_invalid_update_error():
    """The real concurrency risk Track 2 exists to solve: two nodes in the
    same superstep writing different values to the plain (non-Annotated)
    current_phase field used to raise langgraph.errors.InvalidUpdateError.
    With _strip_current_phase applied, it must not.
    """
    compiled = _build_parallel_subgraph()
    # target=None: both real nodes fast-return without any network I/O.
    result = compiled.invoke({"target": None, "client_id": "t", "engagement_id": "e"})

    assert result["current_phase"] == "recon_join"
    assert sorted(result["errors"]) == sorted(
        [
            "No target configured for takeover check.",
            "No target configured for cloud storage check.",
        ]
    )
    assert result["findings"] == []


def test_parallel_subgraph_sequential_baseline_is_consistent():
    """Sanity check: the equivalent sequential wiring (flag-off topology)
    reaches the same errors/findings, just with current_phase reflecting
    the last node to run (expected last-write-wins across two separate
    supersteps — not a bug, documents the difference from the join node).
    """
    g = StateGraph(PentestState)
    g.add_node(NODE_SUBDOMAIN_TAKEOVER, subdomain_takeover_node)
    g.add_node(NODE_CLOUD_STORAGE, cloud_storage_node)
    g.add_edge(START, NODE_SUBDOMAIN_TAKEOVER)
    g.add_edge(NODE_SUBDOMAIN_TAKEOVER, NODE_CLOUD_STORAGE)
    g.add_edge(NODE_CLOUD_STORAGE, END)
    compiled = g.compile()

    result = compiled.invoke({"target": None, "client_id": "t", "engagement_id": "e"})

    assert result["current_phase"] == "cloud_storage"
    assert sorted(result["errors"]) == sorted(
        [
            "No target configured for takeover check.",
            "No target configured for cloud storage check.",
        ]
    )
    assert result["findings"] == []


def test_parallel_subgraph_join_waits_for_both_branches_and_merges_findings():
    """Both branches writing distinct Finding objects to the same Annotated
    findings channel in the same superstep must both survive (merge, not
    clobber) by the time recon_join observes state -- and recon_join itself
    must not execute until BOTH branches have completed (LangGraph's own
    barrier semantics; exercised here, not re-implemented)."""
    sdt_id = "11111111-1111-1111-1111-111111111111"
    cs_id = "22222222-2222-2222-2222-222222222222"

    def fake_subdomain_node(state):
        return {
            "current_phase": "subdomain_takeover",
            "findings": [
                Finding(
                    id=sdt_id,
                    title="Subdomain takeover candidate",
                    severity=Severity.MEDIUM,
                    description="test finding",
                    tool_name="subdomain_takeover",
                    url="https://stale.example.com",
                )
            ],
        }

    def fake_cloud_storage_node(state):
        return {
            "current_phase": "cloud_storage",
            "findings": [
                Finding(
                    id=cs_id,
                    title="Open cloud bucket",
                    severity=Severity.HIGH,
                    description="test finding",
                    tool_name="cloud_storage",
                    url="https://bucket.example.com",
                )
            ],
        }

    g = StateGraph(PentestState)
    g.add_node(NODE_RECON_FANOUT, recon_fanout_node)
    g.add_node(NODE_SUBDOMAIN_TAKEOVER, _strip_current_phase(fake_subdomain_node))
    g.add_node(NODE_CLOUD_STORAGE, _strip_current_phase(fake_cloud_storage_node))
    g.add_node(NODE_RECON_JOIN, recon_join_node)
    g.add_edge(START, NODE_RECON_FANOUT)
    g.add_edge(NODE_RECON_FANOUT, NODE_SUBDOMAIN_TAKEOVER)
    g.add_edge(NODE_RECON_FANOUT, NODE_CLOUD_STORAGE)
    g.add_edge(NODE_SUBDOMAIN_TAKEOVER, NODE_RECON_JOIN)
    g.add_edge(NODE_CLOUD_STORAGE, NODE_RECON_JOIN)
    g.add_edge(NODE_RECON_JOIN, END)
    compiled = g.compile()

    result = compiled.invoke({})

    ids = sorted(str(f.id) for f in result["findings"])
    assert ids == sorted([sdt_id, cs_id])
    # recon_join only runs after BOTH branches land, and sets current_phase
    # itself -- if it ran before either branch, current_phase would be
    # "recon_fanout" (its predecessor's value) instead.
    assert result["current_phase"] == "recon_join"


def test_recon_fanout_and_join_are_pure_pass_through():
    """recon_fanout/recon_join must not read or mutate anything from state
    beyond setting current_phase -- they are dispatch/barrier points only."""
    fanout_result = recon_fanout_node({"findings": ["should not be touched"]})
    assert fanout_result == {"current_phase": "recon_fanout"}

    join_result = recon_join_node({"findings": ["should not be touched"]})
    assert join_result == {"current_phase": "recon_join"}
