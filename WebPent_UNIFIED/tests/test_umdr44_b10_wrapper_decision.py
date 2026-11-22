"""UM-DR-44 B10 — documented decision: chain_planner / oauth_hunter
wrapper agents are RETAINED (not dead code to delete).

Decision record (2026-11-22):

* The PRODUCTION path for both capabilities is
  ``families/execution_node.py``, which calls
  ``PreconditionGraphBuilder`` / ``OAuthSurfaceDetector`` directly
  (the optional-analyzer blocks).  The thin LangGraph-node wrappers
  ``agents/chain_planner/agent.py::ChainPlanner`` and
  ``agents/oauth_hunter/agent.py::OAuthHunter`` have no production
  importer today — only tests import them.
* The mission's own rule ("do not delete modules because a basic grep
  did not find a caller") and the wrappers' documented purpose
  (LangGraph-compatible node surface for the optional layer) argue
  AGAINST deletion: the underlying analyzers are live production code,
  and the wrappers are the node-shaped façade over exactly those
  analyzers.
* DECISION: retain both wrappers; the risk that motivated the dead-code
  question (a wrapper silently drifting from the production path, or
  rotting until it imports something broken) is closed STRUCTURALLY:
  this test imports both wrappers (import rot fails the gate) and
  verifies they delegate to the SAME analyzer classes the production
  execution node uses (drift fails the gate).
"""

from __future__ import annotations

import inspect


class TestWrappersImportAndDelegate:
    def test_chain_planner_imports_and_delegates(self) -> None:
        from webpent.agents.chain_planner.agent import ChainPlanner
        from webpent.chained_exploits import PreconditionGraphBuilder

        src = inspect.getsource(ChainPlanner.run)
        assert "PreconditionGraphBuilder" in src

    def test_oauth_hunter_imports_and_delegates(self) -> None:
        from webpent.agents.oauth_hunter.agent import OAuthHunter
        from webpent.oauth import OAuthSurfaceDetector

        src = inspect.getsource(OAuthHunter.run)
        assert "OAuthSurfaceDetector" in src

    def test_production_node_uses_same_analyzers(self) -> None:
        """The families execution node (the production path) must call
        the same analyzer classes the wrappers delegate to."""
        from webpent.families import execution_node

        src = inspect.getsource(execution_node)
        assert "PreconditionGraphBuilder" in src
        assert "OAuthSurfaceDetector" in src

    def test_chain_planner_run_produces_state_shape(self) -> None:
        from webpent.agents.chain_planner.agent import ChainPlanner

        out = ChainPlanner().run(
            {"target_id": "t1", "engagement_id": "e1",
             "confirmed_findings": []}
        )
        assert "exploit_chain_candidates" in out
        assert "exploit_chain_scenarios" in out

    def test_oauth_hunter_run_produces_state_shape(self) -> None:
        from webpent.agents.oauth_hunter.agent import OAuthHunter

        out = OAuthHunter().run(
            {"target_id": "t1", "engagement_id": "e1",
             "endpoint_inventory": []}
        )
        assert "oauth_candidates" in out
        assert "oauth_scenarios" in out
