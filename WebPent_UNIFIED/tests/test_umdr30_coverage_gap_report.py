"""UM-DR-30 Workstream F §8 — campaign-runtime coverage gap map wiring.

The ``CoverageMap`` / ``CoverageGapDetector`` facades were zero-importer
orphans (UM-DR-29 matrix: coverage_intelligence = UNIT_TESTED, "Coverage
Gap Map not produced by campaign runtime today"). This suite pins the
closed wiring at four levels:

1. REPORT BUILDING — the projection over a real campaign-ledger state:
   open cells surface, clean cells do not, failures fail soft, entries
   stay bounded.
2. NODE DOUBLE-GATE — the flag gates both the builder wiring and the
   node itself (fail-closed, the stateful_discovery precedent).
3. LANGGRAPH RUNTIME — the real node inside a compiled StateGraph over
   the real PentestState: the report survives channel filtering on the
   declared ``coverage_gap_report`` channel.
4. BUILDER LEVEL — the production ``build_graph`` contains the node only
   when the flag is on.

Honesty pins: the report is advisory only — it carries no finding
vocabulary, never promotes, and never touches the causal guard's
confirmation authority.
"""

from __future__ import annotations

from typing import Any


def _ledger_state() -> dict[str, Any]:
    """A realistic campaign-ledger state: one clean cell, one not_scanned,
    one missing-validator, one blocked."""
    return {
        "campaign_ledger": {
            "entries": [
                {"key": "sqli:search", "status": "tool_confirmed"},
                {"key": "idor:profile", "status": "not_scanned"},
                {"key": "ssti:template", "status": "missing-validator"},
                {"key": "cmdi:ping", "status": "policy_block"},
                {"key": "xss:comment", "status": "tool_unconfirmed"},
            ]
        }
    }


# ---------------------------------------------------------------------------
# 1. report building
# ---------------------------------------------------------------------------


class TestReportBuilding:
    def test_open_cells_surface_as_gaps(self) -> None:
        from webpent.production.coverage_gap_report import (
            build_coverage_gap_report,
        )

        report = build_coverage_gap_report(_ledger_state())
        assert report["status"] == "ok"
        # 4 gaps: not_scanned + missing-validator + policy_block, AND
        # xss:comment — its claimed "tool_unconfirmed" status has no
        # backing proof outcome, so the ledger's honest downgrade makes
        # it not_scanned (an unbacked claim IS a gap).
        assert report["gap_count"] == 4
        keys = {gap["key"] for gap in report["gaps"]}
        assert keys == {"idor:profile", "ssti:template", "cmdi:ping", "xss:comment"}
        # the only clean cell (tool_confirmed) does NOT appear as a gap
        assert "sqli:search" not in keys

    def test_report_shape_is_self_describing(self) -> None:
        from webpent.production.coverage_gap_report import (
            build_coverage_gap_report,
        )

        report = build_coverage_gap_report(_ledger_state())
        assert report["generated_by"] == "coverage_gap_report"
        assert report["window"] == "UM-DR-30"
        assert "not_scanned" in report["open_statuses"]
        assert "missing-validator" in report["open_statuses"]
        assert isinstance(report["coverage_metrics"], dict)
        assert report["coverage_metrics"]["gap_count"] == 4
        assert report["projection_entries"] == 5

    def test_empty_state_is_an_honest_empty_report(self) -> None:
        from webpent.production.coverage_gap_report import (
            build_coverage_gap_report,
        )

        report = build_coverage_gap_report({})
        assert report["status"] == "ok"
        assert report["gap_count"] == 0
        assert report["gaps"] == []

    def test_projection_failure_fails_soft_to_error_shape(self, monkeypatch) -> None:
        import webpent.production.coverage_gap_report as report_module

        def _boom(state: Any) -> dict[str, Any]:
            raise RuntimeError("ledger exploded")

        monkeypatch.setattr(
            "webpent.coverage.coverage_map.CoverageMap.project", _boom
        )
        report = report_module.build_coverage_gap_report(_ledger_state())
        assert report["status"] == "error"
        assert report["gaps"] == []
        assert report["gap_count"] == 0

    def test_gap_entries_are_bounded(self, monkeypatch) -> None:
        import webpent.production.coverage_gap_report as report_module

        huge = {
            "campaign_ledger": {
                "entries": [
                    {"key": f"k{i}", "status": "not_scanned"} for i in range(500)
                ]
            }
        }
        report = report_module.build_coverage_gap_report(huge)
        assert len(report["gaps"]) == report_module._MAX_GAP_ENTRIES
        assert report["gap_count"] == 500
        assert report["truncated"] is True

    def test_report_carries_no_finding_vocabulary(self) -> None:
        """Advisory-only pin: the gap report must never read like a
        findings list — no confirmation vocabulary anywhere in it."""
        from webpent.production.coverage_gap_report import (
            build_coverage_gap_report,
        )

        report = build_coverage_gap_report(_ledger_state())
        blob = repr(report)
        for banned in ("confirmed_finding", "vulnerability_confirmed", "severity"):
            assert banned not in blob


# ---------------------------------------------------------------------------
# 2. the node double-gate
# ---------------------------------------------------------------------------


class TestNodeDoubleGate:
    def test_flag_off_node_is_a_noop(self, monkeypatch) -> None:
        from webpent.config.settings import get_settings
        from webpent.production.coverage_gap_report import (
            coverage_gap_report_node,
        )

        monkeypatch.setattr(get_settings(), "enable_coverage_gap_report", False)
        assert coverage_gap_report_node(_ledger_state()) == {}

    def test_flag_on_node_writes_the_channel(self, monkeypatch) -> None:
        from webpent.config.settings import get_settings
        from webpent.production.coverage_gap_report import (
            coverage_gap_report_node,
        )

        monkeypatch.setattr(get_settings(), "enable_coverage_gap_report", True)
        update = coverage_gap_report_node(_ledger_state())
        assert set(update) == {"coverage_gap_report"}
        assert update["coverage_gap_report"]["gap_count"] == 4

    def test_settings_failure_is_not_enabled(self, monkeypatch) -> None:
        import webpent.config.settings as settings_module
        from webpent.production.coverage_gap_report import (
            coverage_gap_report_node,
        )

        def _boom() -> Any:
            raise RuntimeError("settings unavailable")

        monkeypatch.setattr(settings_module, "get_settings", _boom)
        assert coverage_gap_report_node(_ledger_state()) == {}


# ---------------------------------------------------------------------------
# 3. the LangGraph runtime level
# ---------------------------------------------------------------------------


class TestLangGraphRuntimeSurvival:
    def test_report_survives_channel_filtering(self, monkeypatch) -> None:
        from langgraph.graph import END, START, StateGraph

        from webpent.config.settings import get_settings
        from webpent.production.coverage_gap_report import (
            wire_coverage_gap_report,
        )
        from webpent.state.state import PentestState

        monkeypatch.setattr(get_settings(), "enable_coverage_gap_report", True)

        graph = StateGraph(PentestState)
        graph.add_node("reporter", lambda s: {})
        graph.add_node("reflection", lambda s: {})
        graph.add_edge(START, "reporter")
        graph.add_edge("reporter", "reflection")  # the existing edge stays
        graph.add_edge("reflection", END)
        wire_coverage_gap_report(graph)  # the REAL production wiring
        compiled = graph.compile()

        result = compiled.invoke(
            _ledger_state(), config={"recursion_limit": 25}
        )
        report = result.get("coverage_gap_report") or {}
        assert report, "coverage_gap_report was dropped by channel filtering"
        assert report["status"] == "ok"
        assert report["gap_count"] == 4

    def test_flag_off_at_runtime_node_writes_nothing(self, monkeypatch) -> None:
        from langgraph.graph import END, START, StateGraph

        from webpent.config.settings import get_settings
        from webpent.production.coverage_gap_report import (
            wire_coverage_gap_report,
        )
        from webpent.state.state import PentestState

        monkeypatch.setattr(get_settings(), "enable_coverage_gap_report", False)

        graph = StateGraph(PentestState)
        graph.add_node("reporter", lambda s: {})
        graph.add_node("reflection", lambda s: {})
        graph.add_edge(START, "reporter")
        graph.add_edge("reporter", "reflection")
        graph.add_edge("reflection", END)
        wire_coverage_gap_report(graph)
        compiled = graph.compile()

        result = compiled.invoke(_ledger_state(), config={"recursion_limit": 25})
        assert "coverage_gap_report" not in result


# ---------------------------------------------------------------------------
# 4. the production builder level
# ---------------------------------------------------------------------------


class TestProductionBuilderWiring:
    def test_node_present_when_flag_on(self, monkeypatch) -> None:
        from webpent.config.settings import get_settings
        from webpent.graph import builder as graph_builder

        monkeypatch.setattr(get_settings(), "enable_coverage_gap_report", True)
        compiled = graph_builder.build_graph(auto_approve=True)
        nodes = set(getattr(compiled, "nodes", {}) or {})
        assert "coverage_gap_report" in nodes

    def test_node_absent_when_flag_off(self, monkeypatch) -> None:
        from webpent.config.settings import get_settings
        from webpent.graph import builder as graph_builder

        monkeypatch.setattr(get_settings(), "enable_coverage_gap_report", False)
        compiled = graph_builder.build_graph(auto_approve=True)
        nodes = set(getattr(compiled, "nodes", {}) or {})
        assert "coverage_gap_report" not in nodes

    def test_flag_default_is_fail_closed(self) -> None:
        from webpent.config.settings import Settings

        assert (
            Settings.model_fields["enable_coverage_gap_report"].default is False
        )

    def test_channel_is_declared_last_write_wins(self) -> None:
        import typing

        from webpent.state.state import PentestState

        resolved = typing.get_type_hints(PentestState, include_extras=True)
        annotation = resolved["coverage_gap_report"]
        # plain dict channel — no reducer metadata (last-write-wins)
        assert not hasattr(annotation, "__metadata__") or not typing.get_args(
            annotation
        )[1:], "coverage_gap_report must stay last-write-wins (single writer)"
