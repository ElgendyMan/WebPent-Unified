"""Ultimate plan 2026-10-27 — engine unification + learning loop + dynamic
budget + output clarity integration tests.

Covers the parent-authored modules of the plan window:
* state/unified_state.py (mode presets, resolve)
* adapters/legacy_state_bridge.py (loss-free crossing)
* graph/lesson_nodes.py (consultation + extraction, fail-open)
* graph/surface_sizing.py (measurement + budget derivation)
* graph/detector_nodes.py (pass-through contracts)
* graph/budget_governor.py (proposal 2 math: compute_step_budget,
  proportional reserves, active budget)
* graph/progress_display.py (phase mapping + non-TTY rendering)
* shared/finding_announcer.py (instant confirmed lines, dedup)
* cli/unified_hunt.py (preview mode, authorization guard, recursion
  limits)

No network, no LLM, no external binaries. Pure function contracts.
"""

from __future__ import annotations

import io

import pytest

from webpent.adapters.legacy_state_bridge import (
    hunter_state_to_unified,
    pentest_state_to_unified,
    unified_to_pentest_state,
)
from webpent.graph.budget_governor import (
    budget_pressure,
    completion_reserve_for,
    compute_step_budget,
    research_reserve_for,
    steps_remaining,
)
from webpent.shared.finding_announcer import FindingAnnouncer, _announce_line
from webpent.state.unified_state import HUNT_MODES, HUNT_MODE_PRESETS, resolve_hunt_mode


# ---------------------------------------------------------------------------
# state/unified_state.py — mode presets
# ---------------------------------------------------------------------------


class TestHuntModePresets:
    def test_three_modes_exist(self) -> None:
        assert HUNT_MODES == frozenset({"quick", "standard", "deep"})

    def test_presets_are_monotonic(self) -> None:
        """deep >= standard >= quick for every budget dimension."""
        quick = HUNT_MODE_PRESETS["quick"]
        standard = HUNT_MODE_PRESETS["standard"]
        deep = HUNT_MODE_PRESETS["deep"]
        for key in ("time_budget_s", "request_budget", "llm_budget_usd", "max_llm_calls"):
            assert quick[key] <= standard[key] <= deep[key], key

    def test_resolve_default_is_standard(self) -> None:
        assert resolve_hunt_mode(None)["mode"] == "standard"
        assert resolve_hunt_mode("")["mode"] == "standard"

    def test_resolve_case_insensitive(self) -> None:
        assert resolve_hunt_mode("QUICK")["mode"] == "quick"
        assert resolve_hunt_mode(" Deep ")["mode"] == "deep"

    def test_resolve_unknown_raises_with_listing(self) -> None:
        with pytest.raises(ValueError, match="quick"):
            resolve_hunt_mode("yolo")

    def test_resolved_preset_drops_doc_key(self) -> None:
        assert "_doc" not in resolve_hunt_mode("quick")


# ---------------------------------------------------------------------------
# adapters/legacy_state_bridge.py
# ---------------------------------------------------------------------------


class TestLegacyStateBridge:
    def test_pentest_lift_never_overwrites_existing(self) -> None:
        state = {"findings": [], "llm_budget_usd": 99.0}
        unified = pentest_state_to_unified(state, mode="quick")
        assert unified["llm_budget_usd"] == 99.0
        assert unified["max_hypotheses"] == HUNT_MODE_PRESETS["quick"]["max_hypotheses"]

    def test_pentest_lift_fills_missing_budgets(self) -> None:
        unified = pentest_state_to_unified({"findings": []}, mode="deep")
        assert unified["llm_budget_usd"] == HUNT_MODE_PRESETS["deep"]["llm_budget_usd"]

    def test_hunter_crossing_preserves_shared_channels(self) -> None:
        hunter = {
            "findings": ["f1"],
            "hypotheses": ["h1"],
            "max_llm_calls": 40,
            "max_cost_usd": 5.0,
            "persona": "stok",
            "hunt_artifact_root": "/tmp/x",
        }
        unified = hunter_state_to_unified(hunter)
        assert unified["findings"] == ["f1"]
        assert unified["max_llm_calls"] == 40
        assert unified["persona"] == "stok"
        # Hunter-only field preserved as provenance, not silently dropped.
        assert dict(unified["_hunter_legacy_fields"])["hunt_artifact_root"] == "/tmp/x"

    def test_narrowing_strips_unified_only_keys(self) -> None:
        unified = pentest_state_to_unified({"findings": []}, mode="quick")
        narrowed = unified_to_pentest_state(unified)
        assert "max_hypotheses" not in narrowed
        assert "consulted_lessons" not in narrowed
        assert "dynamic_step_budget" not in narrowed
        assert narrowed["findings"] == []

    def test_round_trip_is_loss_free_for_shared_channels(self) -> None:
        original = {"findings": [1, 2], "crawled_data": {"a": 1}}
        unified = pentest_state_to_unified(original, mode="standard")
        narrowed = unified_to_pentest_state(unified)
        for key, value in original.items():
            assert narrowed[key] == value


# ---------------------------------------------------------------------------
# graph/budget_governor.py — proposal 2 math
# ---------------------------------------------------------------------------


class TestComputeStepBudget:
    def test_small_surface_keeps_flat_ceiling(self) -> None:
        assert compute_step_budget(0) == 50
        assert compute_step_budget(5) == 55

    def test_mid_surface_scales(self) -> None:
        # 50 + 200 = 250 — the plan's flagship example.
        assert compute_step_budget(200) == 250

    def test_hard_cap_clamps(self) -> None:
        assert compute_step_budget(5000) == 400
        assert compute_step_budget(5000, hard_cap=300) == 300

    def test_cost_ceiling_clamps_but_never_below_flat(self) -> None:
        # $1 quick pass: cost bound 40 < flat 50 -> stays 50.
        assert compute_step_budget(200, cost_ceiling_usd=1.0) == 50
        # $25 deep: cost bound 1000 -> cap wins.
        assert compute_step_budget(200, cost_ceiling_usd=25.0) == 250

    def test_never_below_flat_for_small_surfaces(self) -> None:
        assert compute_step_budget(0, cost_ceiling_usd=0.01) == 50

    def test_invalid_surface_is_clamped_to_zero(self) -> None:
        assert compute_step_budget(-100) == 50


class TestProportionalReserves:
    def test_flat_budget_reserves_are_byte_identical(self) -> None:
        assert completion_reserve_for(50) == 19
        assert research_reserve_for(50) == 24

    def test_large_budget_reserves_scale(self) -> None:
        assert completion_reserve_for(400) == 48
        assert research_reserve_for(400) == 60

    def test_research_reserve_always_ge_completion(self) -> None:
        for budget in (50, 100, 250, 400, 1000):
            assert research_reserve_for(budget) >= completion_reserve_for(budget)


class TestActiveBudget:
    def test_pressure_uses_dynamic_budget(self) -> None:
        state = {"dynamic_step_budget": 250, "node_step_trace": [{}] * 200}
        pressure = budget_pressure(state)
        assert pressure["max_steps"] == 250
        assert pressure["remaining"] == 50
        assert pressure["reason"] == "inactive"

    def test_flat_path_unchanged_without_dynamic(self) -> None:
        state = {"node_step_trace": [{}] * 40}
        pressure = budget_pressure(state)
        assert pressure["max_steps"] == 50
        assert pressure["remaining"] == 10
        assert pressure["active"] is True
        assert pressure["reason"] == "completion_cutoff"

    def test_completion_cutoff_fires_under_dynamic_budget(self) -> None:
        state = {"dynamic_step_budget": 250, "node_step_trace": [{}] * 230}
        pressure = budget_pressure(state)
        assert pressure["remaining"] == 20
        assert pressure["active"] is True

    def test_corrupt_dynamic_budget_falls_back_to_flat(self) -> None:
        state = {"dynamic_step_budget": "not-a-number", "node_step_trace": [{}] * 10}
        assert steps_remaining(state) == 40


# ---------------------------------------------------------------------------
# graph/surface_sizing.py
# ---------------------------------------------------------------------------


class TestSurfaceSizing:
    def test_measure_empty_state(self) -> None:
        from webpent.graph.surface_sizing import measure_surface

        metrics = measure_surface({})
        assert metrics == {
            "endpoints": 0,
            "forms": 0,
            "parameters": 0,
            "graphql_operations": 0,
            "surface_size": 0,
        }

    def test_measure_counts_endpoints_forms_params(self) -> None:
        from webpent.graph.surface_sizing import measure_surface

        state = {
            "crawled_data": {
                "curated_endpoints": [
                    {"path": "/a", "parameters": ["x", "y"]},
                    {"path": "/b", "params": ["z"]},
                    "plain-string-endpoint",
                ],
                "discovered_forms": [{"action": "/login", "fields": ["user", "pass"]}],
                "graphql_operations": [{"name": "users"}],
            }
        }
        metrics = measure_surface(state)
        assert metrics["endpoints"] == 3
        assert metrics["forms"] == 1
        assert metrics["parameters"] == 5
        assert metrics["graphql_operations"] == 1
        assert metrics["surface_size"] == 9

    def test_node_disabled_writes_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from webpent.graph import surface_sizing
        from webpent.config import settings as settings_module

        class _Off:
            enable_dynamic_step_budget = False

        monkeypatch.setattr(settings_module, "get_settings", lambda: _Off())
        result = surface_sizing.surface_sizing_node(
            {"crawled_data": {"curated_endpoints": ["x"] * 500}}
        )
        assert result == {}

    def test_node_writes_metrics_and_budget(self) -> None:
        from webpent.graph.surface_sizing import surface_sizing_node

        state = {"crawled_data": {"curated_endpoints": [{"path": f"/e{i}"} for i in range(100)]}}
        result = surface_sizing_node(state)
        assert result["surface_metrics"]["endpoints"] == 100
        assert result["surface_metrics"]["surface_size"] == 100
        assert result["dynamic_step_budget"] == 150
        assert result["surface_metrics"]["budget_source"] == "dynamic"


# ---------------------------------------------------------------------------
# graph/lesson_nodes.py — advisory contracts + fail-open
# ---------------------------------------------------------------------------


class TestLessonNodes:
    def test_consultation_without_target_is_noop(self) -> None:
        from webpent.graph.lesson_nodes import lesson_consultation_node

        assert lesson_consultation_node({}) == {}

    def test_consultation_output_is_advisory_only(self) -> None:
        from webpent.graph.lesson_nodes import lesson_consultation_node

        class _Target:
            url = "https://wordpress.example.com"

        state = {"target": _Target(), "crawled_data": {}, "client_id": "acme"}
        result = lesson_consultation_node(state)
        # Either an empty dict (no lessons DB in test env) or advisory
        # payloads — never instructions, never authority.
        if result:
            summary = result["consulted_lessons"][0]
            assert summary["advisory_only"] is True
            assert "route_modifiers" in result["lesson_priority_adjustments"]

    def test_extraction_without_client_scope_is_noop(self) -> None:
        from webpent.graph.lesson_nodes import lesson_extraction_node

        assert lesson_extraction_node({"hypotheses": []}) == {}

    def test_extraction_fail_open_on_bad_state(self) -> None:
        from webpent.graph.lesson_nodes import lesson_extraction_node

        # Malformed hypotheses entries must not crash the node.
        state = {
            "client_id": "acme",
            "engagement_id": "e1",
            "hypotheses": ["not-a-dict", {"status": "promoted"}],
            "decision_log": [],
            "findings": [],
        }
        result = lesson_extraction_node(state)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# graph/detector_nodes.py — pass-through contracts
# ---------------------------------------------------------------------------


class TestDetectorNodePassThroughs:
    def test_graphql_noop_without_surface(self) -> None:
        from webpent.graph.detector_nodes import graphql_testing_node

        assert graphql_testing_node({"crawled_data": {}}) == {}
        assert graphql_testing_node({}) == {}

    def test_cache_poisoning_noop_without_responses(self) -> None:
        from webpent.graph.detector_nodes import cache_poisoning_node

        assert cache_poisoning_node({"crawled_data": {}}) == {}

    def test_prototype_pollution_noop_without_samples(self) -> None:
        from webpent.graph.detector_nodes import prototype_pollution_node

        assert prototype_pollution_node({"crawled_data": {}}) == {}

    def test_oauth_noop_without_flow_records(self) -> None:
        from webpent.graph.detector_nodes import oauth_misconfig_node

        assert oauth_misconfig_node({"crawled_data": {}}) == {}

    def test_graphql_activates_with_introspection_payload(self) -> None:
        from webpent.graph.detector_nodes import graphql_testing_node

        state = {
            "crawled_data": {
                "graphql_operations": [{"kind": "query", "name": "users"}],
                "graphql_introspection_payload": {
                    "data": {"__schema": {"queryType": {"name": "Query", "fields": [{"name": "users"}]}}}
                },
            }
        }
        result = graphql_testing_node(state)
        assert result, "introspection payload must activate the node"
        first = result["detector_results"][0]
        assert first["vulnerability_class"] == "graphql_introspection_exposure"
        assert first["outcome"] == "CONFIRMED"
        assert first["advisory_only"] is True


# ---------------------------------------------------------------------------
# graph/progress_display.py
# ---------------------------------------------------------------------------


class TestProgressDisplay:
    def test_phase_mapping_covers_key_nodes(self) -> None:
        from webpent.graph.progress_display import phase_of_node

        assert phase_of_node("planner") == 1
        assert phase_of_node("lesson_consultation") == 1
        assert phase_of_node("surface_sizing") == 4
        assert phase_of_node("reporter") == 7
        assert phase_of_node("unknown-node") == -1

    def test_non_tty_renders_one_line_per_phase_change(self) -> None:
        from webpent.graph.progress_display import HuntProgressRenderer

        stream = io.StringIO()
        renderer = HuntProgressRenderer(stream=stream, is_tty=False, total_steps=10)
        renderer.observe_trace({"node": "planner"})
        renderer.observe_trace({"node": "planner"})
        renderer.observe_trace({"node": "recon"})
        lines = [ln for ln in stream.getvalue().splitlines() if ln.strip()]
        assert len(lines) == 2  # planner phase, then recon phase

    def test_tty_renders_on_every_step(self) -> None:
        from webpent.graph.progress_display import HuntProgressRenderer

        stream = io.StringIO()
        renderer = HuntProgressRenderer(stream=stream, is_tty=True, total_steps=4)
        renderer.observe_trace({"node": "planner"})
        renderer.observe_trace({"node": "auth"})
        renderer.finish()
        assert "\r" in stream.getvalue()
        assert stream.getvalue().endswith("\n")


# ---------------------------------------------------------------------------
# shared/finding_announcer.py
# ---------------------------------------------------------------------------


class TestFindingAnnouncer:
    def test_confirmed_high_severity_announced_once(self) -> None:
        stream = io.StringIO()
        announcer = FindingAnnouncer(stream=stream)
        finding = {
            "id": "f1",
            "validation_status": "CONFIRMED",
            "severity": "CRITICAL",
            "vulnerability_class": "sqli",
            "url": "https://t.example/search",
        }
        announcer.observe_findings([finding, finding])
        output = stream.getvalue()
        assert output.count("CRITICAL: sqli") == 1

    def test_medium_confirmed_not_announced_as_line(self) -> None:
        stream = io.StringIO()
        announcer = FindingAnnouncer(stream=stream)
        announcer.observe_findings(
            [{"id": "f2", "validation_status": "CONFIRMED", "severity": "MEDIUM",
              "vulnerability_class": "csp", "url": "https://t/"}]
        )
        assert stream.getvalue() == ""
        assert announcer.announced_count == 1

    def test_pending_findings_ignored(self) -> None:
        stream = io.StringIO()
        announcer = FindingAnnouncer(stream=stream)
        announcer.observe_findings(
            [{"id": "f3", "validation_status": "PENDING", "severity": "HIGH",
              "vulnerability_class": "xss", "url": "https://t/"}]
        )
        assert stream.getvalue() == ""
        assert announcer.announced_count == 0

    def test_disabled_is_total_noop(self) -> None:
        stream = io.StringIO()
        announcer = FindingAnnouncer(stream=stream, enabled=False)
        announcer.observe_findings(
            [{"id": "f4", "validation_status": "CONFIRMED", "severity": "HIGH",
              "vulnerability_class": "rce", "url": "https://t/"}]
        )
        assert stream.getvalue() == ""

    def test_announce_line_redaction_safe_shape(self) -> None:
        line = _announce_line(
            {"severity": "HIGH", "vulnerability_class": "idor",
             "url": "https://t/api/users?x=1"}
        )
        assert "idor" in line
        assert "https://t/api/users?x=1"[:60] in line


# ---------------------------------------------------------------------------
# cli/unified_hunt.py — preview + guards
# ---------------------------------------------------------------------------


class TestUnifiedHunt:
    def test_authorization_required(self) -> None:
        from webpent.cli.unified_hunt import validate_authorization

        with pytest.raises(ValueError, match="authorization"):
            validate_authorization("")
        with pytest.raises(ValueError):
            validate_authorization(None)
        assert validate_authorization("  bb-2026-42  ") == "bb-2026-42"

    def test_preview_mode_returns_summary_without_graph(self) -> None:
        from webpent.cli.unified_hunt import run_unified_hunt

        summary = run_unified_hunt(
            url="https://authorized-lab.example.com",
            mode="quick",
            authorization="lab-ref",
            run_graph=False,
        )
        assert summary["graph_invoked"] is False
        assert summary["mode"] == "quick"
        assert summary["llm_budget_usd"] == HUNT_MODE_PRESETS["quick"]["llm_budget_usd"]
        assert summary["recursion_limit"] > 50

    def test_preview_rejects_unknown_mode(self) -> None:
        from webpent.cli.unified_hunt import run_unified_hunt

        with pytest.raises(ValueError):
            run_unified_hunt(
                url="https://t.example", mode="mega",
                authorization="x", run_graph=False,
            )

    def test_recursion_limit_always_exceeds_soft_budget(self) -> None:
        from webpent.cli.unified_hunt import recursion_limit_for_mode

        for mode in ("quick", "standard", "deep"):
            assert recursion_limit_for_mode(mode) >= 50 + 60

    def test_preview_requires_authorization(self) -> None:
        from webpent.cli.unified_hunt import run_unified_hunt

        with pytest.raises(ValueError, match="authorization"):
            run_unified_hunt(
                url="https://t.example", mode="quick",
                authorization="", run_graph=False,
            )


# ---------------------------------------------------------------------------
# Graph wiring — the seven new nodes are registered and reachable
# ---------------------------------------------------------------------------


class TestGraphWiring:
    @pytest.fixture(scope="class")
    def compiled(self):  # type: ignore[no-untyped-def]
        from webpent.graph.builder import build_graph

        return build_graph(auto_approve=True)

    def test_new_nodes_registered(self, compiled) -> None:
        names = set(compiled.get_graph().nodes)
        for node in (
            "lesson_consultation",
            "lesson_extraction",
            "surface_sizing",
            "graphql_testing",
            "cache_poisoning",
            "prototype_pollution",
            "oauth_misconfig",
        ):
            assert node in names, f"missing new node: {node}"

    def test_state_channels_declared(self) -> None:
        # The schema must declare the new channels or LangGraph silently
        # drops every node write (the documented total=False trap).
        from webpent.state.state import PentestState

        annotations = PentestState.__annotations__
        for channel in (
            "consulted_lessons",
            "lesson_priority_adjustments",
            "extracted_lessons",
            "surface_metrics",
            "dynamic_step_budget",
            "detector_results",
            "llm_budget_usd",
        ):
            assert channel in annotations, f"state schema missing {channel}"
