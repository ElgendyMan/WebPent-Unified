from __future__ import annotations

from webpent.graph.builder import (
    NODE_SMART_CAMPAIGNS,
    NODE_STRATEGIST,
    route_after_smart_campaigns_execution,
)


def test_research_route_replans_only_within_bounded_rounds() -> None:
    # POST-P0 Phase 11: updated to pin the ACCEPTED P0 G2 contract
    # (IMPL pass, documented in the P0 report §4-G2 and re-verified at
    # POST-P0 Phase 0): an extra smart-campaigns replan round requires
    # evidence-monotonic markers; MISSING markers fail closed to the
    # strategist. The previous pin (continue on missing markers) is the
    # pre-P0 lenient behavior the P0 fix deliberately removed.
    state = {
        "enable_autonomous_controller": False,
        "smart_replanning": {
            "replan_requested": True,
            "round": 1,
            "max_replan_rounds": 3,
            "replan_evidence_start": 1,
            "replan_evidence_end": 2,
        },
    }

    assert route_after_smart_campaigns_execution(state) == NODE_SMART_CAMPAIGNS


def test_research_route_fails_closed_without_evidence_markers() -> None:
    # Pinned P0 contract: missing evidence markers fail closed.
    state = {
        "enable_autonomous_controller": False,
        "smart_replanning": {
            "replan_requested": True,
            "round": 1,
            "max_replan_rounds": 3,
        },
    }

    assert route_after_smart_campaigns_execution(state) == NODE_STRATEGIST


def test_research_route_fails_closed_on_non_monotonic_evidence() -> None:
    # Pinned P0 contract: evidence must GROW to spend another round.
    state = {
        "enable_autonomous_controller": False,
        "smart_replanning": {
            "replan_requested": True,
            "round": 1,
            "max_replan_rounds": 3,
            "replan_evidence_start": 2,
            "replan_evidence_end": 2,
        },
    }

    assert route_after_smart_campaigns_execution(state) == NODE_STRATEGIST


def test_research_route_stops_when_round_budget_is_exhausted() -> None:
    state = {
        "enable_autonomous_controller": False,
        "smart_replanning": {
            "replan_requested": True,
            "round": 3,
            "max_replan_rounds": 3,
        },
    }

    assert route_after_smart_campaigns_execution(state) == NODE_STRATEGIST


def test_research_route_stops_without_observation_request() -> None:
    state = {
        "enable_autonomous_controller": False,
        "smart_replanning": {
            "replan_requested": False,
            "round": 1,
            "max_replan_rounds": 3,
        },
    }

    assert route_after_smart_campaigns_execution(state) == NODE_STRATEGIST


def test_controller_route_remains_explicitly_opt_in() -> None:
    state = {
        "enable_autonomous_controller": True,
        "smart_replanning": {
            "replan_requested": True,
            "round": 1,
            "max_replan_rounds": 3,
        },
    }

    assert route_after_smart_campaigns_execution(state) == "autonomous_controller"
