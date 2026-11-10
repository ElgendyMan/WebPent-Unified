"""UM-DR-33 §12 — discovery funnel tests.

The funnel is pure, deterministic, honest about unmaterialised stages,
and produces documented explanations for the major drop patterns.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from webpent.production.discovery_funnel import (  # noqa: E402
    FUNNEL_STAGES,
    STAGE_VERSION,
    build_discovery_funnel,
)


def _state(**overrides):
    base = {
        "surface_metrics": {"endpoints": 24, "surface_size": 24},
        "workflow_observations": [{"step": "create"}, {"step": "submit"}],
        "authorization_observations": [
            {"principal": "User_A", "outcome": "allowed"},
            {"principal": "User_B", "outcome": "denied"},
        ],
        "object_identity_registry": {
            "registry": {
                "stats": {
                    "identities": 9,
                    "abstentions": 2,
                    "conflicts_preserved": 1,
                }
            }
        },
        "identity_alias_graph": {
            "graph": {
                "relationships": [
                    {"state": "confirmed_same_object"},
                    {"state": "confirmed_same_object"},
                    {"state": "candidate_same_object"},
                    {"state": "related_distinct"},
                ]
            }
        },
        "multi_identity_reasoning": {
            "principals": [{"id": "User_A"}, {"id": "User_B"}],
            "differential_questions": [{"q": 1}, {"q": 2}, {"q": 3}],
        },
        "composite_workflow_candidates": [{"seq": 1}, {"seq": 2}],
        "identity_workflow": {
            "capabilities": {
                "object_identity": True, "alias_resolution": True,
                "multi_identity": True, "composite_workflows": True,
            },
            "hypotheses_generated": 7,
        },
        "hypotheses": [
            {"status": "unexplored"},
            {"status": "unexplored"},
            {"status": "resolved_true"},
            {"status": "abandoned"},
        ],
        "findings": [{"id": "f1"}, {"id": "f2"}],
    }
    base.update(overrides)
    return base


class TestPurityAndContract:
    def test_all_stages_present_and_versioned(self) -> None:
        funnel = build_discovery_funnel(_state())
        assert set(funnel["stages"]) == set(FUNNEL_STAGES)
        assert funnel["version"] == STAGE_VERSION

    def test_pure_no_state_mutation(self) -> None:
        state = _state()
        snapshot = copy.deepcopy(state)
        build_discovery_funnel(state)
        assert state == snapshot

    def test_deterministic(self) -> None:
        a = build_discovery_funnel(_state())
        b = build_discovery_funnel(_state())
        assert a == b

    def test_empty_state_is_fail_soft_not_crash(self) -> None:
        funnel = build_discovery_funnel({})
        assert funnel["stages"]["endpoints_discovered"] == "not_materialized_in_state"
        assert funnel["totals"]["measurable_stages"] >= 0

    def test_json_safe_output(self) -> None:
        import json

        json.dumps(build_discovery_funnel(_state()))  # must not raise


class TestStageMeasurements:
    def test_endpoints_from_surface_metrics(self) -> None:
        assert build_discovery_funnel(_state())["stages"]["endpoints_discovered"] == 24

    def test_object_observations_sum_of_channels(self) -> None:
        # workflow (2) + authorization (2) = 4
        assert build_discovery_funnel(_state())["stages"]["object_observations"] == 4

    def test_identity_counts_from_registry_stats(self) -> None:
        stages = build_discovery_funnel(_state())["stages"]
        assert stages["canonical_identities"] == 9
        assert stages["abstained_or_conflicting"] == 3  # 2 abstain + 1 conflict

    def test_alias_state_split(self) -> None:
        stages = build_discovery_funnel(_state())["stages"]
        assert stages["confirmed_aliases"] == 2
        assert stages["candidate_aliases"] == 1

    def test_principals_and_questions(self) -> None:
        stages = build_discovery_funnel(_state())["stages"]
        assert stages["principals_observed"] == 2
        assert stages["differential_questions"] == 3

    def test_workflow_candidates(self) -> None:
        assert build_discovery_funnel(_state())["stages"]["workflow_sequence_candidates"] == 2

    def test_hypothesis_status_split(self) -> None:
        stages = build_discovery_funnel(_state())["stages"]
        assert stages["hypotheses_generated"] == 7
        assert stages["hypotheses_in_pool"] == 4
        assert stages["hypotheses_open"] == 2
        assert stages["hypotheses_resolved"] == 2

    def test_confirmed_findings(self) -> None:
        assert build_discovery_funnel(_state())["stages"]["confirmed_findings"] == 2

    def test_capabilities_surfaced(self) -> None:
        funnel = build_discovery_funnel(_state())
        assert funnel["capabilities"]["object_identity"] is True


class TestHonestUnmaterialised:
    def test_absent_channel_is_marked_not_faked_zero(self) -> None:
        state = _state(surface_metrics=None)
        stages = build_discovery_funnel(state)["stages"]
        assert stages["endpoints_discovered"] == "not_materialized_in_state"
        assert "endpoints_discovered" in build_discovery_funnel(state)["totals"]["not_materialized"]

    def test_not_materialized_never_counts_as_measurement(self) -> None:
        funnel = build_discovery_funnel(_state(surface_metrics=None))
        assert funnel["totals"]["measurable_stages"] < funnel["totals"]["total_stages"]


class TestDropExplanations:
    def test_capability_off_drop_is_explained(self) -> None:
        state = _state()
        state["object_identity_registry"] = {}  # identities never built
        state["identity_workflow"] = {
            "capabilities": {
                "object_identity": False, "alias_resolution": False,
                "multi_identity": False, "composite_workflows": False,
            },
            "hypotheses_generated": 0,
        }
        notes = build_discovery_funnel(state)["drops_explained"]
        assert any("object-identity capability flag is OFF" in n for n in notes)

    def test_abstention_is_explained_as_correct_behavior(self) -> None:
        notes = build_discovery_funnel(_state())["drops_explained"]
        assert any("correct abstention" in n for n in notes)

    def test_no_false_notes_on_healthy_funnel_shape(self) -> None:
        # a state where the explanations should NOT fire
        state = _state(
            identity_alias_graph={"graph": {"relationships": []}},
            object_identity_registry={
                "registry": {"stats": {"identities": 9, "abstentions": 0, "conflicts_preserved": 0}},
            },
        )
        notes = build_discovery_funnel(state)["drops_explained"]
        assert not any("capability flag is OFF" in n for n in notes)
        assert not any("correct abstention" in n for n in notes)

    def test_open_without_findings_note(self) -> None:
        state = _state(findings=[])
        notes = build_discovery_funnel(state)["drops_explained"]
        assert any("CausalGuard authority chain" in n for n in notes)
