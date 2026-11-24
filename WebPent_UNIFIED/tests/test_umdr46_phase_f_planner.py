"""UM-DR-46 Phase F — autonomous experimentation (SKG-driven plans).

The mission's Phase F: the SKG + the priorities drive EXPERIMENT
PLANNING — deterministic plans binding modeled targets to the
registry's experiment families, each with a COMPLETE observed
principal matrix (owner + non-owner), a differential pair, a negative
control and the sealed-replay contract. The planner PLANS ONLY: the
ResearchLoop stays the sole scheduler, execution stays inside
ModernOrchestrator (ScopeLaw + ToolBoundary), and CausalGuard remains
the sole authority. Plans with incomplete matrices are ABSTAINED
(never invented).
"""

from __future__ import annotations

from typing import Any

from webpent.researcher.experiment_planner import (
    experiment_planner_summary,
    plan_experiments,
)

BASE = "https://shop.example"


def _plan_state() -> dict[str, Any]:
    from tests.test_umdr46_phase_b_brain import _brain_state

    return _brain_state()


def _model_of(state: dict[str, Any]) -> Any:
    from webpent.appmodel.skg import build_security_knowledge_graph

    return build_security_knowledge_graph(state)


class TestExperimentPlans:
    """خطط التجارب من الـ SKG — complete matrices only, never invented."""

    def test_orders_123_plan_with_complete_matrix(self) -> None:
        model = _model_of(_plan_state())
        plans = plan_experiments(model)
        assert plans, "orders:123 (alice owner + bob accessor) must plan"
        target = next(
            (p for p in plans if p["target"]["resource_label"] == "resource:orders:123"),
            None,
        )
        assert target is not None
        assert target["registry_experiment_id"] == "exp_idor_v1"
        matrix = target["principal_matrix"]
        assert "identity:alice" in str(matrix["primary"])
        assert "identity:bob" in str(matrix["secondary"])
        assert target["negative_control"]
        assert target["replay_contract"] == "sealed replay, guard adjudicated"
        assert target["advisory_only"] is True
        assert target["preconditions"], "scope-bound + guard-required"

    def test_incomplete_matrix_abstains(self) -> None:
        model = _model_of(_plan_state())
        plans = plan_experiments(model)
        # orders:789 has an ownership change by root but NO observed
        # owner → the matrix is incomplete → NO plan may be emitted
        assert not any(
            p["target"]["resource_label"] == "resource:orders:789"
            for p in plans
        )

    def test_unmarked_reads_without_owner_abstain_honestly(self) -> None:
        model = _model_of(_plan_state())
        plans = plan_experiments(model)
        # invoices:900 has NO observed owner → the matrix is incomplete
        # → the planner must ABSTAIN (never invent a principal), and
        # the abstention must be RECORDED, not silent
        assert not any(
            "/api/admin/invoices/900" in str(p["target"]) for p in plans
        )
        from webpent.researcher.experiment_planner import blocked_targets

        blocked = blocked_targets(model)
        assert any(
            "invoices-900" in b["resource_id"]
            and b["reason"] == "incomplete_principal_matrix"
            for b in blocked
        ), "the abstention must be recorded with its reason"

    def test_plans_deterministic_and_bounded(self) -> None:
        model = _model_of(_plan_state())
        one = plan_experiments(model)
        two = plan_experiments(model)
        assert [p["plan_id"] for p in one] == [p["plan_id"] for p in two]
        assert len(one) <= 16


class TestPlannerNode:
    """The production node writes the advisory channel."""

    def test_node_emits_channel(self) -> None:
        import json

        from webpent.production.experiment_planner_node import (
            experiment_planner_node,
        )

        update = experiment_planner_node(_plan_state())
        assert update["experiment_planner"]["built"] is True
        assert update["experiment_planner"]["advisory_only"] is True
        assert update["experiment_planner"]["plan_count"] > 0
        assert update["experiment_planner"]["scheduler_authority"] == (
            "research_loop_only")
        json.dumps(update["experiment_plans"])
        json.dumps(update["experiment_planner"])

    def test_empty_state_yields_noop(self) -> None:
        from webpent.production.experiment_planner_node import (
            experiment_planner_node,
        )

        update = experiment_planner_node({"engagement_id": "empty"})
        assert update["experiment_planner"]["plan_count"] == 0


class TestSummary:
    def test_summary(self) -> None:
        model = _model_of(_plan_state())
        summary = experiment_planner_summary(model)
        assert summary["advisory_only"] is True
        assert summary["plan_count"] >= 1
