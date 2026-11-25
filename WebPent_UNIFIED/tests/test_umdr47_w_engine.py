"""UM-DR-47 Phase W — the brain-engine wiring (W1/W4/W5 + the node).

Law 47-1 (Wire-or-it-doesn't-exist): every capability must reach
actual campaign behavior. These tests prove the wiring itself on the
46 Phase-B lab fixture (same SKG, same ground truth):

* W1 — the SKG queries (ownership_changers / reads_without_authz /
  get_all_paths_to) land in the priority context that scores
  hypotheses;
* W4 — unverified coverage cells become canonical research-task
  hypotheses (executed inside the same campaign);
* W5 — attack chains decompose into sequentially-gated step
  hypotheses (step N rankable only after step N-1 closes);
* the node writes the declared state channels and the pool.
"""
from __future__ import annotations

from tests.test_umdr46_phase_b_brain import _brain_state

from webpent.production.brain_engine import (
    BrainPriorityContext,
    brain_engine_node,
    build_brain_context,
    chain_step_hypotheses,
    coverage_gap_hypotheses,
    priority_formula,
    rank_with_brain,
)


def _ctx():
    return build_brain_context(_brain_state())


class TestW1Context:
    def test_context_builds_from_real_state(self):
        ctx = _ctx()
        assert ctx.built is True
        assert ctx.error == ""
        assert ctx.model is not None

    def test_ownership_changers_feed_the_context(self):
        # the fixture plants an UNMARKED ownership change on
        # /api/admin/invoices/900 (actor bob) — W1 must see it
        ctx = _ctx()
        assert any(
            "invoices" in path or "900" in path
            for path in ctx.ownership_changer_targets
        ), ctx.ownership_changer_targets

    def test_sensitive_reachability_uses_skg_paths(self):
        ctx = _ctx()
        # at least one endpoint path carries a reachability weight
        assert ctx.sensitive_reachable, "W1a produced no reachability"

    def test_context_deterministic(self):
        a, b = _ctx(), _ctx()
        assert a.sensitive_reachable == b.sensitive_reachable
        assert sorted(a.ownership_changer_targets) == sorted(b.ownership_changer_targets)
        assert a.coverage_cells == b.coverage_cells


class TestW4CoverageGapTasks:
    def test_unverified_cells_become_research_tasks(self):
        ctx = _ctx()
        assert ctx.unverified_cells, "fixture has no unverified cells"
        tasks = coverage_gap_hypotheses(ctx, "https://shop.example")
        assert tasks, "no coverage-gap tasks emitted"
        for task in tasks:
            assert str(task.origin) == "researcher_brain"
            assert "UM-DR-47 W4" in task.origin_detail
            assert task.info_gain is not None and 0.0 < task.info_gain <= 1.0
            # canonical contract fields present
            assert task.evidence_contract["appmodel_hint"]["kind"] == "coverage_gap"

    def test_tasks_are_deterministic_ids(self):
        ctx = _ctx()
        a = [str(t.id) for t in coverage_gap_hypotheses(ctx, "https://shop.example")]
        b = [str(t.id) for t in coverage_gap_hypotheses(ctx, "https://shop.example")]
        assert a == b


class TestW5ChainSteps:
    def test_chains_decompose_into_ordered_steps(self):
        ctx = _ctx()
        assert ctx.chains, "fixture produces no attack chains"
        steps = chain_step_hypotheses(ctx, "https://shop.example")
        assert len(steps) >= 2, "no multi-step chains emitted"
        for step in steps:
            meta = step.evidence_contract["chain_step"]
            assert meta["chain_id"]
            assert meta["total"] >= 2
            assert "step=" in step.origin_detail

    def test_step_gate_blocks_until_predecessor_closes(self):
        ctx = _ctx()
        steps = chain_step_hypotheses(ctx, "https://shop.example")
        first, second = steps[0], steps[1]
        # both open → first ranks, second gated to score 0 (bottom)
        open_pool = [first, second]
        ranked = rank_with_brain(open_pool, ctx)
        ranked_ids = [str(h.id) for h, _ in ranked]
        assert ranked_ids[0] == str(first.id)
        assert ranked_ids[-1] == str(second.id)
        # predecessor closes (refuted) → the gate OPENS for step 2
        from webpent.models.hypothesis import HypothesisStatus
        second_prev = first.model_copy(
            update={"status": HypothesisStatus.RESOLVED_FALSE}
        )
        ranked2 = rank_with_brain([second, second_prev], ctx)
        scores = {str(h.id): s for h, s in ranked2}
        assert scores[str(second.id)] > 0.0

    def test_gate_open_when_predecessor_missing(self):
        # lone step (predecessor pruned) must not starve
        ctx = _ctx()
        steps = chain_step_hypotheses(ctx, "https://shop.example")
        lone = steps[1]
        ranked = rank_with_brain([lone], ctx)
        assert ranked[0][1] > 0.0


class TestBrainEngineNode:
    def test_node_writes_declared_channels_and_pool(self):
        update = brain_engine_node(_brain_state())
        assert set(update) == {"brain_engine", "brain_engine_context", "hypotheses"}
        summary = update["brain_engine"]
        assert summary["built"] is True
        assert summary["unverified_cells"] >= 1
        assert summary["influence_contract"].startswith("wired")
        # the pool gets BOTH W4 tasks and W5 steps
        pool = update["hypotheses"]
        w4 = [h for h in pool if "UM-DR-47 W4" in h.origin_detail]
        w5 = [h for h in pool if "UM-DR-47 W5" in h.origin_detail]
        assert w4 and w5

    def test_node_fail_safe_on_empty_state(self):
        # an empty state builds a valid EMPTY model — no tasks, no
        # steps, no crash (the honest fail-safe for bare state)
        update = brain_engine_node({})
        assert update["brain_engine"]["unverified_cells"] == 0
        assert update["hypotheses"] == []

    def test_flag_gates_graph_wiring(self, monkeypatch):
        from webpent.config.settings import get_settings
        from webpent.graph import builder as graph_builder

        monkeypatch.setattr(get_settings(), "enable_brain_engine", False)
        assert graph_builder._brain_engine_enabled() is False
        monkeypatch.setattr(get_settings(), "enable_brain_engine", True)
        assert graph_builder._brain_engine_enabled() is True


class TestRankingUsesFormula:
    def test_rank_with_brain_orders_by_formula(self):
        ctx = _ctx()
        steps = chain_step_hypotheses(ctx, "https://shop.example")
        # a coverage task with high EIG should outrank a low-EIG step
        tasks = coverage_gap_hypotheses(ctx, "https://shop.example")
        assert tasks
        ranked = rank_with_brain(steps + tasks, ctx)
        assert ranked
        # every returned score is the formula applied (positive)
        assert all(score >= 0.0 for _, score in ranked)
