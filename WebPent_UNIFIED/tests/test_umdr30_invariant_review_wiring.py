"""UM-DR-30 Workstream D §6 — business-invariant review wiring.

The deterministic ``InvariantChecker`` was a zero-importer orphan (UM-DR-29
qualification matrix: business_invariant reasoning = PROPOSED) while its
exact input — ``WorkflowObservation`` records — already flowed through the
declared ``workflow_observations`` channel whenever the campaign ran with
``enable_workflow_understanding``. This window closes that dead-capability
wiring gap: the business_logic_fuzzer's workflow enrichment now feeds the
observations through the checker and emits an ``invariant_review`` advisory
channel.

Contract pins:

1. CHECKER SEMANTICS — the three conservative invariants, verified on
   directly constructed observations (destructive replay, missing
   authorization context, denied-scope processing).
2. WIRING — the enrichment returns the review only when the workflow flag
   is on; it is fail-soft on checker failure and on missing
   engagement/target identity context.
3. NON-PROMOTION — every entry is a ``candidate_violation`` whose
   ``required_validation`` names the causal-guard evidence contract; the
   enrichment never emits ``findings``; confirmation authority stays with
   cqa_v2/causal_guard.py.
4. LANGGRAPH RUNTIME — the real node inside a compiled StateGraph over
   the real PentestState: ``invariant_review`` survives channel filtering
   (declared, merge_lists append-only).
"""

from __future__ import annotations

from typing import Any

import pytest

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _observation(**overrides: Any):
    """Construct a minimal valid WorkflowObservation for checker tests."""
    from webpent.models.workflows import WorkflowObservation

    base: dict[str, Any] = {
        "fingerprint": "fp-0123456789abcdef",
        "workflow_key": "orders",
        "transition_key": "submitted->settled",
        "source_ref": "crawler:forms",
        "endpoint": "http://t.example/app/orders",
        "method": "POST",
        "from_state": "submitted",
        "to_state": "settled",
    }
    base.update(overrides)
    return WorkflowObservation(**base)


def _crawled_data_with_replay_violation() -> dict[str, Any]:
    """workflow_steps record: destructive, from_state == to_state, no
    forms → the node's burst executor never engages (safe test fixture),
    but the observation extraction sees a replay-shaped transition."""
    return {
        "workflow_steps": [
            {
                "url": "http://t.example/app/orders/1",
                "method": "DELETE",
                "state": "submitted",
            }
        ]
    }


class _Target:
    """Dict-free target object exposing url + is_in_scope."""

    url = "http://t.example"

    @staticmethod
    def is_in_scope(url: str) -> bool:  # pragma: no cover - trivial
        return str(url).startswith("http://t.example/")


# ---------------------------------------------------------------------------
# 1. checker semantics (the orphan module, now load-bearing)
# ---------------------------------------------------------------------------


class TestCheckerSemantics:
    def test_destructive_same_state_transition_is_a_candidate(self) -> None:
        from webpent.business_logic.invariant_checker import InvariantChecker

        results = InvariantChecker().check(
            [_observation(method="DELETE", to_state="submitted", destructive=True)],
            target_id="t-1",
            engagement_id="e-1",
        )
        assert [r.invariant for r in results] == [
            "state_must_progress_or_reject_replay"
        ]
        assert results[0].status == "candidate_violation"

    def test_progressing_destructive_transition_is_clean(self) -> None:
        from webpent.business_logic.invariant_checker import InvariantChecker

        results = InvariantChecker().check(
            [_observation(method="DELETE", from_state="submitted", to_state="deleted")],
            target_id="t-1",
            engagement_id="e-1",
        )
        assert results == []

    def test_cross_identity_without_context_is_a_candidate(self) -> None:
        from webpent.business_logic.invariant_checker import InvariantChecker

        results = InvariantChecker().check(
            [_observation(authorization_boundary="cross_identity", identity_ref=None)],
            target_id="t-1",
            engagement_id="e-1",
        )
        assert [r.invariant for r in results] == [
            "authorization_context_must_be_present"
        ]

    def test_denied_scope_processing_is_a_candidate(self) -> None:
        from webpent.business_logic.invariant_checker import InvariantChecker

        results = InvariantChecker().check(
            [_observation(scope_decision="denied")],
            target_id="t-1",
            engagement_id="e-1",
        )
        assert [r.invariant for r in results] == [
            "out_of_scope_transition_must_not_be_processed"
        ]

    def test_results_are_bounded(self) -> None:
        from webpent.business_logic.invariant_checker import InvariantChecker

        many = [
            _observation(
                fingerprint=f"fp-{i:016d}",
                scope_decision="denied",
            )
            for i in range(400)
        ]
        assert len(InvariantChecker().check(many, target_id="t", engagement_id="e")) == 256

    def test_context_is_required(self) -> None:
        from webpent.business_logic.invariant_checker import InvariantChecker

        with pytest.raises(ValueError):
            InvariantChecker().check(
                [_observation(scope_decision="denied")], target_id="", engagement_id="e"
            )


# ---------------------------------------------------------------------------
# 2. the enrichment wiring (flag, fail-soft, honesty)
# ---------------------------------------------------------------------------


class TestEnrichmentWiring:
    @pytest.fixture(autouse=True)
    def _workflow_flag_on(self, monkeypatch):
        from webpent.config.settings import get_settings

        monkeypatch.setattr(get_settings(), "enable_workflow_understanding", True)

    def _enrich(self, state=None, crawled=None, target=None):
        from webpent.agents.business_logic_fuzzer.agent import _workflow_enrichment

        return _workflow_enrichment(
            state if state is not None else {"engagement_id": "eng-umdr30"},
            crawled if crawled is not None else _crawled_data_with_replay_violation(),
            target if target is not None else {"url": "http://t.example"},
        )

    def test_review_flows_when_flag_enabled(self) -> None:
        update = self._enrich()
        review = update.get("invariant_review") or []
        assert review, "invariant review did not flow through the enrichment"
        entry = review[0]
        assert entry["invariant"] == "state_must_progress_or_reject_replay"
        assert entry["status"] == "candidate_violation"
        assert entry["engagement_id"] == "eng-umdr30"
        # target_id fell back to the target-url digest (target_id absent)
        assert entry["target_id"].startswith("target-")

    def test_flag_off_disables_the_whole_enrichment(self, monkeypatch) -> None:
        from webpent.config.settings import get_settings

        monkeypatch.setattr(get_settings(), "enable_workflow_understanding", False)
        assert self._enrich() == {}

    def test_missing_engagement_skips_review_fail_soft(self) -> None:
        update = self._enrich(state={})  # no engagement_id, no target_id
        assert update.get("invariant_review") == []
        # observations still flow — the review is the only thing skipped
        assert update.get("workflow_observations")

    def test_checker_failure_never_breaks_the_campaign(self, monkeypatch) -> None:
        import webpent.business_logic.invariant_checker as checker_module

        def _boom(*args: Any, **kwargs: Any):
            raise RuntimeError("checker exploded")

        monkeypatch.setattr(checker_module.InvariantChecker, "check", _boom)
        update = self._enrich()
        assert update.get("invariant_review") == []
        assert update.get("workflow_observations")

    def test_clean_surface_yields_empty_review(self) -> None:
        update = self._enrich(
            crawled={
                "workflow_steps": [
                    {
                        "url": "http://t.example/app/orders/1",
                        "method": "DELETE",
                        "state": "submitted",
                        "to_state": "deleted",
                    }
                ]
            }
        )
        assert update.get("invariant_review") == []


# ---------------------------------------------------------------------------
# 3. non-promotion pins (the precision guarantee)
# ---------------------------------------------------------------------------


class TestNonPromotionPins:
    @pytest.fixture(autouse=True)
    def _workflow_flag_on(self, monkeypatch):
        from webpent.config.settings import get_settings

        monkeypatch.setattr(get_settings(), "enable_workflow_understanding", True)

    def test_entries_demand_the_causal_guard_contract(self) -> None:
        from webpent.agents.business_logic_fuzzer.agent import _workflow_enrichment

        update = _workflow_enrichment(
            {"engagement_id": "eng-umdr30"},
            _crawled_data_with_replay_violation(),
            {"url": "http://t.example"},
        )
        for entry in update["invariant_review"]:
            assert set(entry["required_validation"]) >= {
                "target_backed_causal_signal",
                "independent_negative_control",
                "sealed_replayable_proof_bundle",
            }
            assert entry["status"] != "confirmed"

    def test_enrichment_never_emits_findings(self) -> None:
        from webpent.agents.business_logic_fuzzer.agent import _workflow_enrichment

        update = _workflow_enrichment(
            {"engagement_id": "eng-umdr30"},
            _crawled_data_with_replay_violation(),
            {"url": "http://t.example"},
        )
        assert "findings" not in update
        assert "confirmed_findings" not in update


# ---------------------------------------------------------------------------
# 4. the LangGraph runtime level (the real node, the real state schema)
# ---------------------------------------------------------------------------


class TestLangGraphRuntimeSurvival:
    def test_invariant_review_survives_channel_filtering(self, monkeypatch) -> None:
        from langgraph.graph import END, START, StateGraph

        from webpent.agents.business_logic_fuzzer.agent import business_logic_fuzzer_node
        from webpent.config.settings import get_settings
        from webpent.state.state import PentestState

        monkeypatch.setattr(get_settings(), "enable_workflow_understanding", True)

        graph = StateGraph(PentestState)
        graph.add_node("business_logic_fuzzer", business_logic_fuzzer_node)
        graph.add_edge(START, "business_logic_fuzzer")
        graph.add_edge("business_logic_fuzzer", END)
        compiled = graph.compile()

        # workflow_steps produce the observation; no forms → no burst
        # endpoints → the node returns the workflow update on its safe
        # early path (no request ever leaves the process).
        result = compiled.invoke(
            {
                "engagement_id": "eng-umdr30",
                "target": {"url": "http://t.example"},
                "crawled_data": _crawled_data_with_replay_violation(),
            },
            config={"recursion_limit": 25},
        )

        review = result.get("invariant_review") or []
        assert review, "invariant_review was dropped or never written"
        assert review[0]["invariant"] == "state_must_progress_or_reject_replay"
        assert review[0]["status"] == "candidate_violation"
        # the adjacent workflow channels still flow (no regression)
        assert result.get("workflow_observations")

    def test_channel_is_append_only(self) -> None:
        """merge_lists: a second enrichment run appends rather than
        replacing — the audit trail survives model refreshes.

        state.py uses ``from __future__ import annotations``, so raw
        ``__annotations__`` values are unresolved ForwardRefs; the check
        resolves them with ``get_type_hints(include_extras=True)``."""
        import typing

        from webpent.state.state import PentestState

        resolved = typing.get_type_hints(PentestState, include_extras=True)
        annotation = resolved["invariant_review"]
        assert typing.get_origin(annotation) is not None
        reducer = typing.get_args(annotation)[1]
        assert getattr(reducer, "__name__", None) == "merge_lists", (
            f"invariant_review lost its merge_lists reducer: {reducer!r}"
        )
