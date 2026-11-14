"""Tests for the autonomous hunt orchestrator (Phase 1).

These verify the loop's governance properties, not just its happy path:

* it fails closed when runtime dependencies are missing,
* it never promotes a finding without a verified proof bundle,
* it stops with an explicit typed reason on every convergence bound,
* learning hints can reorder but never override the deterministic ranking,
* a bundle that does not verify is refused.
"""

from __future__ import annotations

from typing import Any

from webpent.autonomous import (
    AutonomousHuntOrchestrator,
    AutonomousHuntState,
    HuntOutcome,
    HuntPhase,
    HuntStopReason,
    run_autonomous_hunt,
)
from webpent.autonomous.hunt_orchestrator import (
    _apply_learning_hints,
    _bundle_verifies,
    _coerce_hypotheses,
    _controller_stop_reason,
    _has_negative_control,
    _outcome_for,
)


class _FakeController:
    """A controller double that returns a scripted update per iteration."""

    def __init__(self, updates: list[dict[str, Any]]) -> None:
        self._updates = updates
        self.calls = 0

    def run(self, state, *, handler, iterations=1):  # noqa: ANN001
        update = self._updates[min(self.calls, len(self._updates) - 1)]
        self.calls += 1
        return dict(update)


class _FakeMemory:
    def __init__(self, hints: dict[str, float]) -> None:
        self._hints = hints

    def update(self, state):  # noqa: ANN001
        return dict(self._hints)


def _sealed_bundle():
    from webpent.models.proof_bundle import build_proof_bundle

    return build_proof_bundle(
        engagement_id="e1",
        finding_id="f1",
        evidence=[{"status": 200, "causal_signal": True}],
        evidence_refs=["obs:1"],
        negative_control={"status": 403, "matched": True},
    ).seal(actor="validator")


def test_hunt_fails_closed_without_executor() -> None:
    state = run_autonomous_hunt(
        engagement_id="e1", target_url="http://lab.example/", max_iterations=3
    )
    assert state.stop_reason is HuntStopReason.RUNTIME_DEPENDENCIES_MISSING
    assert state.outcome is HuntOutcome.BLOCKED


def test_hunt_records_all_phases_in_order() -> None:
    state = run_autonomous_hunt(
        engagement_id="e1", target_url="http://lab.example/", max_iterations=1
    )
    phases = [record.phase for record in state.phase_trace]
    assert phases[0] is HuntPhase.RECON
    assert HuntPhase.EXECUTE in phases
    assert phases[-1] is HuntPhase.REPORT


def test_hunt_stops_on_no_new_evidence() -> None:
    controller = _FakeController([{"task_outcomes": [], "stop_reason": ""}])
    orch = AutonomousHuntOrchestrator(
        action_executor=object(),
        handler=lambda task: None,
        controller=controller,
        max_iterations=5,
    )
    state = AutonomousHuntState(engagement_id="e1", target_url="http://lab.example/")
    result = orch.run(state)
    assert result.stop_reason is HuntStopReason.NO_NEW_EVIDENCE
    assert result.outcome is HuntOutcome.INCONCLUSIVE


def test_hunt_confirms_only_with_verified_bundle() -> None:
    bundle = _sealed_bundle()
    controller = _FakeController(
        [
            {
                "task_outcomes": [{"status": "confirmed"}],
                "positive_evidence_ledger": [{"id": "p1"}],
                "proof_bundles": [bundle],
                "stop_reason": "no_new_ready_task",
            }
        ]
    )
    orch = AutonomousHuntOrchestrator(
        action_executor=object(),
        handler=lambda task: None,
        controller=controller,
        max_iterations=3,
    )
    state = AutonomousHuntState(engagement_id="e1", target_url="http://lab.example/")
    result = orch.run(state)
    assert len(result.proof_bundles) == 1
    assert result.outcome is HuntOutcome.CONFIRMED


def test_unverified_bundle_is_refused() -> None:
    # A dict claiming to be sealed but with no seal_digest must be refused.
    controller = _FakeController(
        [
            {
                "task_outcomes": [{"status": "confirmed"}],
                "positive_evidence_ledger": [{"id": "p1"}],
                "proof_bundles": [{"sealed": True, "seal_digest": None}],
                "stop_reason": "no_new_ready_task",
            }
        ]
    )
    orch = AutonomousHuntOrchestrator(
        action_executor=object(),
        handler=lambda task: None,
        controller=controller,
        max_iterations=3,
    )
    state = AutonomousHuntState(engagement_id="e1", target_url="http://lab.example/")
    result = orch.run(state)
    assert result.proof_bundles == []
    assert result.outcome is HuntOutcome.INCONCLUSIVE


def test_learning_hints_are_capped_so_they_cannot_dominate() -> None:
    hypotheses = [
        {"pattern_id": "a", "priority": 1.0},
        {"pattern_id": "b", "priority": 0.5},
    ]
    # The hint is capped at 0.75, so b's effective score is 0.5 + 0.75 = 1.25.
    # Without the cap a hint of 999.0 would put b arbitrarily far ahead; with
    # it the boost is bounded and predictable.
    ranked = _apply_learning_hints(hypotheses, {"b": 999.0})
    assert ranked[0]["pattern_id"] == "b"
    # A hint cannot overcome a deterministic gap larger than the cap.
    hypotheses2 = [
        {"pattern_id": "a", "priority": 2.0},
        {"pattern_id": "b", "priority": 0.5},
    ]
    ranked2 = _apply_learning_hints(hypotheses2, {"b": 999.0})
    assert ranked2[0]["pattern_id"] == "a"


def test_learning_hints_can_promote_a_close_candidate() -> None:
    hypotheses = [
        {"pattern_id": "a", "priority": 0.60},
        {"pattern_id": "b", "priority": 0.50},
    ]
    ranked = _apply_learning_hints(hypotheses, {"b": 0.30})
    assert ranked[0]["pattern_id"] == "b"


def test_memory_hints_are_clamped_in_state() -> None:
    controller = _FakeController(
        [
            {
                "task_outcomes": [{"status": "ok"}],
                "positive_evidence_ledger": [{"id": "p1"}],
                "stop_reason": "",
            }
        ]
    )
    orch = AutonomousHuntOrchestrator(
        action_executor=object(),
        handler=lambda task: None,
        controller=controller,
        memory=_FakeMemory({"a": 5.0}),
        max_iterations=1,
    )
    state = AutonomousHuntState(engagement_id="e1", target_url="http://lab.example/")
    result = orch.run(state)
    assert result.learning_hints["a"] <= 0.75


def test_outcome_mapping_blocks_on_governance_stops() -> None:
    state = AutonomousHuntState(engagement_id="e1", target_url="http://lab.example/")
    assert _outcome_for(HuntStopReason.SCOPE_DENIED, state) is HuntOutcome.BLOCKED
    assert _outcome_for(HuntStopReason.AUTHORITY_DENIED, state) is HuntOutcome.BLOCKED
    assert _outcome_for(HuntStopReason.NO_NEW_EVIDENCE, state) is HuntOutcome.INCONCLUSIVE


def test_coerce_hypotheses_handles_objects_and_dicts() -> None:
    class _Item:
        def as_dict(self):
            return {"pattern_id": "x"}

    assert _coerce_hypotheses(None) == []
    assert _coerce_hypotheses({"pattern_id": "y"}) == [{"pattern_id": "y"}]
    assert _coerce_hypotheses(_Item()) == [{"pattern_id": "x"}]


def test_bundle_verifies_rejects_none_and_bad_dicts() -> None:
    assert _bundle_verifies(None) is False
    assert _bundle_verifies({"sealed": False}) is False
    assert _bundle_verifies(_sealed_bundle()) is True


def test_state_summary_is_redaction_safe() -> None:
    state = AutonomousHuntState(
        engagement_id="e1",
        target_url="http://lab.example/?token=supersecretvalue12345",
    )
    summary = state.summary()
    assert "supersecretvalue12345" not in str(summary)


def test_real_controller_contract_is_understood() -> None:
    """The loop reads the real controller keys: stop_decision.reason,
    campaign_task_outcomes, and per-record sealed proof bundles."""
    bundle = _sealed_bundle()
    controller = _FakeController(
        [
            {
                "campaign_task_outcomes": [
                    {"status": "executed", "proof_bundle_sealed": True, "proof_bundle": bundle},
                    {"status": "policy_denied", "proof_bundle_sealed": False, "proof_bundle": None},
                ],
                "positive_evidence_ledger": [{"id": "p1"}],
                "stop_decision": {"should_stop": True, "reason": "no_new_ready_task"},
            }
        ]
    )
    orch = AutonomousHuntOrchestrator(
        action_executor=object(),
        handler=lambda task: None,
        controller=controller,
        max_iterations=3,
    )
    state = AutonomousHuntState(engagement_id="e1", target_url="http://lab.example/")
    result = orch.run(state)
    assert len(result.outcomes) == 2
    assert len(result.proof_bundles) == 1
    assert result.stop_reason is HuntStopReason.NO_NEW_READY_TASK
    assert result.outcome is HuntOutcome.CONFIRMED


def test_stop_decision_beats_top_level_and_replanning_fallback() -> None:
    assert _controller_stop_reason({"stop_decision": {"reason": "same_action_repeated"}}) == (
        "same_action_repeated"
    )
    assert _controller_stop_reason({"stop_reason": "no_new_evidence"}) == "no_new_evidence"
    assert (
        _controller_stop_reason({"smart_replanning": {"stop_reason": "operator_halt"}})
        == "operator_halt"
    )
    assert _controller_stop_reason({}) == ""


def _bundle_without_negative_control():
    from webpent.models.proof_bundle import build_proof_bundle

    return build_proof_bundle(
        engagement_id="e1",
        finding_id="f1",
        evidence=[{"status": 200, "causal_signal": True}],
        evidence_refs=["obs:1"],
    ).seal(actor="validator")


def test_bundle_without_negative_control_is_refused() -> None:
    bundle = _bundle_without_negative_control()
    assert _has_negative_control(bundle) is False
    controller = _FakeController(
        [
            {
                "campaign_task_outcomes": [
                    {
                        "status": "executed",
                        "proof_bundle_sealed": True,
                        "proof_bundle": bundle,
                    }
                ],
                "stop_decision": {"reason": "no_new_ready_task"},
            }
        ]
    )
    orch = AutonomousHuntOrchestrator(
        action_executor=object(), handler=lambda t: None, controller=controller
    )
    state = AutonomousHuntState(engagement_id="e1", target_url="http://lab.example/")
    result = orch.run(state)
    assert result.proof_bundles == []
    assert result.outcome is not HuntOutcome.CONFIRMED


def test_foreign_engagement_bundle_is_refused() -> None:
    bundle = _sealed_bundle()
    controller = _FakeController(
        [
            {
                "campaign_task_outcomes": [
                    {
                        "status": "executed",
                        "proof_bundle_sealed": True,
                        "proof_bundle": bundle,
                    }
                ],
                "stop_decision": {"reason": "no_new_ready_task"},
            }
        ]
    )
    orch = AutonomousHuntOrchestrator(
        action_executor=object(), handler=lambda t: None, controller=controller
    )
    state = AutonomousHuntState(
        engagement_id="e1", target_url="http://lab.example/"
    )
    result = orch.run(state)
    assert len(result.proof_bundles) == 1

    orch2 = AutonomousHuntOrchestrator(
        action_executor=object(), handler=lambda t: None, controller=controller
    )
    state2 = AutonomousHuntState(
        engagement_id="e2", target_url="http://lab.example/"
    )
    result2 = orch2.run(state2)
    assert result2.proof_bundles == []
    assert result2.outcome is HuntOutcome.INCONCLUSIVE


def test_verified_bundles_link_to_findings_report() -> None:
    bundle = _sealed_bundle()
    controller = _FakeController(
        [
            {
                "campaign_task_outcomes": [
                    {
                        "status": "executed",
                        "proof_bundle_sealed": True,
                        "proof_bundle": bundle,
                    }
                ],
                "stop_decision": {"reason": "no_new_ready_task"},
            }
        ]
    )
    orch = AutonomousHuntOrchestrator(
        action_executor=object(), handler=lambda t: None, controller=controller
    )
    state = AutonomousHuntState(engagement_id="e1", target_url="http://lab.example/")
    result = orch.run(state)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["finding_id"] == "f1"
    assert finding["proof_digest"] == str(bundle.seal_digest)
