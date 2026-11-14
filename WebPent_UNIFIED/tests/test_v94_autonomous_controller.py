from __future__ import annotations

from types import SimpleNamespace

from webpent.shared.action_authority import ActionAuthority
from webpent.shared.autonomous_controller import AutonomousController
from webpent.shared.campaign_executor import ActionExecutor


def _state() -> dict:
    return {
        "smart_mode": True,
        "scan_mode": "safe-smart",
        "engagement_id": "engagement:test-controller",
        "target": {"url": "http://example.test"},
        "campaign_plan": {
            "entries": [
                {
                    "key": "sqli",
                    "matched_observation_refs": ["surface:0"],
                    "contract": {
                        "method": "GET",
                        "oracle": "status_compare",
                        "preconditions": ["surface observed"],
                        "observed_preconditions": ["surface observed"],
                    },
                }
            ]
        },
        "crawled_data": {
            "surface_records": [
                {"url": "http://example.test/item", "ref": "surface:0"}
            ]
        },
        "findings": [],
        "hypotheses": [],
        "campaign_task_outcomes": [],
        "research_decision_trace": [],
    }


def test_controller_requires_injected_runtime_dependencies() -> None:
    try:
        AutonomousController().run(_state())
    except RuntimeError as exc:
        assert "runtime_dependencies_required" in str(exc)
    else:
        raise AssertionError("controller must reject missing runtime dependencies")


def test_controller_executes_only_through_action_executor() -> None:
    authority = ActionAuthority(
        settings=SimpleNamespace(
            scan_mode="safe-smart",
            smart_auto_approve=False,
            smart_action_budget=10.0,
            smart_max_actions=3,
            smart_require_idempotency=True,
        ),
        allowed_origin="http://example.test",
        manifest={"capabilities": {"http_read": {"available": True}}},
    )
    executor = ActionExecutor(authority)
    calls: list[str] = []

    def handler(task):
        calls.append(task.task_id)
        return {
            "finding_id": "finding:test-controller",
            "proof_evidence": [{"kind": "response", "status_code": 200}],
            "evidence_refs": ["surface:0"],
            "negative_control": {"status": "completed", "matched": False},
            "proof_verified": True,
            # See test_v92_action_executor_proof_bundle.py — GOED's
            # proof_bundle_promotion_ready() requires this full evidence
            # envelope before sealing a bundle.
            "baseline": {"kind": "response", "status_code": 403},
            "request_evidence": [{"method": "GET", "url": "http://example.test/"}],
            "response_evidence": [{"status": 200}],
            "scope_context": {"targets": ["example.test"], "authorized": True},
            "identity_context": {"identity": "primary", "authenticated": True},
            "target_fingerprint": "sha256:fixture-target",
            "causal_oracle": {
                "causal_signal": True,
                "negative_control_complete": True,
                "requires_target_backed": False,
            },
            "validator_id": "controller-fixture-validator",
            "validator_version": "v1",
            "replay_metadata": {"replayable": True},
            "cleanup_status": "not_applicable",
        }

    result = AutonomousController(action_executor=executor, max_iterations=2).run(
        _state(), handler=handler, iterations=1
    )

    assert len(calls) == 1
    assert result["smart_replanning"]["status"] == "controller_completed"
    assert result["campaign_task_outcomes"][0]["status"] == "executed"
    assert result["campaign_task_outcomes"][0]["proof_bundle_sealed"] is True
    assert result["lifecycle_events"]


def test_controller_blocks_unproven_preconditions_before_handler() -> None:
    state = _state()
    state["campaign_plan"]["entries"][0]["contract"].pop("observed_preconditions", None)
    calls: list[str] = []

    result = AutonomousController(
        action_executor=ActionExecutor(
            ActionAuthority(
                settings=SimpleNamespace(
                    scan_mode="safe-smart",
                    smart_auto_approve=False,
                    smart_action_budget=10.0,
                    smart_max_actions=3,
                    smart_require_idempotency=True,
                ),
                allowed_origin="http://example.test",
                manifest={"capabilities": {"http_read": {"available": True}}},
            )
        )
    ).run(state, handler=lambda task: calls.append(task.task_id), iterations=1)

    assert calls == []
    assert result["campaign_task_outcomes"][0]["status"] == "blocked_by_precondition"
    assert result["smart_replanning"]["controller_executed"] == 0


def test_controller_requires_executor_when_handler_is_present() -> None:
    calls: list[str] = []

    try:
        AutonomousController().run(_state(), handler=lambda task: calls.append(task.task_id))
    except RuntimeError as exc:
        assert "runtime_dependencies_required" in str(exc)
    else:
        raise AssertionError("controller must reject a missing ActionExecutor")
    assert calls == []
