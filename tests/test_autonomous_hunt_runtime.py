"""Tests for the real execution wiring of the autonomous hunt (Phase 2).

These drive the *real* runtime spine — ``RuntimeFactory.create`` builds the
scope policy, action authority with ``require_g02=True``, budget, ledger and
proof-bundle store — and prove the fail-closed contract:

* the wired adapter carries the full G-02 contract,
* an out-of-scope task is denied without the handler ever running,
* a state-changing method is denied in safe-smart mode,
* the same method executes in authorized-active mode,
* a task without G-02 adapter metadata is denied,
* the wired hunt runs end to end through the real controller.
"""

from __future__ import annotations

import pytest

from webpent.autonomous.hunt_contracts import HuntOutcome, HuntStopReason
from webpent.autonomous.hunt_runtime import (
    build_hunt_runtime,
    run_wired_hunt,
    wire_orchestrator,
)
from webpent.config.settings import ScanMode, Settings
from webpent.shared.campaign_executor import CampaignTask, CampaignTaskStatus
from webpent.shared.g02_contract import g02_http_metadata

_ENGAGEMENT = "engagement:hunt-wiring"
_CAMPAIGN = "campaign:hunt-wiring"
_TARGET = "http://example.test"


def _settings(**overrides: object) -> Settings:
    fields: dict[str, object] = {
        "scan_mode": ScanMode.SAFE_SMART,
        "smart_require_idempotency": True,
        "smart_action_budget": 10.0,
        "smart_max_actions": 5,
    }
    fields.update(overrides)
    return Settings(**fields)  # type: ignore[arg-type]


def _hunt_runtime(**kwargs: object):
    return build_hunt_runtime(
        engagement_id=_ENGAGEMENT,
        campaign_id=_CAMPAIGN,
        target_url=_TARGET,
        settings=_settings(),
        use_default_ledger=False,
        **kwargs,
    )


def _task(
    target_url: str = f"{_TARGET}/object/1",
    method: str = "GET",
    risk_tier: object = None,
    with_g02: bool = True,
) -> CampaignTask:

    fields: dict[str, object] = {
        "task_id": "task-1",
        "engagement_id": _ENGAGEMENT,
        "asset_id": "asset-1",
        "source_evidence_ids": ("surface-1",),
        "vulnerability_class": "idor",
        "hypothesis_id": "hypothesis-1",
        "target_url": target_url,
        "idempotency_key": "task-1-idempotent",
        "expected_information_gain": 0.8,
        "method": method,
        "capability": "http_read",
        "action_family": "http_read",
    }
    if risk_tier is not None:
        fields["risk_tier"] = risk_tier
    if with_g02:
        fields["metadata"] = g02_http_metadata()
    return CampaignTask(**fields)  # type: ignore[arg-type]


def _proof_payload() -> dict[str, object]:
    """The full evidence envelope the sealed-bundle path requires."""
    return {
        "finding_id": "finding:hunt-wiring",
        "proof_evidence": [{"kind": "response", "status_code": 200}],
        "evidence_refs": ["surface:0"],
        "negative_control": {"status": "completed", "matched": False},
        "proof_verified": True,
        "baseline": {"kind": "response", "status_code": 403},
        "request_evidence": [{"method": "GET", "url": f"{_TARGET}/object/1"}],
        "response_evidence": [{"status": 200}],
        "scope_context": {"targets": ["example.test"], "authorized": True},
        "identity_context": {"identity": "primary", "authenticated": True},
        "target_fingerprint": "sha256:fixture-target",
        "causal_oracle": {
            "causal_signal": True,
            "negative_control_complete": True,
            "requires_target_backed": False,
        },
        "validator_id": "hunt-wiring-validator",
        "validator_version": "v1",
        "replay_metadata": {"replayable": True},
        "cleanup_status": "not_applicable",
    }


def test_wired_adapter_carries_full_g02_contract() -> None:
    hr = _hunt_runtime()
    adapter = hr.runtime.adapters.get("smart_http")
    assert adapter is not None
    assert adapter.policy_checked is True
    assert adapter.scope_policy == "same-origin"
    assert "direct_io_inventory" in adapter.static_inventory_ref
    assert adapter.proof_contract
    assert adapter.canonical_wrapper.endswith("make_safe_httpx_client")


def test_wired_runtime_exposes_real_executor_and_handler() -> None:
    hr = _hunt_runtime()
    assert hr.runtime.configuration_errors == ()
    assert type(hr.action_executor).__name__ == "ActionExecutor"
    assert callable(hr.handler)
    assert hr.runtime.require_valid() is hr.runtime


def test_invalid_origin_fails_closed() -> None:
    from webpent.shared.runtime import RuntimeConfigurationError

    with pytest.raises(RuntimeConfigurationError):
        hr = build_hunt_runtime(
            engagement_id=_ENGAGEMENT,
            campaign_id=_CAMPAIGN,
            target_url="not-a-url",
            settings=_settings(),
            use_default_ledger=False,
        )
        hr.runtime.require_valid()


def test_out_of_scope_task_is_denied_without_running_handler() -> None:
    hr = _hunt_runtime()
    called = False

    def handler(task: CampaignTask) -> dict[str, object]:
        nonlocal called
        called = True
        return _proof_payload()

    record = hr.action_executor.execute(_task("http://other.test/object/1"), handler)

    assert record["status"] == CampaignTaskStatus.POLICY_DENIED.value
    assert called is False
    assert record["proof_bundle"] is None


def test_post_is_denied_in_safe_smart_mode() -> None:
    from webpent.shared.action_authority import ActionRisk

    hr = _hunt_runtime()
    called = False

    def handler(task: CampaignTask) -> dict[str, object]:
        nonlocal called
        called = True
        return _proof_payload()

    record = hr.action_executor.execute(
        _task(method="POST", risk_tier=ActionRisk.ACTIVE), handler
    )

    assert record["status"] == CampaignTaskStatus.POLICY_DENIED.value
    assert called is False
    assert record["proof_bundle"] is None


def test_post_executes_in_authorized_active_mode() -> None:
    from webpent.shared.action_authority import ActionRisk

    hr = build_hunt_runtime(
        engagement_id=_ENGAGEMENT,
        campaign_id=_CAMPAIGN,
        target_url=_TARGET,
        settings=_settings(scan_mode="authorized-active", smart_auto_approve=True),
        use_default_ledger=False,
    )
    called = False

    def handler(task: CampaignTask) -> dict[str, object]:
        nonlocal called
        called = True
        return dict(_proof_payload(), request_evidence=[{"method": "POST"}])

    record = hr.action_executor.execute(
        _task(method="POST", risk_tier=ActionRisk.ACTIVE), handler
    )

    assert record["status"] == CampaignTaskStatus.EXECUTED.value
    assert called is True
    assert record["proof_bundle_sealed"] is True


def test_task_without_g02_metadata_is_denied() -> None:
    hr = _hunt_runtime()
    called = False

    def handler(task: CampaignTask) -> dict[str, object]:
        nonlocal called
        called = True
        return _proof_payload()

    record = hr.action_executor.execute(_task(with_g02=False), handler)

    assert record["status"] == CampaignTaskStatus.POLICY_DENIED.value
    assert called is False


def test_get_executes_through_wired_handler_and_seals_bundle() -> None:
    hr = _hunt_runtime()
    record = hr.action_executor.execute(_task(), lambda _task: _proof_payload())

    assert record["status"] == CampaignTaskStatus.EXECUTED.value
    assert record["proof_bundle_sealed"] is True
    assert record["negative_control_present"] is True


def test_wire_orchestrator_binds_executor_and_handler() -> None:
    hr = _hunt_runtime()
    orchestrator = wire_orchestrator(hr, max_iterations=3)
    assert orchestrator.action_executor is hr.runtime.action_executor
    assert orchestrator.handler is hr.handler
    assert orchestrator.max_iterations == 3


def test_run_wired_hunt_end_to_end_stops_without_ready_tasks() -> None:
    state = run_wired_hunt(
        engagement_id=_ENGAGEMENT,
        campaign_id=_CAMPAIGN,
        target_url=_TARGET,
        settings=_settings(),
        max_iterations=2,
    )
    # With no target knowledge the real planner produces no ready tasks, so
    # the bounded loop must stop with the typed reason — never invent work.
    assert state.stop_reason in {
        HuntStopReason.NO_NEW_READY_TASK,
        HuntStopReason.NO_NEW_EVIDENCE,
    }
    assert state.outcome is HuntOutcome.INCONCLUSIVE
    phases = [record.phase.value for record in state.phase_trace]
    assert "execute" in phases
    assert phases[-1] == "report"
