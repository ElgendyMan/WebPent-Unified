from __future__ import annotations

from webpent.config.settings import ScanMode, Settings
from webpent.shared.action_authority import (
    ActionAuthority,
    ActionRequest,
    ActionRisk,
    ActionStatus,
)
from webpent.shared.capability_manifest import build_capability_manifest, capability_available


def _settings(**overrides: object) -> Settings:
    values = {
        "scan_mode": ScanMode.SAFE_SMART,
        "smart_require_idempotency": True,
        "smart_max_actions": 2,
        "smart_action_budget": 5.0,
    }
    values.update(overrides)
    return Settings(**values)


def _manifest(*capabilities: str) -> dict[str, object]:
    return {
        "profile": "safe-smart",
        "capabilities": {name: {"available": True} for name in capabilities},
        "blockers": [],
        "fail_closed": True,
    }


def _request(**overrides: object) -> ActionRequest:
    values: dict[str, object] = {
        "task_id": "task-1",
        "engagement_id": "eng-1",
        "target_url": "http://target.test/path",
        "idempotency_key": "idem-1",
    }
    values.update(overrides)
    return ActionRequest(**values)


def test_scan_mode_defaults_to_legacy_and_accepts_alias(monkeypatch):
    assert Settings().scan_mode == ScanMode.LEGACY
    monkeypatch.setenv("WEBPENT_SCAN_MODE", "safe-smart")
    assert Settings().scan_mode == ScanMode.SAFE_SMART


def test_capability_manifest_is_explicit_and_fail_closed():
    manifest = build_capability_manifest(_settings())
    assert manifest["fail_closed"] is True
    assert "capabilities" in manifest
    assert capability_available(manifest, "http_read") is True
    assert capability_available(manifest, "missing") is False


def test_safe_smart_allows_same_origin_get_only():
    authority = ActionAuthority(
        settings=_settings(),
        allowed_origin="http://target.test",
        manifest=_manifest("http_read"),
    )
    decision = authority.authorize(_request())
    assert decision.status == ActionStatus.AUTHORIZED
    assert decision.allowed is True


def test_safe_smart_blocks_active_method_even_with_auto_approve():
    authority = ActionAuthority(
        settings=_settings(smart_auto_approve=True),
        allowed_origin="http://target.test",
        manifest=_manifest("http_read", "workflow"),
    )
    decision = authority.authorize(
        _request(
            method="POST",
            action_family="workflow",
            capability="workflow",
            risk=ActionRisk.ACTIVE,
        )
    )
    assert decision.status == ActionStatus.POLICY_DENIED
    assert "policy:active_method_requires_authorized_active_profile" in decision.reasons


def test_authorized_active_requires_approval_and_capability():
    authority = ActionAuthority(
        settings=_settings(scan_mode=ScanMode.AUTHORIZED_ACTIVE),
        allowed_origin="http://target.test",
        manifest=_manifest("workflow"),
    )
    denied = authority.authorize(
        _request(
            method="POST",
            action_family="workflow",
            capability="workflow",
            risk=ActionRisk.ACTIVE,
        )
    )
    assert "approval:active_action_not_approved" in denied.reasons

    approved = authority.authorize(
        _request(
            method="POST",
            action_family="workflow",
            capability="workflow",
            risk=ActionRisk.ACTIVE,
            human_approved=True,
        )
    )
    assert approved.allowed is True


def test_scope_and_missing_capability_fail_closed():
    authority = ActionAuthority(
        settings=_settings(),
        allowed_origin="http://target.test",
        manifest=_manifest("http_read"),
    )
    decision = authority.authorize(
        _request(target_url="http://other.test/path", capability="browser")
    )
    assert decision.status == ActionStatus.POLICY_DENIED
    assert "scope:target_origin_mismatch" in decision.reasons
    assert "capability:browser:unavailable" in decision.reasons


def test_idempotency_and_budget_are_enforced():
    authority = ActionAuthority(
        settings=_settings(smart_action_budget=1.0),
        allowed_origin="http://target.test",
        manifest=_manifest("http_read"),
    )
    decision = authority.authorize(_request(idempotency_key="", estimated_cost=2.0))
    assert "idempotency:key_required" in decision.reasons
    assert "budget:invalid_or_over_engagement_limit" in decision.reasons


def test_executor_does_not_call_handler_when_policy_denies():
    called: list[str] = []
    authority = ActionAuthority(
        settings=_settings(),
        allowed_origin="http://target.test",
        manifest=_manifest("http_read"),
    )
    result = authority.execute(
        _request(target_url="http://other.test/path"),
        lambda _request: called.append("called"),
    )
    assert result.status == ActionStatus.POLICY_DENIED
    assert called == []


def test_executor_records_execution_and_updates_budget():
    authority = ActionAuthority(
        settings=_settings(),
        allowed_origin="http://target.test",
        manifest=_manifest("http_read"),
    )
    result = authority.execute(_request(estimated_cost=2.0), lambda _request: "ok")
    assert result.status == ActionStatus.EXECUTED
    assert result.output == "ok"
    assert authority.used_actions == 1
    assert authority.used_budget == 2.0
    assert authority.trace[-1]["status"] == ActionStatus.EXECUTED.value
