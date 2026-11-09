from webpent.config.settings import Settings
from webpent.shared.action_authority import ActionAuthority, ActionRisk
from webpent.shared.campaign_executor import (
    CampaignExecutor,
    CampaignTask,
    CampaignTaskStatus,
    NextBestActionEngine,
)


def _settings(**overrides):
    values = {
        "scan_mode": "authorized-active",
        "smart_auto_approve": True,
        "smart_require_idempotency": True,
        "smart_action_budget": 10.0,
        "smart_max_actions": 5,
    }
    values.update(overrides)
    return Settings(**values)


def _task(**overrides):
    values = {
        "task_id": "task-idor-001",
        "engagement_id": "engagement-001",
        "asset_id": "asset-user-profile",
        "source_evidence_ids": ("evidence:profile",),
        "vulnerability_class": "idor",
        "hypothesis_id": "hypothesis-001",
        "preconditions": ("owner_identity",),
        "identity_context": "owner",
        "expected_information_gain": 0.6,
        "risk_tier": ActionRisk.READ_ONLY,
        "target_url": "http://target.test/user_profile/1",
    }
    values.update(overrides)
    return CampaignTask(**values)


def test_next_best_action_changes_when_coverage_signal_changes():
    engine = NextBestActionEngine()
    idor = _task(task_id="idor", vulnerability_class="idor", expected_information_gain=0.5)
    ssrf = _task(
        task_id="ssrf",
        vulnerability_class="ssrf",
        source_evidence_ids=("evidence:fetch",),
        expected_information_gain=0.5,
    )

    first = engine.choose([idor, ssrf], observed_evidence=("evidence:profile",))
    second = engine.choose(
        [idor, ssrf],
        observed_evidence=("evidence:profile", "evidence:fetch"),
        covered_classes=("idor",),
    )

    assert first is not None and second is not None
    assert first.task.task_id != second.task.task_id


def test_campaign_executor_denies_active_action_in_legacy_profile_without_handler_call():
    settings = _settings(scan_mode="legacy", smart_auto_approve=False)
    authority = ActionAuthority(
        settings=settings,
        allowed_origin="http://target.test",
        manifest={"capabilities": {"http_read": {"available": True}}},
    )
    executor = CampaignExecutor(authority)
    calls = []

    result = executor.execute(
        _task(method="POST", risk_tier=ActionRisk.ACTIVE),
        lambda task: calls.append(task.task_id),
    )

    assert result["status"] == CampaignTaskStatus.POLICY_DENIED.value
    assert calls == []


def test_campaign_executor_is_idempotent_and_executes_handler_once():
    authority = ActionAuthority(
        settings=_settings(),
        allowed_origin="http://target.test",
        manifest={"capabilities": {"http_read": {"available": True}}},
    )
    executor = CampaignExecutor(authority)
    calls = []
    task = _task()

    first = executor.execute(task, lambda value: calls.append(value.task_id) or {"ok": True})
    second = executor.execute(task, lambda value: calls.append(value.task_id) or {"ok": True})

    assert first["status"] == CampaignTaskStatus.EXECUTED.value
    assert second["status"] == CampaignTaskStatus.STOPPED.value
    assert calls == [task.task_id]


def test_campaign_executor_blocks_missing_precondition_without_authority_call():
    authority = ActionAuthority(
        settings=_settings(),
        allowed_origin="http://target.test",
        manifest={"capabilities": {"http_read": {"available": True}}},
    )
    executor = CampaignExecutor(authority)
    result = executor.execute(_task(), lambda _: {"ok": True})

    assert result["status"] == CampaignTaskStatus.EXECUTED.value

    second = executor.execute(
        _task(task_id="blocked"),
        lambda _: (_ for _ in ()).throw(AssertionError()),
        preconditions_met=False,
    )
    assert second["status"] == CampaignTaskStatus.BLOCKED_BY_PRECONDITION.value


def test_campaign_executor_emits_report_safe_lifecycle_events():
    authority = ActionAuthority(
        settings=_settings(),
        allowed_origin="http://target.test",
        manifest={"capabilities": {"http_read": {"available": True}}},
    )
    executor = CampaignExecutor(authority)
    task = _task()

    completed = executor.execute(task, lambda value: {"ok": True, "secret": "not-stored"})
    duplicate = executor.execute(task, lambda value: {"ok": True})
    blocked = executor.execute(
        _task(task_id="blocked"),
        lambda value: {"ok": True},
        preconditions_met=False,
    )

    assert completed["status"] == CampaignTaskStatus.EXECUTED.value
    assert duplicate["status"] == CampaignTaskStatus.STOPPED.value
    assert blocked["status"] == CampaignTaskStatus.BLOCKED_BY_PRECONDITION.value
    stages = [event["stage"] for event in executor.lifecycle_events]
    assert stages[:3] == ["planned", "authorized", "completed"]
    assert "deduplicated" in stages
    assert "blocked" in stages
    assert "not-stored" not in str(executor.lifecycle_events)



def test_next_best_action_accepts_explicit_observed_precondition_evidence():
    engine = NextBestActionEngine()
    task = _task(preconditions=("owner identity", "baseline response captured"))

    planned = engine.score(
        task,
        observed_preconditions=("owner identity", "baseline response captured"),
    )

    assert planned.score >= 0
    assert not any(reason.startswith("blocked_precondition:") for reason in planned.reasons)


def test_next_best_action_blocks_only_explicitly_missing_or_blocked_preconditions():
    engine = NextBestActionEngine()
    task = _task(preconditions=("owner_identity", "foreign_identity"))

    missing = engine.score(task, observed_preconditions=("owner_identity",))
    blocked = engine.score(task, blocked_preconditions=("foreign_identity",))
    legacy = engine.score(task)

    assert missing.score == -1.0
    assert blocked.score == -1.0
    assert legacy.score >= 0
    assert "blocked_precondition:foreign_identity" in blocked.reasons
