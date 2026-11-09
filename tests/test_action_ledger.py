from webpent.config.settings import ScanMode, Settings
from webpent.shared.action_authority import ActionAuthority, ActionRequest, ActionStatus
from webpent.shared.action_ledger import SQLiteActionLedger


def _settings(**overrides: object) -> Settings:
    values = {
        "scan_mode": ScanMode.SAFE_SMART,
        "smart_require_idempotency": True,
        "smart_max_actions": 2,
        "smart_action_budget": 2.0,
    }
    values.update(overrides)
    return Settings(**values)


def _request(key: str, *, cost: float = 1.0) -> ActionRequest:
    return ActionRequest(
        task_id=f"task-{key}",
        engagement_id="eng-ledger",
        target_url="http://target.test/path",
        idempotency_key=key,
        estimated_cost=cost,
    )


def _authority(
    ledger: SQLiteActionLedger, settings: Settings | None = None
) -> ActionAuthority:
    return ActionAuthority(
        settings=settings or _settings(),
        allowed_origin="http://target.test",
        manifest={"capabilities": {"http_read": {"available": True}}},
        ledger=ledger,
    )


def test_ledger_prevents_duplicate_after_authority_restart(tmp_path):
    ledger = SQLiteActionLedger(tmp_path / "actions.sqlite3")
    first = _authority(ledger).execute(_request("same-key"), lambda _request: "ok")
    second = _authority(ledger).execute(_request("same-key"), lambda _request: "must-not-run")

    assert first.status == ActionStatus.EXECUTED
    assert second.status == ActionStatus.POLICY_DENIED
    assert "idempotency:duplicate_reservation" in second.decision.reasons


def test_ledger_enforces_engagement_budget_across_authorities(tmp_path):
    ledger = SQLiteActionLedger(tmp_path / "actions.sqlite3")
    settings = _settings(smart_max_actions=2, smart_action_budget=1.0)
    first = _authority(ledger, settings).execute(_request("first"), lambda _request: "ok")
    second = _authority(ledger, settings).execute(
        _request("second"), lambda _request: "must-not-run"
    )

    assert first.status == ActionStatus.EXECUTED
    assert second.status == ActionStatus.POLICY_DENIED
    assert "budget:action_budget_exhausted" in second.decision.reasons


def test_ledger_does_not_persist_transport_output(tmp_path):
    ledger_path = tmp_path / "actions.sqlite3"
    ledger = SQLiteActionLedger(ledger_path)
    result = _authority(ledger).execute(
        _request("redaction-check"),
        lambda _request: {"secret": "never-persist-this"},
    )

    assert result.status == ActionStatus.EXECUTED
    raw = ledger_path.read_bytes()
    assert b"never-persist-this" not in raw
