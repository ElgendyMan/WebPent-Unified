from __future__ import annotations

import json

from typer.testing import CliRunner

from webpent.cli.commands import app
from webpent.production.campaign_state import OPERATOR_HALTED, CampaignState
from webpent.production.product_layer import estimate_campaign_cost, render_campaign_dashboard
from webpent.shared.action_ledger import SQLiteActionLedger
from webpent.shared.llm import invoke_structured


def test_action_ledger_halt_finishes_current_action_then_blocks_next(tmp_path):
    ledger = SQLiteActionLedger(tmp_path / "actions.sqlite3")
    kwargs = dict(
        engagement_id="eng-1", task_id="task-1", target_origin="https://lab.test",
        method="GET", action_family="http_read", identity_ref="alias-a",
        tenant_context="tenant", vulnerability_class="idor", validator_id="v1",
        estimated_cost=1.0, max_actions=10, max_budget=10.0,
    )
    first = ledger.reserve(idempotency_key="a1", **kwargs)
    assert first.allowed is True
    assert ledger.request_halt("eng-1", "operator") is True
    assert ledger.complete("eng-1", "a1", status="executed") is True
    second = ledger.reserve(idempotency_key="a2", **{**kwargs, "task_id": "task-2"})
    assert second.allowed is False
    assert second.reason == "operator:halted"
    assert ledger.clear_halt("eng-1") is True
    assert ledger.reserve(idempotency_key="a2", **{**kwargs, "task_id": "task-2"}).allowed is True


def test_action_ledger_skips_repeated_hypothesis_after_three_attempts(tmp_path):
    ledger = SQLiteActionLedger(tmp_path / "loops.sqlite3")
    base = dict(
        engagement_id="eng-loop", target_origin="https://lab.test", method="GET",
        action_family="http_read", identity_ref="anon", tenant_context="t",
        vulnerability_class="xss", validator_id="v", estimated_cost=1.0,
        max_actions=10, max_budget=10.0, action_signature="same-hypothesis",
    )
    for index in range(3):
        reservation = ledger.reserve(idempotency_key=f"key-{index}", task_id=f"task-{index}", **base)
        assert reservation.allowed is True
        assert ledger.complete("eng-loop", f"key-{index}", status="executed") is True
    blocked = ledger.reserve(idempotency_key="key-3", task_id="task-3", **base)
    assert blocked.allowed is False
    assert blocked.reason == "loop:repeated_hypothesis"
    assert ledger.loop_detected("eng-loop", "same-hypothesis") is True


def test_campaign_state_halt_is_durable_and_resumable(tmp_path):
    state = CampaignState("eng-1", "https://lab.test")
    state.request_halt("operator")
    assert state.budget_exhausted() == (True, OPERATOR_HALTED)
    state.mark_terminal(OPERATOR_HALTED)
    path = tmp_path / "state.json"
    from webpent.production.campaign_state import load_campaign_state, persist_campaign_state
    persist_campaign_state(state, str(path))
    loaded = load_campaign_state(str(path))
    assert loaded.is_terminal() is True
    loaded.resume()
    assert loaded.is_terminal() is False
    assert loaded.halt_requested is False


def test_cost_estimate_formula_is_preflight_only():
    estimate = estimate_campaign_cost(endpoint_count=4, form_count=2, auth_complexity=3,
                                       estimated_llm_calls=10, per_call_cost=0.01)
    assert estimate.estimated_budget == 0.9
    assert "estimated_llm_calls" in json.dumps(estimate.as_dict())


def test_dashboard_groups_findings_and_escapes_content():
    html = render_campaign_dashboard("campaign-1", [
        {"id": "f1", "title": "<script>alert(1)</script>", "severity": "high",
         "confidence_level": "Tool-Confirmed",
         "evidence": {"identity_bound": True, "tool_confirmed_by": "test.fixture"}},
        {"id": "f2", "title": "Needs review", "confidence_level": "Needs Human Review"},
    ])
    assert "&lt;script&gt;" in html
    assert "Tool-Confirmed" in html
    assert "Needs Human Review" in html
    assert "<details" in html
    assert "<script>alert(1)</script>" not in html


def test_cli_campaign_halt_persists_operator_request(tmp_path, monkeypatch):
    monkeypatch.setenv("WEBPENT_ACTION_LEDGER_PATH", str(tmp_path / "cli.sqlite3"))
    result = CliRunner().invoke(app, ["campaign", "halt", "eng-cli"])
    assert result.exit_code == 0, result.output
    assert SQLiteActionLedger(tmp_path / "cli.sqlite3").is_halted("eng-cli") is True
